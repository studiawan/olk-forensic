#!/usr/bin/env python3
"""
Unit tests for olk_forensic.py (and the hfl_parse.py functions it relies on).

All inputs are small synthetic artifacts built by tests/synth.py; no private evidence is
needed. Run from the project folder:

    python3.12 -B -m unittest discover -s tests -v
    # or, if pytest is installed:  python3.12 -B -m pytest tests -q

Optional integration test against a real profile (slow, read-only):

    OLK_PROFILE="Main Profile" python3.12 -B -m unittest discover -s tests -k RealProfile -v
"""
import argparse
import contextlib
import csv
import datetime as dt
import gzip
import hashlib
import io
import json
import os
import plistlib
import re
import shutil
import sqlite3
import struct
import subprocess
import sys
import tempfile
import unittest

sys.dont_write_bytecode = True
HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.join(os.path.dirname(HERE), "tools")       # olk_forensic.py, hfl_parse.py
sys.path.insert(0, ROOT)
sys.path.insert(0, HERE)

import hfl_parse as hp            # noqa: E402
import olk_forensic as of         # noqa: E402
import synth as S                 # noqa: E402

T_CREATED = dt.datetime(2025, 11, 10, 22, 57, 40)     # trace log creation (wall clock)
MONO_AT_CREATE = 3_000_000_000                         # monotonic ns at creation -> boot = 22:57:37


@contextlib.contextmanager
def quiet():
    """The tool reports progress on stdout/stderr; keep test output clean."""
    with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
        yield


class TmpCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="olkf_test_")
        self.addCleanup(shutil.rmtree, self.tmp, True)

    def path(self, *parts):
        return os.path.join(self.tmp, *parts)

    def write(self, rel, data, root=None):
        full = os.path.join(root or self.tmp, rel)
        os.makedirs(os.path.dirname(full), exist_ok=True)
        with open(full, "wb") as fh:
            fh.write(data)
        return full

    def fileinfo(self, rel, root=None):
        """The dict that inventory() produces, for parsers that take one."""
        full = os.path.join(root or self.tmp, rel)
        with open(full, "rb") as fh:
            head = fh.read(64)
        md5, sha = of.hashes(full)
        return {"path": rel, "full": full, "size": os.path.getsize(full), "head": head,
                "category": of.categorize(rel), "type": of.detect(head, rel), "sha256": sha, "md5": md5}

    def newdb(self, name="t.db"):
        db = of.DB(self.path(name))
        self.addCleanup(db.c.close)
        return db

    def rows(self, db, sql, *a):
        db.flush()
        return db.c.execute(sql, a).fetchall()


# =================================================================================== helpers
class Helpers(unittest.TestCase):
    def test_iso_truncates_to_milliseconds(self):
        self.assertEqual(of.iso(dt.datetime(2025, 1, 2, 3, 4, 5, 678901)), "2025-01-02 03:04:05.678")
        self.assertIsNone(of.iso(None))

    def test_from_unix(self):
        self.assertEqual(of.from_unix(0), "1970-01-01 00:00:00.000")
        self.assertEqual(of.from_unix(1762815463), "2025-11-10 22:57:43.000")
        self.assertIsNone(of.from_unix(None))
        self.assertIsNone(of.from_unix(1e20))

    def test_from_ticks_round_trip_and_range_guard(self):
        d = dt.datetime(2025, 11, 10, 22, 57, 43, 370000)
        self.assertEqual(of.from_ticks(S.ticks(d)), "2025-11-10 22:57:43.370")
        self.assertIsNone(of.from_ticks(12345))            # implausible value is not a date
        self.assertIsNone(of.from_ticks(8 * 10 ** 17))

    def test_from_cocoa(self):
        self.assertEqual(of.from_cocoa(0), "2001-01-01 00:00:00.000")
        d = dt.datetime(2024, 3, 4, 5, 6, 7)
        self.assertEqual(of.from_cocoa(S.cocoa(d)), "2024-03-04 05:06:07.000")
        self.assertIsNone(of.from_cocoa(5e9))

    def test_sg_maps_unsigned_64_to_signed(self):
        self.assertEqual(of.sg(5), 5)
        self.assertEqual(of.sg((1 << 64) - 1), -1)
        self.assertEqual(of.sg(1 << 63), -(1 << 63))
        self.assertIsNone(of.sg(None))

    def test_strings_of_finds_utf16_and_ascii_without_duplicates(self):
        b = "Inbox".encode("utf-16-le") + b"\x00\x01" + b"hello world" + b"\x00" + b"AAAAAAA" + b"hello world"
        out = of.strings_of(b)
        self.assertIn("Inbox", out)
        self.assertIn("hello world", out)
        self.assertEqual(out.count("hello world"), 1)
        self.assertNotIn("AAAAAAA", out)                   # runs of one repeated char are noise
        self.assertEqual(len(of.strings_of(b"abcdefgh\x00" * 0 + b"".join(b"w%04d\x00" % i for i in range(100)), 5)), 5)

    def test_hashes(self):
        with tempfile.NamedTemporaryFile(delete=False) as fh:
            fh.write(b"evidence")
        try:
            md5, sha = of.hashes(fh.name)
            self.assertEqual(md5, hashlib.md5(b"evidence").hexdigest())
            self.assertEqual(sha, hashlib.sha256(b"evidence").hexdigest())
        finally:
            os.remove(fh.name)

    def test_safe_name(self):
        self.assertEqual(of.safe_name('a/b\\c:d*e?"f<g>h|i'), "a_b_c_d_e_f_g_h_i")
        self.assertEqual(of.safe_name("  .hidden. "), "hidden")
        self.assertEqual(of.safe_name(""), "unnamed")
        self.assertEqual(of.safe_name(None), "unnamed")
        self.assertEqual(len(of.safe_name("x" * 500)), 120)

    def test_osa_time(self):
        self.assertEqual(of.osa_time("2025-11-10T22:57:44.1534567Z"), "2025-11-10 22:57:44.153")
        self.assertIsNone(of.osa_time(None))
        self.assertIsNone(of.osa_time(""))

    def test_esc_and_shift(self):
        self.assertEqual(of.esc("<a&b>"), "&lt;a&amp;b&gt;")
        self.assertEqual(of.esc(None), "")
        self.assertEqual(of.shift("2025-11-10 22:57:43.335", 7), "2025-11-11 05:57:43.335")
        self.assertEqual(of.shift("2025-11-10 22:57:43.335", -5.5), "2025-11-10 17:27:43.335")
        self.assertEqual(of.shift("2025-11-10 22:57:43.335", 0), "2025-11-10 22:57:43.335")
        self.assertEqual(of.shift("not a time", 7), "not a time")
        self.assertIsNone(of.shift(None, 7))

    def test_png_size(self):
        self.assertEqual(of.png_size(S.png(96, 48)), (96, 48))
        self.assertEqual(of.png_size(b"GIF89a" + b"\x00" * 30), (None, None))

    def test_ok_status_set(self):
        for s in ("Success", "Ok", "OK", "200", "201", "202", "204", "304"):
            self.assertIn(s, of.OK_STATUS)
            self.assertIn("'%s'" % s, of.OK_SQL)
        self.assertNotIn("500", of.OK_STATUS)


class Classification(unittest.TestCase):
    def test_detect_magics(self):
        cases = {
            b"Nostromoi\x00": "HxStore database (Nostromoi)",
            b"Nostromo\x00\x00": "HxCore replication state (Nostromo)",
            b"bplist00": "binary property list",
            b"SQLite format 3\x00": "SQLite database",
            b"\x1f\x8b\x08": "gzip",
            b"\xd0\x0d\x00\x00": "Outlook 2016 record (olk15)",
            b"\xef\xbe\xad\xde": "lock table (DEADBEEF)",
            b"XENO": "counter file (XENO)",
            b"\x89PNG\r\n": "PNG image",
            b"%PDF-1.7": "PDF document",
        }
        for head, want in cases.items():
            self.assertEqual(of.detect(head, "x"), want, head)

    def test_detect_fallbacks(self):
        self.assertEqual(of.detect(b"\x08\x00\x00\x00\x00\x00\x01\x00", "hxcore.hfl"), "HxCore trace log (.hfl)")
        self.assertEqual(of.detect(b"\x08\x00\x00\x00", "other.bin"), "binary")
        self.assertEqual(of.detect(b"  <HTML><body>", "a"), "HTML")
        self.assertEqual(of.detect(b"Received: from x\r\nFrom: y", "a"), "e-mail message (RFC 822)")
        self.assertEqual(of.detect(b"plain text\n", "a"), "text")
        self.assertEqual(of.detect(b"", "a"), "binary")

    def test_categorize(self):
        cases = {
            "hxcore.hfl": "HxCore trace log",
            "hxcore_previous_session.hfl": "HxCore trace log",
            "HxStore.hxd": "HxCore store",
            "AccountsBackup.bhxd": "Accounts backup",
            "Osa/OsaPinnedLogs/x.xmlgz": "Osa pinned logs",
            "Osa/OutlookServiceApiLogs_2025-11-10-22_69126E17/a.xmlgz": "Osa API logs",
            "Files/S0/1/Attachments/a[1].pdf": "Attachment cache",
            "Files/S0/1/EFMData/12.dat": "Message bodies (EFMData)",
            "Files/S0/1/Photos/p.png": "Contact photos",
            "Files/S0/1/AadLogos/l.png": "Tenant logos",
            "Files/S0/1/Data/x": "Files (other)",
            "Data/Categories/3/u.olk15Category": "Legacy olk15 records",
            "Data/Outlook.sqlite": "Legacy SQLite",
            "Data/Other/x": "Legacy data (other)",
            "Omc/c.xml": "Outlook.com connector",
            "rss/a.rep": "Replication state",
            "TelemetryStorage/t.bin": "Telemetry",
            "ProfilePreferences.plist": "Preferences / config",
            "clientConfigsForAM.dat": "Preferences / config",
            "HxStore.lock": "Other",
        }
        for rel, want in cases.items():
            self.assertEqual(of.categorize(rel), want, rel)
        self.assertEqual(of.categorize("Osa\\OsaPinnedLogs\\x"), "Osa pinned logs")   # Windows separators

    def test_filename_patterns(self):
        m = of.REF_RE.match("Quarterly report[12].pdf")
        self.assertEqual((m.group(1), m.group(2), m.group(3)), ("Quarterly report", "12", ".pdf"))
        m = of.REF_RE.match("noext[3]")
        self.assertEqual((m.group(1), m.group(2), m.group(3)), ("noext", "3", None))
        self.assertIsNone(of.REF_RE.match("plain.pdf"))
        g = S.new_guid()
        m = of.PHOTO_RE.match(S.photo_name(g, dt.datetime(2025, 10, 26, 8, 0)))
        self.assertEqual(m.group(1), g)
        self.assertEqual(of.from_ticks(int(m.group(2))), "2025-10-26 08:00:00.000")
        m = of.OSA_NAME.search("osa{2025-11-10-22-57-44}_17_acct01_sync.GetMessage.4242.response.xmlgz")
        self.assertEqual(m.groups(), ("2025-11-10-22-57-44", "17", "acct01", "sync.GetMessage.4242.response"))
        self.assertEqual(of.OSA_FOLDER.search("OutlookServiceApiLogs_2025-11-10-22_69126E17").group(1), "69126E17")


# =================================================================================== HFL primitives
class Lz4Block(unittest.TestCase):
    def test_literal_only_short_and_long(self):
        for n in (0, 1, 14, 15, 16, 269, 270, 1000):
            data = bytes(i % 251 for i in range(n))
            self.assertEqual(hp.lz4_block(S.lz4_literals(data)), data, n)

    def test_overlapping_match(self):
        # token lit=2 ml=6-4, "ab", offset 2, then last literal "x"
        blk = bytes([0x22]) + b"ab" + b"\x02\x00" + bytes([0x10]) + b"x"
        self.assertEqual(hp.lz4_block(blk), b"abababab" + b"x")

    def test_non_overlapping_match_with_extended_length(self):
        # lit=4 "abcd", offset 4, ml = 15 + 5 + 4 = 24
        blk = bytes([0x4F]) + b"abcd" + b"\x04\x00" + bytes([5]) + bytes([0x10]) + b"!"
        self.assertEqual(hp.lz4_block(blk), b"abcd" * 7 + b"!")

    def test_malformed_blocks_return_none(self):
        self.assertIsNone(hp.lz4_block(bytes([0x50]) + b"ab"))                 # literal past end
        self.assertIsNone(hp.lz4_block(bytes([0x10]) + b"a" + b"\x05\x00"))    # offset beyond output
        self.assertIsNone(hp.lz4_block(bytes([0x10]) + b"a" + b"\x00\x00"))    # offset zero
        self.assertIsNone(hp.lz4_block(bytes([0xF0])))                          # unterminated length

    def test_output_limit(self):
        blk = bytes([0x1F]) + b"a" + b"\x01\x00" + b"\xff" * 10 + b"\x00" + bytes([0x10]) + b"b"
        self.assertIsNone(hp.lz4_block(blk, max_out=100))


class DecodeArgs(unittest.TestCase):
    def test_every_type_code(self):
        g = bytes(range(16))
        buf = b"".join([S.tlv_str8("sync"), S.tlv_str16("Inbox"), S.tlv_i32(-5), S.tlv_u64(2 ** 63),
                        S.tlv_u32(29853), S.tlv_bool(True), S.tlv_f64(1.5), S.tlv_guid(g),
                        S.tlv_bytes(b"\x01\x02"), S.tlv_u8(173), S.tlv_u16(65535), S.tlv_i64(-1)])
        args, end, err = hp.decode_args(buf, 0, len(buf), 12)
        self.assertIsNone(err)
        self.assertEqual(end, len(buf))
        self.assertEqual(args, [("str8", "sync"), ("str16", "Inbox"), ("i32", -5), ("u64", 2 ** 63),
                                ("u32", 29853), ("bool", 1), ("f64", 1.5), ("guid", g),
                                ("bytes", b"\x01\x02"), ("u8", 173), ("u16", 65535), ("i64", -1)])
        self.assertEqual(hp.arg_signature(args), "sSiQI?dGbBHq")

    def test_errors_are_reported_not_raised(self):
        buf = S.tlv_str8("abcdef")
        self.assertEqual(hp.decode_args(buf, 0, len(buf) - 2, 1)[2], "string past end")
        self.assertEqual(hp.decode_args(b"\x99\x00", 0, 2, 1)[2], "unknown type byte 0x99")
        self.assertEqual(hp.decode_args(S.tlv_u8(1), 0, 2, 2)[2], "ran out of bytes")
        self.assertEqual(hp.decode_args(b"\x05\x01", 0, 2, 1)[2], "value past end")

    def test_record_iteration_stops_at_bad_length(self):
        r1 = S.hfl_record(10, 1, 4, 1, [S.tlv_u32(1)])
        r2 = S.hfl_record(20, 2, 4, 1, [])
        bad = bytearray(S.hfl_record(30, 3, 4, 1, []))
        struct.pack_into("<H", bad, 0x20, 0x10)             # length < header size
        recs = list(hp.iter_records(r1 + r2 + bytes(bad)))
        self.assertEqual([off for off, _ in recs], [0, len(r1)])
        self.assertEqual(recs[1][1][1], 20)                  # stamp


class HflHeaderAndChunks(unittest.TestCase):
    def test_header_clock_model(self):
        d = S.hfl_file(T_CREATED, MONO_AT_CREATE, [])
        h = hp.parse_header(d)
        self.assertEqual(h["magic_0x00"], 8)
        self.assertEqual(h["version_0x04"], "0x00010000")
        self.assertEqual(h["office_build"], "16.0.20622.33801")
        self.assertEqual(h["settings"], {"Level": "4", "Areas": "all"})
        self.assertEqual(h["created_utc"][:23], "2025-11-10 22:57:40.000")
        self.assertEqual(h["monotonic_zero_utc"][:23], "2025-11-10 22:57:37.000")   # T_c - M_c
        self.assertEqual(h["data_start"], len(d))

    def test_header_rejects_bad_files(self):
        with self.assertRaises(hp.HflError):
            hp.parse_header(b"\x08" * 0x20)
        d = bytearray(S.hfl_file(T_CREATED, 0, []))
        struct.pack_into("<I", d, 0x54, 10 ** 6)
        with self.assertRaises(hp.HflError):
            hp.parse_header(bytes(d))

    def test_chunks_tile_and_gaps_are_found(self):
        c1 = S.hfl_chunk([S.hfl_record(1, 1, 4, 1, [])])
        c2 = S.hfl_chunk([S.hfl_record(2, 1, 4, 1, [])])
        d = S.hfl_file(T_CREATED, 0, [c1, c2], gap=b"\x00" * 37)
        start = hp.parse_header(d)["data_start"]
        got = list(hp.iter_chunks(d, start))
        self.assertEqual([k for k, _, _ in got], ["chunk", "gap", "chunk"])
        self.assertEqual(got[1][2], 37)
        self.assertEqual(got[0][2], len(c1))
        self.assertEqual(sum(ln for _, _, ln in got), len(d) - start)           # exact tiling (W1/W2)
        ch = hp.chunk_header(d, start)
        self.assertEqual(ch["comp_len"], len(c1))


# =================================================================================== parse_hfl
class ParseHfl(TmpCase):
    def build(self, gap=b""):
        oid_hex = (0x4F6D19).to_bytes(8, "little").hex().upper()   # "196D4F0000000000"
        act = bytes.fromhex("44e68bdc47904 07ea8445b0a095ce225".replace(" ", ""))
        recs1 = [
            S.hfl_record(6_335_000_000, 1011, 2, 4, [S.tlv_str16(oid_hex), S.tlv_str16("sync"), S.tlv_u32(29853)],
                         thread=4760, activity=act),
            S.hfl_record(6_400_000_000, 20, 4, 1, [S.tlv_str8("QueueRun"), S.tlv_u32(1)], thread=4760),
        ]
        recs2 = [S.hfl_record(7_000_000_000, 20, 3, 1, [S.tlv_str8("QueueRun"), S.tlv_u32(2)], thread=11)]
        d = S.hfl_file(T_CREATED, MONO_AT_CREATE, [S.hfl_chunk(recs1), S.hfl_chunk(recs2)], gap=gap)
        return self.write("hxcore.hfl", d)

    def test_records_mode(self):
        p = self.build()
        db = self.newdb()
        with quiet():
            r = of.parse_hfl(p, "hxcore.hfl", db, "records", set())
        self.assertEqual(r["records"], 3)
        self.assertEqual(r["errors"], 1)
        self.assertEqual(r["first"], "2025-11-10 22:57:43.335")     # boot 22:57:37 + 6.335 s
        self.assertEqual(r["last"], "2025-11-10 22:57:44.000")
        f = self.rows(db, "SELECT office_build, chunks, gaps, gap_bytes, records, errors, warnings, threads, "
                          "activities, events, created_utc, monotonic_zero_utc FROM hfl_files")[0]
        self.assertEqual(f, ("16.0.20622.33801", 2, 0, 0, 3, 1, 1, 2, 1, 2,
                             "2025-11-10 22:57:40.000", "2025-11-10 22:57:37.000"))
        recs = self.rows(db, "SELECT chunk, off, time_utc, thread, ekey, level, sig, activity FROM hfl_records ORDER BY stamp_ns")
        self.assertEqual(len(recs), 3)
        self.assertEqual(recs[0][:7], (0, 0, "2025-11-10 22:57:43.335", 4760, "4.1011", 2, "SSI"))
        self.assertEqual(recs[0][7], "44e68bdc-4790-407e-a844-5b0a095ce225")
        self.assertIsNone(recs[1][7])                                  # all-zero activity -> NULL
        self.assertEqual(recs[2][0], 1)                                # second chunk index

    def test_events_object_activity_and_timeline(self):
        p = self.build()
        db = self.newdb()
        with quiet():
            of.parse_hfl(p, "hxcore.hfl", db, "records", set())
        ev = dict(self.rows(db, "SELECT ekey, count FROM hfl_events"))
        self.assertEqual(ev, {"4.1011": 1, "1.20": 2})
        sig = self.rows(db, "SELECT signature FROM hfl_events WHERE ekey='1.20'")[0][0]
        self.assertEqual(sig, "sI")
        obj = self.rows(db, "SELECT object_id, mentions, first_utc FROM hfl_object_activity")
        self.assertIn((0x4F6D19, 1, "2025-11-10 22:57:43.335"), obj)
        kinds = sorted(k for (k,) in self.rows(db, "SELECT kind FROM timeline WHERE source='hfl'"))
        self.assertEqual(kinds, ["first trace record", "last trace record", "trace error", "trace log created"])
        hourly = self.rows(db, "SELECT hour_utc, level, n FROM hfl_hourly ORDER BY level")
        self.assertEqual(hourly, [("2025-11-10 22:00", 2, 1), ("2025-11-10 22:00", 3, 1), ("2025-11-10 22:00", 4, 1)])

    def test_summary_mode_keeps_only_errors_and_warnings(self):
        p = self.build()
        db = self.newdb()
        with quiet():
            r = of.parse_hfl(p, "hxcore.hfl", db, "summary", set())
        self.assertEqual(r["records"], 3)
        levels = sorted(l for (l,) in self.rows(db, "SELECT level FROM hfl_records"))
        self.assertEqual(levels, [2, 3])

    def test_gap_is_counted(self):
        p = self.build(gap=b"\x00" * 50)
        db = self.newdb()
        with quiet():
            of.parse_hfl(p, "hxcore.hfl", db, "summary", set())
        self.assertEqual(self.rows(db, "SELECT chunks, gaps, gap_bytes, records FROM hfl_files")[0], (2, 1, 50, 3))

    def test_evidence_not_modified(self):
        p = self.build()
        before = (of.hashes(p), os.stat(p).st_mtime_ns)
        db = self.newdb()
        with quiet():
            of.parse_hfl(p, "hxcore.hfl", db, "records", set())
        self.assertEqual((of.hashes(p), os.stat(p).st_mtime_ns), before)


# =================================================================================== AccountsBackup
class AccountBackup(TmpCase):
    def test_decodes_all_value_types(self):
        when = dt.datetime(2025, 10, 18, 9, 30)
        entries = [
            S.kv_entry("EmailAddress", 1, "user@example.org\x00".encode("utf-16-le")),
            S.kv_entry("SyncInterval", 2, struct.pack("<I", 300)),
            S.kv_entry("LastSync", 8, struct.pack("<Q", S.ticks(when))),
            S.kv_entry("Enabled", 7, b"\x01"),
            S.kv_entry("Blob", 12, b"\xde\xad\xbe\xef\x01"),
            S.kv_entry("Nothing", 9, b""),
        ]
        p = self.write("AccountsBackup.bhxd", S.account_backup("Account", entries))
        db = self.newdb()
        self.assertEqual(of.parse_account_backup(p, "AccountsBackup.bhxd", db), 6)
        got = {r[0]: r[1:] for r in self.rows(db, "SELECT prop, section, type_name, value, file_offset, record_hash FROM account_backup")}
        self.assertEqual(got["EmailAddress"][:3], ("Account", "string", "user@example.org"))
        self.assertEqual(got["SyncInterval"][1:3], ("u32", "300"))
        self.assertEqual(got["LastSync"][2], "%d (2025-10-18 09:30:00.000 UTC)" % S.ticks(when))
        self.assertEqual(got["Enabled"][1:3], ("bool", "1"))
        self.assertEqual(got["Blob"][1:3], ("type 12", "deadbeef01"))
        self.assertEqual(got["Nothing"][1:3], ("empty", ""))
        self.assertEqual(got["Enabled"][3], 4096)
        self.assertEqual(got["Enabled"][4], "aa" * 8)

    def test_truncated_and_empty_inputs(self):
        db = self.newdb()
        p = self.write("empty.bhxd", b"Nostromoi" + b"\x00" * 8000)
        self.assertEqual(of.parse_account_backup(p, "empty.bhxd", db), 0)
        self.assertEqual(of.decode_kv(b"\x00" * 4, "x", "h", 0, db, 10), 0)
        # count says 5 entries but the payload ends after one
        name = "S".encode("utf-16-le")
        p2 = name + struct.pack("<QI", 0, 5) + S.kv_entry("A", 2, struct.pack("<I", 7)) + b"\xff\xff"
        self.assertEqual(of.decode_kv(p2, "x", "h", 0, db, len(name)), 1)


# =================================================================================== Osa
class OsaLogs(TmpCase):
    FOLDER_TIME = dt.datetime(2025, 11, 10, 22, 57, 43)

    def folder(self):
        return "OutlookServiceApiLogs_2025-11-10-22_%08X" % S.unix(self.FOLDER_TIME)

    def add(self, name, data, pinned=False):
        rel = ("Osa/OsaPinnedLogs/" if pinned else "Osa/%s/" % self.folder()) + name
        self.write(rel, data)
        return self.fileinfo(rel)

    def test_request_response_fields(self):
        f = self.add("osa{2025-11-10-22-57-44}_1_acct01_sync.GetMessage.4242.response.xmlgz", S.gz(S.osa_xml(
            LogTime="2025-11-10T22:57:44.1534567Z", StartTimeStamp="2025-11-10T22:57:44.100Z",
            EndTimeStamp="2025-11-10T22:57:44.350Z", StatusCode="Success", Size="2048",
            BackEndServer="BE01", ServerBuild="15.20.1", AppState="Foreground",
            Headers="Host: x\nUser-Agent: Outlook-Mac/16.115\n", Body="pii:abc pii:def")))
        db = self.newdb()
        with quiet():
            self.assertEqual(of.parse_osa([f], db), 1)
        r = self.rows(db, "SELECT folder, pinned, session_start_utc, seq, account, channel, command, request_id, kind, "
                          "root, time_utc, duration_ms, status, size, backend, server_build, app_state, user_agent, "
                          "pii_values FROM osa_logs")[0]
        self.assertEqual(r, (self.folder(), 0, "2025-11-10 22:57:43.000", 1, "acct01", "sync", "GetMessage", "4242",
                             "response", "Log", "2025-11-10 22:57:44.153", 250.0, "Success", 2048, "BE01", "15.20.1",
                             "Foreground", "Outlook-Mac/16.115", 2))
        paths = dict(self.rows(db, "SELECT path, value FROM osa_fields"))
        self.assertEqual(paths["Log/StatusCode"], "Success")
        self.assertNotIn("Log/Headers", paths)                    # headers kept only in osa_logs.xml
        # a successful sync command is not a timeline event, but the folder (session) is
        kinds = [k for (k,) in self.rows(db, "SELECT kind FROM timeline")]
        self.assertEqual(kinds, ["api log session start"])

    def test_failures_go_to_timeline_and_ok_statuses_do_not(self):
        fs = []
        for i, st in enumerate(["Ok", "304", "ErrorItemNotFound", "500"]):
            fs.append(self.add("osa{2025-11-10-22-57-4%d}_%d_a_sync.GetItem.%d.response.xmlgz" % (i, i, i),
                               S.gz(S.osa_xml(LogTime="2025-11-10T22:57:4%d.000Z" % i, StatusCode=st))))
        db = self.newdb()
        with quiet():
            of.parse_osa(fs, db)
        desc = [d for (d,) in self.rows(db, "SELECT description FROM timeline WHERE kind LIKE 'api%' AND kind != 'api log session start'")]
        self.assertEqual(len(desc), 2)
        self.assertTrue(any("[ErrorItemNotFound]" in d for d in desc))
        self.assertTrue(any("[500]" in d for d in desc))
        n = self.rows(db, "SELECT sum(not_success) FROM osa_commands")[0][0]
        self.assertEqual(n, 2)

    def test_malformed_xml_uses_regex_fallback(self):
        f = self.add("osa{2025-11-10-22-57-44}_2_a_app.Initialize.request.xmlgz",
                     S.gz(b"<Log><LogTime>2025-11-10T22:57:44Z</LogTime><StatusCode>OK</StatusCode><Broken>"))
        db = self.newdb()
        with quiet():
            of.parse_osa([f], db)
        r = self.rows(db, "SELECT root, time_utc, status, request_id, kind FROM osa_logs")[0]
        self.assertEqual(r, ("(malformed)", "2025-11-10 22:57:44", "OK", None, "request"))
        # chan == "app" is always a timeline event
        self.assertEqual(self.rows(db, "SELECT count(*) FROM timeline WHERE kind='api app'")[0][0], 1)

    def test_unreadable_file_and_pinned_log(self):
        bad = self.add("osa{2025-11-10-22-57-44}_3_a_sync.X.response.xmlgz", b"not gzip")
        pin = self.add("osa{2025-11-09-10-00-00}_4_a_sync.SendMail.response.xmlgz",
                       S.gz(S.osa_xml(LogTime="2025-11-09T10:00:00Z", StatusCode="500")), pinned=True)
        db = self.newdb()
        with quiet():
            self.assertEqual(of.parse_osa([bad, pin], db), 1)
        self.assertEqual(self.rows(db, "SELECT parser FROM binary_artifacts")[0][0], "osa (unreadable)")
        r = self.rows(db, "SELECT pinned, session_start_utc FROM osa_logs")[0]
        self.assertEqual(r, (1, "2025-11-09 10:00:00.000"))         # no folder time -> filename time
        self.assertEqual(self.rows(db, "SELECT count(*) FROM timeline")[0][0], 0)   # pinned logs stay off the timeline


# =================================================================================== olk15 / plists
class Olk15(TmpCase):
    def test_properties(self):
        g = bytes(range(16))
        when = dt.datetime(2019, 5, 6, 7, 8, 9)
        data = S.olk15("CATa", [
            (0x0001, 0x1f, "Red category".encode("utf-16-le")),
            (0x0002, 0x03, struct.pack("<i", -2)),
            (0x0003, 0x48, g),
            (0x0004, 0x4d, struct.pack("<d", S.cocoa(when))),
            (0x0005, 0x08, b"\xca\xfe"),
            (0x0006, 0x77, b"\x01"),
        ])
        rel = "Data/Categories/3/0A1B2C3D.olk15Category"
        self.write(rel, data)
        db = self.newdb()
        self.assertTrue(of.parse_olk15(self.fileinfo(rel), db))
        rec = self.rows(db, "SELECT kind, record_type, uuid, folder_no, name, modified_utc, n_props, size FROM olk15_records")[0]
        self.assertEqual(rec, ("Categories", "CATa", "0A1B2C3D", 3, "Red category", "2019-05-06 07:08:09.000", 6, len(data)))
        props = {p: (t, v) for p, t, v in self.rows(db, "SELECT prop_id, prop_type, value FROM olk15_props")}
        self.assertEqual(props["0x0002"], ("i32", "-2"))
        self.assertEqual(props["0x0003"], ("guid", "03020100-0504-0706-0809-0a0b0c0d0e0f"))
        self.assertEqual(props["0x0005"], ("binary", "cafe"))
        self.assertEqual(props["0x0006"], ("0x77", "01"))
        self.assertEqual(self.rows(db, "SELECT time_utc, kind FROM timeline")[0], ("2019-05-06 07:08:09.000", "legacy record date"))

    def test_rejects_non_olk15(self):
        self.write("Data/x.olk15Message", b"\x00" * 100)
        db = self.newdb()
        self.assertFalse(of.parse_olk15(self.fileinfo("Data/x.olk15Message"), db))

    def test_truncated_entry_table(self):
        data = S.olk15("MSGa", [(1, 0x03, struct.pack("<i", 1))])
        d = bytearray(data)
        struct.pack_into("<I", d, 0x28, 99)                  # claims 99 entries
        self.write("Data/M/1/t.olk15Message", bytes(d))
        db = self.newdb()
        self.assertTrue(of.parse_olk15(self.fileinfo("Data/M/1/t.olk15Message"), db))   # no exception


class Plists(TmpCase):
    def test_keyed_archive_is_unarchived(self):
        obj = of.load_plist_bytes(S.keyed_archive("DefaultAccountIdentifier", "ACCT-1"))
        self.assertEqual(obj, {"root": {"DefaultAccountIdentifier": "ACCT-1"}})

    def test_unarchive_special_objects_and_cycles(self):
        top = {"$top": {"a": plistlib.UID(1), "n": plistlib.UID(0)},
               "$objects": ["$null",
                            {"NS.objects": [plistlib.UID(2), plistlib.UID(3), plistlib.UID(4), plistlib.UID(1)]},
                            {"NS.string": "hello"}, {"NS.time": 0.0}, {"NS.bytes": b"\x01"}]}
        out = of.unarchive(top)
        self.assertIsNone(out["n"])
        self.assertEqual(out["a"][:3], ["hello", "2001-01-01 00:00:00.000", b"\x01"])
        self.assertEqual(out["a"][3], "<cycle>")

    def test_flatten_paths_types_and_nested_bplist(self):
        inner = plistlib.dumps({"k": 1}, fmt=plistlib.FMT_BINARY)
        rows = []
        of.flatten({"a": [1, "x"], "d": dt.datetime(2025, 1, 1), "b": b"\x00\x01", "nested": inner}, "", rows)
        got = {p: (t, v) for p, t, v in rows}
        self.assertEqual(got["/a[0]"], ("int", "1"))
        self.assertEqual(got["/a[1]"], ("str", "x"))
        self.assertEqual(got["/d"], ("date", "2025-01-01 00:00:00.000"))
        self.assertEqual(got["/b"], ("bytes", "0001"))
        self.assertEqual(got["/nested{bplist}/k"], ("int", "1"))

    def test_flatten_depth_limit(self):
        deep = cur = {}
        for _ in range(50):
            cur["x"] = {}
            cur = cur["x"]
        cur["leaf"] = 1
        rows = []
        of.flatten(deep, "", rows)
        self.assertEqual(rows, [])

    def test_parse_plist_xml_and_garbage(self):
        self.write("ProfilePreferences.plist", plistlib.dumps({"Name": "Main Profile", "Count": 3}))
        self.write("broken.plist", b"bplist00 not really")
        db = self.newdb()
        self.assertTrue(of.parse_plist(self.fileinfo("ProfilePreferences.plist"), db))
        self.assertFalse(of.parse_plist(self.fileinfo("broken.plist"), db))
        self.assertEqual(dict((k, v) for k, _, v in self.rows(db, "SELECT keypath, type, value FROM plist_values")),
                         {"/Name": "Main Profile", "/Count": "3"})


# =================================================================================== legacy SQLite
class LegacySqlite(TmpCase):
    def make_wal_db(self, prof):
        """A database whose newest rows exist only in its -wal file, as in a live profile."""
        build = self.path("build")
        os.makedirs(build)
        src = os.path.join(build, "Outlook.sqlite")
        c = sqlite3.connect(src)
        c.execute("PRAGMA journal_mode=WAL")
        c.execute("PRAGMA wal_autocheckpoint=0")
        c.execute("CREATE TABLE Folders (id INTEGER, name TEXT)")
        c.commit()
        c.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        c.executemany("INSERT INTO Folders VALUES (?,?)", [(1, "Inbox"), (2, "Sent")])
        c.execute("CREATE TABLE Empty (x)")
        c.commit()
        os.makedirs(os.path.join(prof, "Data"), exist_ok=True)
        for ext in ("", "-wal"):
            shutil.copy2(src + ext, os.path.join(prof, "Data", "Outlook.sqlite" + ext))
        c.close()

    def test_wal_is_applied_without_touching_evidence(self):
        prof = self.path("prof")
        self.make_wal_db(prof)
        evid = sorted(os.listdir(os.path.join(prof, "Data")))
        snap = {f: of.hashes(os.path.join(prof, "Data", f)) for f in evid}
        files = [self.fileinfo("Data/Outlook.sqlite", root=prof)]
        db = self.newdb()
        tmp = self.path("work")
        os.makedirs(tmp)
        out = of.parse_legacy_sqlite(prof, files, db, tmp)
        self.assertIn(("Data/Outlook.sqlite", "Folders", 2), out)
        self.assertEqual(self.rows(db, 'SELECT name FROM "legacy_Outlook_Folders" ORDER BY id'), [("Inbox",), ("Sent",)])
        lt = {r[0]: r[1:] for r in self.rows(db, "SELECT tbl, rows, copied_as FROM legacy_tables")}
        self.assertEqual(lt["Empty"], (0, None))
        w = self.rows(db, "SELECT db, page_size, frames FROM wal_journals")[0]
        self.assertEqual(w[0], "Data/Outlook.sqlite")
        self.assertGreater(w[2], 0)
        self.assertEqual(sorted(os.listdir(os.path.join(prof, "Data"))), evid)           # no -shm created
        self.assertEqual({f: of.hashes(os.path.join(prof, "Data", f)) for f in evid}, snap)

    def test_unreadable_database(self):
        self.write("Data/Bad.sqlite", b"SQLite format 3\x00" + b"\xff" * 200)
        db = self.newdb()
        tmp = self.path("work")
        os.makedirs(tmp)
        of.parse_legacy_sqlite(self.tmp, [self.fileinfo("Data/Bad.sqlite")], db, tmp)
        note = self.rows(db, "SELECT note FROM legacy_tables")[0][0]
        self.assertTrue(note.startswith("unreadable"))


# =================================================================================== small binaries
class SmallBinaries(TmpCase):
    def parse(self, rel, data):
        self.write(rel, data)
        db = self.newdb()
        parser = of.parse_small(self.fileinfo(rel), db, self.tmp)
        row = self.rows(db, "SELECT parser, fields, strings FROM binary_artifacts")[0]
        return parser, json.loads(row[1]), json.loads(row[2]), db

    def test_lock_table(self):
        when = dt.datetime(2025, 11, 10, 22, 57, 43, 370000)
        data = S.lock_table([(4321, b"\x01" * 8, 9, when, 0, 2)]) + b"\x00" * 0x28 * 2
        parser, fields, _, db = self.parse("HxStore.lock", data)
        self.assertEqual(parser, "HxStore lock table")
        self.assertEqual(fields["header"], [1, 2, 3])
        self.assertEqual(len(fields["entries"]), 1)                 # all-zero entries skipped
        e = fields["entries"][0]
        self.assertEqual((e["offset"], e["pid"], e["counter"], e["slot"], e["time_utc"]),
                         (0x10, 4321, 9, 2, "2025-11-10 22:57:43.370"))
        self.assertEqual(self.rows(db, "SELECT time_utc, source FROM timeline")[0], ("2025-11-10 22:57:43.370", "lock"))

    def test_lock_table_last_entry_at_end_of_file(self):
        when = dt.datetime(2025, 11, 10, 22, 57, 43)
        data = S.lock_table([(1, b"\x00" * 8, 1, when, 0, 0), (2, b"\x00" * 8, 2, when, 0, 1)])   # no padding
        _, fields, _, _ = self.parse("HxStore.lock", data)
        self.assertEqual([e["pid"] for e in fields["entries"]], [1, 2])

    def test_counters_and_logging_cache(self):
        parser, fields, _, _ = self.parse("ExternalCounters.ctr", b"XENO" + struct.pack("<3I", 1, 2, 3))
        self.assertEqual((parser, fields["u32"]), ("external counters", [1, 2, 3]))
        parser, fields, _, _ = self.parse("FileSystemLoggingCache.log", struct.pack("<II", 2, 7) + struct.pack("<4I", 5, 5, 5, 9))
        self.assertEqual(parser, "file-system logging cache")
        self.assertEqual((fields["version"], fields["entries"], fields["distinct_values"][0]), (2, 4, ["00000005", 3]))

    def test_telemetry_and_generic(self):
        ts = S.unix(dt.datetime(2025, 11, 1, 12, 0))
        parser, fields, _, db = self.parse("TelemetryStorage/FileSystemStatisticsTelemetry.bin",
                                           struct.pack("<II", 1, ts) + struct.pack("<2Q", 10, 20))
        self.assertEqual((parser, fields["time_utc"], fields["u64"]), ("file-system telemetry", "2025-11-01 12:00:00.000", [10, 20]))
        parser, fields, strings, _ = self.parse("nls/unknown.bin", b"\x00\x01" + b"SomeIdentifier" + b"\x00")
        self.assertEqual(parser, "generic")
        self.assertIn("SomeIdentifier", strings)

    def test_replication_state_and_schema_version(self):
        parser, fields, _, _ = self.parse("rss/a.rep", b"Nostromo" + struct.pack("<8I", *range(8)) + b"\x00" * 5000)
        self.assertEqual((parser, fields["header_u32"], fields["nonzero_pages"]), ("replication state", list(range(8)), [0]))
        parser, fields, _, _ = self.parse("Data/.schema_version", b"42")
        self.assertEqual((parser, fields["value"]), ("schema version", "42"))


class ConfigFiles(TmpCase):
    def test_formats(self):
        db = self.newdb()
        for rel, data in (("Omc/a.xml", b"  <cfg><x>1</x></cfg>"), ("Omc/b.txt", b"hello"),
                          ("Omc/c.cfg", b"G123\x00FPrimary Mailbox I\x00\x02FArchive I")):
            self.write(rel, data)
            of.parse_config(self.fileinfo(rel), db)
        got = {p: (f, c) for p, f, c in self.rows(db, "SELECT path, format, content FROM config_files")}
        self.assertEqual(got["Omc/a.xml"][0], "xml")
        self.assertEqual(got["Omc/b.txt"], ("text", "hello"))
        self.assertEqual(got["Omc/c.cfg"][0], "binary (j-serialized)")
        self.assertEqual(json.loads(got["Omc/c.cfg"][1])["names"], ["Primary Mailbox", "Archive"])


# =================================================================================== Files/ caches
class FilesArea(TmpCase):
    def setUp(self):
        super().setUp()
        self.att = "Files/S0/1/Attachments/Quarterly report[3].pdf"
        self.orphan = "Files/S0/1/Attachments/old photo[9].jpg"
        self.efm_plain = "Files/S0/1/EFMData/12.dat"
        self.efm_gz = "Files/S0/1/EFMData/13.dat"
        self.photo = "Files/S0/1/Photos/" + S.photo_name(S.new_guid(), dt.datetime(2025, 10, 26, 8, 0))
        self.other = "Files/S0/1/Data/thing.bin"
        self.write(self.att, b"%PDF-1.7 synthetic")
        self.write(self.orphan, b"\xff\xd8\xff synthetic")
        self.write(self.efm_plain, b"<html><head><title> Hello </title></head><body><p>Body text</p></body></html>")
        self.write(self.efm_gz, gzip.compress(b"<html><body>Zipped body</body></html>"))
        self.write(self.photo, S.png(64, 32))
        self.write(self.other, b"<\x00x\x00>\x00")
        self.write("Files/S0/1/Attachments/.DS_Store", b"\x00\x00\x00\x01Bud1")

    def run_area(self):
        files = [self.fileinfo(r) for r in (self.att, self.orphan, self.efm_plain, self.efm_gz, self.photo,
                                            self.other, "Files/S0/1/Attachments/.DS_Store")]
        store_att = {(5218940, self.att): ("Quarterly report.pdf", None, None, None, None, None, "sender@example.org")}
        efm_refs = {5218940: {12}}
        db = self.newdb()
        st = of.parse_files_area(files, db, store_att, efm_refs)
        return st, db

    def test_stats(self):
        st, _ = self.run_area()
        self.assertEqual(dict(st), {"attachments": 2, "efm": 2, "photos": 1})

    def test_attachment_links(self):
        _, db = self.run_area()
        a = {r[0]: r[1:] for r in self.rows(db, "SELECT path, filename, ref_no, ext, store_record_ids, store_names, senders FROM attachment_files")}
        self.assertEqual(a[self.att], ("Quarterly report[3].pdf", 3, ".pdf", "5218940", "Quarterly report.pdf", "sender@example.org"))
        self.assertEqual(a[self.orphan][1:4], (9, ".jpg", None))
        c = dict(self.rows(db, "SELECT left_ref, status FROM correlations WHERE kind LIKE 'attachment%'"))
        self.assertEqual(c, {self.att: "linked", self.orphan: "on disk only"})

    def test_bodies(self):
        _, db = self.run_area()
        e = {r[0]: r[1:] for r in self.rows(db, "SELECT path, number, format, title, text_preview, store_record_ids FROM efm_files")}
        self.assertEqual(e[self.efm_plain][:3], (12, "plain", "Hello"))
        self.assertIn("Body text", e[self.efm_plain][3])
        self.assertEqual(e[self.efm_plain][4], "5218940")
        self.assertEqual(e[self.efm_gz][:2], (13, "gzip"))
        self.assertIn("Zipped body", e[self.efm_gz][3])
        self.assertIsNone(e[self.efm_gz][4])
        c = dict(self.rows(db, "SELECT left_ref, status FROM correlations WHERE kind LIKE 'EFMData%'"))
        self.assertEqual(c, {self.efm_plain: "linked", self.efm_gz: "unreferenced"})

    def test_photos_and_other(self):
        _, db = self.run_area()
        p = self.rows(db, "SELECT kind, guid, time_utc, width, height FROM photos")[0]
        self.assertEqual(p, ("contact photo", S.new_guid(), "2025-10-26 08:00:00.000", 64, 32))
        self.assertEqual(self.rows(db, "SELECT kind FROM timeline")[0][0], "photo timestamp (filename ticks)")
        b = self.rows(db, "SELECT path, strings FROM binary_artifacts")
        self.assertEqual(b[0][0], self.other)
        self.assertEqual(json.loads(b[0][1]), ["<x>"])                # UTF-16 XML decoded


# =================================================================================== DB, inventory
class Database(TmpCase):
    def test_schema_views_and_buffering(self):
        db = self.newdb()
        names = {r[0] for r in db.c.execute("SELECT name FROM sqlite_master")}
        for t in ("meta", "files", "timeline", "hfl_records", "store_records", "osa_logs", "wal_journals"):
            self.assertIn(t, names)
        for v in ("store_mail", "hfl_store_objects", "osa_commands"):
            self.assertIn(v, names)
        for i in range(5001):
            db.add("findings", ("info", "a", str(i), ""))
        self.assertEqual(db.c.execute("SELECT count(*) FROM findings").fetchone()[0], 5000)   # auto-flushed batch
        db.flush()
        self.assertEqual(db.c.execute("SELECT count(*) FROM findings").fetchone()[0], 5001)

    def test_meta_timeline_and_close(self):
        db = self.newdb()
        db.meta("a", "text")
        db.meta("b", [1, 2])
        db.tl(None, "x", "y", "z", "dropped")
        db.tl("2025-01-01 00:00:00.000", "x", "y", "z", "d" * 900)
        db.close()
        self.assertEqual(dict(db.c.execute("SELECT key, value FROM meta")), {"a": "text", "b": "[1, 2]"})
        rows = db.c.execute("SELECT description FROM timeline").fetchall()
        self.assertEqual(len(rows), 1)
        self.assertEqual(len(rows[0][0]), 500)
        idx = {r[0] for r in db.c.execute("SELECT name FROM sqlite_master WHERE type='index'")}
        self.assertTrue({"ix_tl", "ix_store", "ix_osa"} <= idx)

    def test_existing_db_is_replaced(self):
        p = self.path("x.db")
        with open(p, "w") as fh:
            fh.write("old")
        db = of.DB(p)
        db.c.close()
        self.assertTrue(sqlite3.connect(p).execute("SELECT count(*) FROM meta").fetchone() == (0,))


class Inventory(TmpCase):
    def test_hashes_types_and_order(self):
        prof = self.path("p")
        self.write("b.plist", plistlib.dumps({}, fmt=plistlib.FMT_BINARY), root=prof)
        self.write("Osa/F_00000000/a.xmlgz", S.gz(b"<x/>"), root=prof)
        self.write("a.txt", b"hello\n", root=prof)
        db = self.newdb()
        files = of.inventory(prof, db)
        self.assertEqual([f["path"] for f in files], ["a.txt", "b.plist", "Osa/F_00000000/a.xmlgz"])
        a = files[0]
        self.assertEqual(a["sha256"], hashlib.sha256(b"hello\n").hexdigest())
        self.assertEqual(a["type"], "text")
        self.assertEqual(files[1]["type"], "binary property list")
        self.assertEqual(files[2]["category"], "Osa API logs")
        self.assertEqual(a["head"], b"hello\n")

    def test_copy_without_timestamps_is_flagged(self):
        prof = self.path("p")
        for i in range(55):
            self.write("f%02d.bin" % i, b"x", root=prof)
        db = self.newdb()
        of.inventory(prof, db)
        f = self.rows(db, "SELECT severity, area FROM findings")
        self.assertEqual(f, [("warning", "Acquisition")])
        self.assertEqual(len(json.loads(self.rows(db, "SELECT value FROM meta WHERE key='fs_mtime_range'")[0][0])), 2)

    def test_few_files_not_flagged(self):
        prof = self.path("p")
        self.write("one.bin", b"x", root=prof)
        db = self.newdb()
        of.inventory(prof, db)
        self.assertEqual(self.rows(db, "SELECT count(*) FROM findings")[0][0], 0)


# =================================================================================== correlation, findings
class CorrelationAndFindings(TmpCase):
    def populate(self, db):
        store = lambda rid, ver: ("HxStore.hxd", rid, ver, 2, 1, 4096, 10, 20, "0x3B0", "Email record", 191,
                                  "Email", rid, 1, "s@example.org", "S", "Subj", "2025-11-10 22:00:00.000",
                                  None, None, None, "Inbox", 3, "h", b"p", b"r")
        for row in (store(100, 1), store(100, 2), store(200, 1), store(300, 1)):
            db.add("store_records", row)
        act = lambda oid, n: ("hxcore.hfl", oid, n, "2025-11-10 22:57:43.335", "2025-11-10 22:59:00.000", "{}", "{}", "0:0x0", "0:0x10")
        db.add("hfl_object_activity", act(100, 30))
        db.add("hfl_object_activity", act(200, 10))
        db.add("hfl_object_activity", act(999, 60))       # not in the store
        db.add("store_attachments", ("HxStore.hxd", 100, "1", "a.pdf", "/x", "Files/S0/1/Attachments/a[1].pdf", 0, None, None, None))
        db.add("hfl_files", ("hxcore.hfl", 1, "h", "b", "", "", "2025-11-10 22:57:43.335", "2025-11-10 23:30:00.000",
                             1, 0, 0, 3, 0, 0, 1, 0, 1, "records", "{}", "{}"))
        osa = lambda i, t, st: (i, "f", "F", 0, None, i, "a", "sync", "Cmd%d" % (i % 2), None, "response", "Log", t,
                                None, None, None, None, None, st, None, "BE01", None, None, None, None, None, None,
                                None, None, None, None, None, None, "UA/1", None, 0, "<Log/>")
        db.add("osa_logs", osa(1, "2025-11-10 22:58:00.000", "Ok"))
        db.add("osa_logs", osa(2, "2025-11-10 23:00:00.000", "304"))
        db.add("osa_logs", osa(3, "2025-11-10 23:10:00.000", "ErrorItemNotFound"))
        db.add("osa_logs", osa(4, "2025-11-11 09:00:00.000", "500"))      # outside the trace range
        db.add("attachment_files", ("Files/S0/1/Attachments/o[2].png", "o[2].png", 2, ".png", 5, "h", "PNG image", None, None, None))
        db.add("plist_values", ("ProfilePreferences.plist", "/DefaultAccountIdentifier", "str", "ACCT-1"))

    def test_correlate(self):
        db = self.newdb()
        self.populate(db)
        of.correlate(db, {"ids": {100, 200, 300}})
        c = {k: (s, d) for k, s, d in self.rows(db, "SELECT kind, status, detail FROM correlations")}
        self.assertEqual(c["hfl object ids <-> HxStore records"][1],
                         "3 logged object ids, 2 present in the store, covering 40 of 100 mentions (40%)")
        self.assertEqual(c["HxStore records never seen in trace logs"][1], "1 records")
        self.assertEqual(c["store attachment reference -> file"][0], "file missing")
        self.assertIn(": 3 Osa log files (2 distinct commands)", c["hfl time range <-> Osa API logs"][1])

    def test_correlate_without_store(self):
        db = self.newdb()
        self.populate(db)
        of.correlate(db, None)
        kinds = {k for (k,) in self.rows(db, "SELECT kind FROM correlations")}
        self.assertNotIn("hfl object ids <-> HxStore records", kinds)
        self.assertIn("hfl time range <-> Osa API logs", kinds)

    def test_findings(self):
        db = self.newdb()
        self.populate(db)
        of.findings(db)
        f = [r[0] for r in self.rows(db, "SELECT finding FROM findings")]
        bad = [x for x in f if x.startswith("Non-success API responses")]
        self.assertEqual(len(bad), 1)
        self.assertIn("ErrorItemNotFound=1", bad[0])
        self.assertIn("500=1", bad[0])
        self.assertNotIn("Ok=", bad[0])
        self.assertNotIn("304=", bad[0])
        self.assertIn("Default account: ACCT-1", f)
        self.assertIn("1 attachment references in HxStore, 1 point to files that are not on disk", f)
        self.assertIn("1 cached attachment files are not referenced by any current HxStore record", f)
        self.assertIn("1 store objects have more than one stored version (older versions still in the file)", f)
        self.assertTrue(any(x.startswith("Mailbox back-end server: BE01") for x in f))


# =================================================================================== export
class ExportContent(TmpCase):
    def setUp(self):
        super().setUp()
        self.prof = self.path("prof")
        self.out = self.path("out")
        os.makedirs(self.out)
        self.write("Files/S0/1/Attachments/Quarterly report[3].pdf", b"%PDF synthetic", root=self.prof)
        self.write("Files/S0/1/Attachments/Quarterly report[4].pdf", b"%PDF second", root=self.prof)
        self.write("Files/S0/1/Attachments/left over[9].jpg", b"\xff\xd8\xff jpg", root=self.prof)
        db = of.DB(os.path.join(self.out, "profile.db"))
        db.meta("profile_path", self.prof)
        rec = lambda rid, ver, payload, subj: ("HxStore.hxd", rid, ver, 2, 1, 0, 1, len(payload), "0x3B0", "Email record",
                                              191, "Email", rid, 1, "s@example.org", "S", subj, "2025-11-10 22:00:00.000",
                                              None, None, None, "Inbox", 0, hashlib.sha256(payload).hexdigest(), payload, b"")
        db.add("store_records", rec(10, 1, b"v1 payload", "First"))
        db.add("store_records", rec(10, 2, b"v2 payload", "First"))
        db.add("store_bodies", ("HxStore.hxd", 10, "efm", 10, "Files/S0/1/EFMData/12.dat", "txt", "<html><body>Hi</body></html>"))
        db.add("store_bodies", ("HxStore.hxd", 11, "preview", 11, None, "a < b & c", None))
        for rel in ("Files/S0/1/Attachments/Quarterly report[3].pdf", "Files/S0/1/Attachments/Quarterly report[4].pdf"):
            db.add("store_attachments", ("HxStore.hxd", 10, "1", "Quarterly report.pdf", None, rel, 1, 1, "h", None))
        db.add("store_attachments", ("HxStore.hxd", 12, "1", "gone.docx", None, "Files/S0/1/Attachments/gone[1].docx", 0, None, None, None))
        db.add("attachment_files", ("Files/S0/1/Attachments/left over[9].jpg", "left over[9].jpg", 9, ".jpg", 9,
                                    of.hashes(os.path.join(self.prof, "Files/S0/1/Attachments/left over[9].jpg"))[1],
                                    "JPEG image", None, None, None))
        db.close()
        db.c.close()
        self.db = os.path.join(self.out, "profile.db")

    def test_files_names_and_counts(self):
        cnt = of.export_content(self.db, self.out)
        self.assertEqual(dict(cnt), {"e-mail body": 2, "store record (decompressed)": 2, "attachment": 2,
                                     "attachment (missing on disk)": 1, "attachment (unreferenced)": 1})
        ex = os.path.join(self.out, "export")
        self.assertEqual(sorted(os.listdir(os.path.join(ex, "bodies"))), ["10_efm.html", "11_preview.html"])
        self.assertEqual(sorted(os.listdir(os.path.join(ex, "records"))), ["10_v1.bin", "10_v2.bin"])
        self.assertEqual(sorted(os.listdir(os.path.join(ex, "attachments"))),
                         ["10_Quarterly report.pdf", "10_Quarterly report_2.pdf", "unreferenced"])   # collision -> _2
        self.assertEqual(os.listdir(os.path.join(ex, "attachments", "unreferenced")), ["left over.jpg"])
        with open(os.path.join(ex, "records", "10_v2.bin"), "rb") as fh:
            self.assertEqual(fh.read(), b"v2 payload")

    def test_text_only_body_is_escaped(self):
        of.export_content(self.db, self.out)
        with open(os.path.join(self.out, "export", "bodies", "11_preview.html"), encoding="utf-8") as fh:
            s = fh.read()
        self.assertIn("a &lt; b &amp; c", s)
        self.assertIn("Preview text only", s)

    def test_manifest_hashes_verify_and_match_table(self):
        of.export_content(self.db, self.out)
        with open(os.path.join(self.out, "export", "manifest.csv"), newline="", encoding="utf-8") as fh:
            rows = list(csv.DictReader(fh))
        self.assertEqual(len(rows), 8)
        for r in rows:
            if r["path"]:
                self.assertEqual(of.hashes(os.path.join(self.out, r["path"]))[1], r["sha256"], r["path"])
            else:
                self.assertEqual(r["kind"], "attachment (missing on disk)")
        n = sqlite3.connect(self.db).execute("SELECT count(*) FROM export_files").fetchone()[0]
        self.assertEqual(n, len(rows))

    def test_rerun_replaces_export(self):
        of.export_content(self.db, self.out)
        stray = os.path.join(self.out, "export", "bodies", "stray.html")
        open(stray, "w").close()
        of.export_content(self.db, self.out)
        self.assertFalse(os.path.exists(stray))
        self.assertEqual(sqlite3.connect(self.db).execute("SELECT count(*) FROM export_files").fetchone()[0], 8)


class ExportJson(TmpCase):
    def test_small_and_large_tables(self):
        db = of.DB(self.path("profile.db"))
        for i in range(30):
            db.add("findings", ("info", "a", str(i), ""))
        db.add("store_records", ("HxStore.hxd", 1, 1, 1, 0, 0, 1, 1, "f", "n", 1, "t", 1, 0, None, None, None, None,
                                 None, None, None, None, 0, "h", b"\x00secret", b"\x00raw"))
        db.add("config_files", ("Omc/x", "binary", b"\x01\x02"))
        db.close()
        db.c.close()
        of.export_json(self.path("profile.db"), self.tmp, big=20)
        with open(self.path("profile.json"), encoding="utf-8") as fh:
            doc = json.load(fh)
        self.assertEqual(doc["large_tables"]["findings"], {"rows": 30, "file": os.path.join("json", "findings.jsonl")})
        with open(self.path("json", "findings.jsonl"), encoding="utf-8") as fh:
            self.assertEqual(len(fh.readlines()), 30)
        rec = doc["tables"]["store_records"][0]
        self.assertNotIn("payload", rec)
        self.assertNotIn("raw", rec)
        self.assertEqual(doc["tables"]["config_files"][0]["content"], "0102")     # bytes -> hex
        self.assertIn("store_mail", doc["tables"])                                 # views exported too


# =================================================================================== HTML
class HtmlReport(TmpCase):
    def test_table_cells(self):
        h = of.table(["a", "n", "t", "l"], [("<x>", 1234567, "2025-11-10 22:00:00.000", of.Link("open", "../e/a b.html")),
                                            ("y", 1.25, None, "z")],
                     num=(1,), mono=(0,), fid="t1", tzcols=(2,), tz=7)
        self.assertIn('<td class="mono">&lt;x&gt;</td>', h)
        self.assertIn('<td class="n">1,234,567</td>', h)
        self.assertIn('<td class="n">1.2</td>', h)
        self.assertIn("<td>2025-11-11 05:00:00.000</td>", h)
        self.assertIn('<a href="../e/a b.html">open</a>', h)
        self.assertIn('id="t1"', h)
        self.assertIn("flt(this,'t1')", h)

    def test_table_maxrows(self):
        h = of.table(["a"], [(i,) for i in range(10)], maxrows=3)
        self.assertEqual(h.count("<tr>"), 4)              # header + 3
        self.assertIn("showing 3 of 10 rows", h)

    def test_daily_chart(self):
        self.assertIn("no timestamps", of.daily_chart([], 0))
        svg = of.daily_chart([("2025-11-10", "osa", 5), ("2025-11-10", "hfl", 3), ("2025-11-11", "osa", 1)], 0)
        self.assertTrue(svg.startswith("<svg"))
        self.assertIn("events per day", svg)

    def test_write_pages_splits_sections_and_links_resolve(self):
        body = ['<h1>Title</h1><p>head</p>', '<h2 id="summary">Summary</h2><p>sum</p>',
                '<h2 id="findings">Findings</h2><p>f</p>', '<h2 id="timeline">Timeline</h2><p>t</p>',
                '<h2 id="custom">Custom</h2><p>c</p>']
        out = self.path("report.html")
        of.write_pages(out, body, {"profile_path": "/p"}, "UTC+7")
        pages = sorted(os.listdir(self.path("report")))
        self.assertEqual(pages, ["custom.html", "findings.html", "timeline.html"])
        with open(out, encoding="utf-8") as fh:
            main = fh.read()
        self.assertIn("<p>sum</p>", main)                # summary stays on the main page
        self.assertNotIn("<p>f</p>", main)               # sections moved out
        self.assertLess(main.index("report/findings.html"), main.index("report/timeline.html"))   # SECTION_INFO order
        with open(self.path("report", "timeline.html"), encoding="utf-8") as fh:
            t = fh.read()
        self.assertIn('<h1 id="timeline">Timeline</h1>', t)
        self.assertIn('href="findings.html">&larr; Findings', t)
        self.assertIn('href="custom.html">custom &rarr;', t)
        self.assertIn('href="../report.html"', t)
        assert_links_resolve(self, self.tmp)

    def test_rewrite_removes_old_pages(self):
        out = self.path("report.html")
        of.write_pages(out, ['<h1>x</h1><h2 id="osa">Osa</h2>'], {}, "UTC")
        of.write_pages(out, ['<h1>x</h1><h2 id="hfl">HFL</h2>'], {}, "UTC")
        self.assertEqual(os.listdir(self.path("report")), ["hfl.html"])


def assert_links_resolve(tc, outdir):
    """Every relative href in report.html and report/*.html must point to an existing file."""
    pages = [os.path.join(outdir, "report.html")] + [os.path.join(outdir, "report", f)
                                                    for f in os.listdir(os.path.join(outdir, "report"))]
    n = 0
    for p in pages:
        with open(p, encoding="utf-8") as fh:
            s = fh.read()
        for href in re.findall(r'href="([^"]+)"', s):
            href = html_unescape(href)
            if href.startswith(("#", "http:", "https:", "mailto:")):
                continue
            target = os.path.normpath(os.path.join(os.path.dirname(p), href.split("#")[0]))
            tc.assertTrue(os.path.exists(target), "%s -> %s" % (os.path.relpath(p, outdir), href))
            n += 1
    return n


def html_unescape(s):
    import html
    return html.unescape(s)


# =================================================================================== end to end
def build_profile(root):
    """A small synthetic profile that touches every parser except HxStore.hxd."""
    def w(rel, data):
        full = os.path.join(root, rel)
        os.makedirs(os.path.dirname(full), exist_ok=True)
        with open(full, "wb") as fh:
            fh.write(data)
    oid_hex = (0x4F6D19).to_bytes(8, "little").hex().upper()
    w("hxcore.hfl", S.hfl_file(T_CREATED, MONO_AT_CREATE, [S.hfl_chunk([
        S.hfl_record(6_335_000_000, 1011, 2, 4, [S.tlv_str16(oid_hex), S.tlv_str16("sync")]),
        S.hfl_record(6_400_000_000, 20, 4, 1, [S.tlv_str8("QueueRun"), S.tlv_u32(1)]),
    ])]))
    w("AccountsBackup.bhxd", S.account_backup("Account", [S.kv_entry("Enabled", 7, b"\x01")]))
    folder = "Osa/OutlookServiceApiLogs_2025-11-10-22_%08X/" % S.unix(dt.datetime(2025, 11, 10, 22, 57, 43))
    w(folder + "osa{2025-11-10-22-57-44}_1_acct01_app.Initialize.request.xmlgz",
      S.gz(S.osa_xml(LogTime="2025-11-10T22:57:44.153Z", StatusCode="Success")))
    w(folder + "osa{2025-11-10-22-58-00}_2_acct01_sync.GetItem.7.response.xmlgz",
      S.gz(S.osa_xml(LogTime="2025-11-10T22:58:00.000Z", StatusCode="ErrorItemNotFound", BackEndServer="BE01")))
    w("Data/Categories/3/0A1B.olk15Category", S.olk15("CATa", [(1, 0x1f, "Blue".encode("utf-16-le"))]))
    w("ProfilePreferences.plist", plistlib.dumps({"DefaultAccountIdentifier": "ACCT-1"}, fmt=plistlib.FMT_BINARY))
    w("clientConfigsForAM.dat", S.keyed_archive("ConfigVersion", "3"))
    w("Omc/settings.xml", b"<cfg/>")
    w("HxStore.lock", S.lock_table([(99, b"\x00" * 8, 1, dt.datetime(2025, 11, 10, 22, 57, 43, 370000), 0, 0)]) + b"\x00" * 80)
    w("ExternalCounters.ctr", b"XENO" + struct.pack("<2I", 1, 2))
    w("Files/S0/1/Attachments/Doc[3].pdf", b"%PDF synthetic")
    w("Files/S0/1/EFMData/12.dat", b"<html><body>body</body></html>")
    w("Files/S0/1/Photos/" + S.photo_name(S.new_guid(), dt.datetime(2025, 10, 26, 8)), S.png(8, 8))
    c = sqlite3.connect(os.path.join(root, "Data", "Outlook.sqlite"))
    c.execute("CREATE TABLE Folders (id, name)")
    c.execute("INSERT INTO Folders VALUES (1, 'Inbox')")
    c.commit()
    c.close()


def snapshot(root):
    snap = {}
    for dp, _, fns in os.walk(root):
        for fn in fns:
            full = os.path.join(dp, fn)
            st = os.stat(full)
            snap[os.path.relpath(full, root)] = (of.hashes(full)[1], st.st_size, st.st_mtime_ns)
    return snap


class EndToEnd(TmpCase):
    @classmethod
    def setUpClass(cls):
        cls.base = tempfile.mkdtemp(prefix="olkf_e2e_")
        cls.prof = os.path.join(cls.base, "Main Profile")
        cls.out = os.path.join(cls.base, "out")
        build_profile(cls.prof)
        cls.before = snapshot(cls.prof)
        args = argparse.Namespace(profile=cls.prof, out=cls.out, tz=7.0, hfl_mode="records", skip_hfl=False)
        with quiet():
            of.run(args)
        cls.after = snapshot(cls.prof)
        cls.c = sqlite3.connect(os.path.join(cls.out, "profile.db"))

    @classmethod
    def tearDownClass(cls):
        cls.c.close()
        shutil.rmtree(cls.base, True)

    def q(self, sql, *a):
        return self.c.execute(sql, a).fetchall()

    def test_evidence_is_unchanged(self):
        self.assertEqual(self.after, self.before)

    def test_every_file_inventoried_and_parsed(self):
        files = dict(self.q("SELECT path, parser FROM files"))
        self.assertEqual(set(files), set(self.before))
        self.assertEqual(files["hxcore.hfl"], "hfl")
        self.assertEqual(files["AccountsBackup.bhxd"], "accounts backup")
        self.assertEqual(files["ProfilePreferences.plist"], "plist")
        self.assertEqual(files["Omc/settings.xml"], "config")
        self.assertEqual(files["Data/Outlook.sqlite"], "sqlite")
        self.assertEqual(files["Data/Categories/3/0A1B.olk15Category"], "olk15")
        self.assertEqual(files["HxStore.lock"], "binary")
        self.assertEqual(self.q("SELECT count(*) FROM files WHERE parse_status != 'ok'"), [(0,)])
        for path, sha in self.q("SELECT path, sha256 FROM files"):
            self.assertEqual(sha, self.before[path][0])

    def test_decoded_tables(self):
        self.assertEqual(self.q("SELECT records, errors FROM hfl_files"), [(2, 1)])
        self.assertEqual(self.q("SELECT count(*) FROM osa_logs"), [(2,)])
        self.assertEqual(self.q("SELECT value FROM account_backup"), [("1",)])
        self.assertEqual(self.q("SELECT name FROM legacy_Outlook_Folders"), [("Inbox",)])
        self.assertEqual(self.q("SELECT name FROM olk15_records"), [("Blue",)])
        self.assertEqual(self.q("SELECT count(*) FROM attachment_files"), [(1,)])
        self.assertEqual(self.q("SELECT count(*) FROM photos"), [(1,)])

    def test_session_start_is_corroborated_by_three_clocks(self):
        tl = self.q("SELECT time_utc, source, kind FROM timeline WHERE time_utc BETWEEN '2025-11-10 22:57:43' AND '2025-11-10 22:57:45' ORDER BY time_utc")
        got = [(t, s) for t, s, k in tl if k in ("api log session start", "first trace record", "store lock entry")]
        self.assertEqual(got, [("2025-11-10 22:57:43.000", "osa"), ("2025-11-10 22:57:43.335", "hfl"),
                               ("2025-11-10 22:57:43.370", "lock")])

    def test_findings_and_correlations(self):
        f = [r[0] for r in self.q("SELECT finding FROM findings")]
        self.assertIn("Default account: ACCT-1", f)
        self.assertTrue(any("ErrorItemNotFound=1" in x for x in f))
        kinds = {k for (k,) in self.q("SELECT kind FROM correlations")}
        self.assertIn("hfl time range <-> Osa API logs", kinds)
        self.assertIn("attachment file <-> store record", kinds)

    def test_outputs_exist(self):
        for rel in ("profile.db", "profile.json", "report.html", "export/manifest.csv"):
            self.assertTrue(os.path.isfile(os.path.join(self.out, rel)), rel)
        pages = set(os.listdir(os.path.join(self.out, "report")))
        self.assertTrue({"findings.html", "inventory.html", "timeline.html", "osa.html", "hfl.html"} <= pages, pages)
        with open(os.path.join(self.out, "profile.json"), encoding="utf-8") as fh:
            doc = json.load(fh)
        self.assertEqual(len(doc["tables"]["files"]), len(self.before))
        self.assertEqual(os.listdir(os.path.join(self.out, "export", "attachments", "unreferenced")), ["Doc.pdf"])

    def test_report_links_resolve_and_times_are_shifted(self):
        self.assertGreater(assert_links_resolve(self, self.out), 20)
        with open(os.path.join(self.out, "report", "timeline.html"), encoding="utf-8") as fh:
            t = fh.read()
        self.assertIn("UTC+7", t)
        self.assertIn("2025-11-11 05:57:43.335", t)          # 22:57:43.335 UTC shown in UTC+7

    def test_report_only_and_rebuild_cli(self):
        db = os.path.join(self.out, "profile.db")
        env = dict(os.environ, PYTHONDONTWRITEBYTECODE="1")
        tool = os.path.join(ROOT, "olk_forensic.py")
        r = subprocess.run([sys.executable, "-I", tool, "--report-only", db, "--tz", "0"],
                           capture_output=True, text=True, env=env, timeout=300)
        self.assertEqual(r.returncode, 0, r.stderr)
        r = subprocess.run([sys.executable, "-I", tool, "--rebuild", db, "--tz", "7"],
                           capture_output=True, text=True, env=env, timeout=300)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("export:", r.stdout)
        self.assertEqual(snapshot(self.prof), self.before)
        assert_links_resolve(self, self.out)


class Cli(unittest.TestCase):
    def run_tool(self, *args):
        return subprocess.run([sys.executable, "-I", os.path.join(ROOT, "olk_forensic.py")] + list(args),
                              capture_output=True, text=True, timeout=120, env=dict(os.environ, PYTHONDONTWRITEBYTECODE="1"))

    def test_help(self):
        r = self.run_tool("--help")
        self.assertEqual(r.returncode, 0)
        self.assertIn("--hfl-mode", r.stdout)
        self.assertIn("--rebuild", r.stdout)

    def test_missing_profile_argument(self):
        r = self.run_tool()
        self.assertEqual(r.returncode, 2)
        self.assertIn("profile folder required", r.stderr)

    def test_profile_not_a_folder(self):
        r = self.run_tool("/nonexistent/profile/folder", "--out", tempfile.gettempdir() + "/olkf_never")
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("is not a folder", r.stderr)

    def test_no_bytecode_written(self):
        self.assertFalse(os.path.isdir(os.path.join(ROOT, "__pycache__")))


# =================================================================================== optional: real profile
@unittest.skipUnless(os.environ.get("OLK_PROFILE"), "set OLK_PROFILE to a real profile folder to run")
class RealProfile(TmpCase):
    """Read-only checks against a real profile: HxStore decoding and trace-log well-formedness."""

    def setUp(self):
        super().setUp()
        self.prof = os.path.abspath(os.environ["OLK_PROFILE"])

    def test_store_parse(self):
        p = os.path.join(self.prof, "HxStore.hxd")
        if not os.path.isfile(p):
            self.skipTest("no HxStore.hxd")
        if of.HXDECODE_ERR:
            self.skipTest(of.HXDECODE_ERR)
        before = of.hashes(p)
        db = self.newdb()
        with quiet():
            r = of.store_parse(p, "HxStore.hxd", db, self.prof, {})
        self.assertGreater(r["records"], 0)
        self.assertEqual(self.rows(db, "SELECT count(*) FROM store_records")[0][0], r["records"])
        self.assertEqual(self.rows(db, "SELECT count(*) FROM store_records WHERE payload_sha256 IS NULL")[0][0], 0)
        self.assertEqual(of.hashes(p), before)

    def test_trace_log_well_formedness(self):
        p = os.path.join(self.prof, "hxcore.hfl")
        if not os.path.isfile(p):
            self.skipTest("no hxcore.hfl")
        with open(p, "rb") as fh:
            d = fh.read()
        h = hp.parse_header(d)
        sig = {}
        for kind, pos, length in hp.iter_chunks(d, h["data_start"]):
            if kind != "chunk":
                continue
            dec = hp.lz4_block(d[pos + hp.CHUNK_HDR:pos + length])
            self.assertIsNotNone(dec, "chunk at 0x%x does not decompress" % pos)
            self.assertEqual(len(dec), hp.chunk_header(d, pos)["decoded_size"])                 # W1
            end = 0
            for off, rh in hp.iter_records(dec):
                args, aend, err = hp.decode_args(dec, off + rh[5], off + rh[4], rh[3])
                self.assertIsNone(err, "record at chunk 0x%x + 0x%x" % (pos, off))             # W3
                key = "%d.%d" % (rh[8], rh[6])
                self.assertEqual(sig.setdefault(key, hp.arg_signature(args)), hp.arg_signature(args))   # W4
                end = off + rh[4]
            self.assertEqual(end, len(dec))                                                     # W2


if __name__ == "__main__":
    unittest.main()

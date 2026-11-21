#!/usr/bin/env python3
"""
olk_forensic.py - forensic parser for a whole Outlook for Mac (new Outlook / HxCore) profile
folder, e.g. a copy of
  ~/Library/Group Containers/UBF8T346G9.Office/Outlook/Outlook 15 Profiles/Main Profile

Every file in the profile is inventoried (size, timestamps, MD5, SHA-256, detected type) and
every known artifact is decoded:

  hxcore.hfl, hxcore_previous_session.hfl   HxCore trace logs (decoded with hfl_parse.py)
  HxStore.hxd                              HxCore object store (hxstore-decode library):
                                           every record version, strings, e-mails, folders,
                                           attachment references, message bodies
  AccountsBackup.bhxd                      account settings backup (uncompressed key/value
                                           records, decoded here)
  Osa/**/*.xmlgz                           Outlook Service API request/response logs
  Data/*.sqlite (+ -wal)                   legacy Outlook 2016 database, lock databases
  Data/**/*.olk15*                         legacy Outlook 2016 record files (property lists)
  ProfilePreferences.plist,
  clientConfigsForAM.dat                   property lists / NSKeyedArchiver
  Files/S0/*/Attachments, EFMData, Photos,
  AadLogos, Data                           cached attachments, message bodies, photos
  Omc/**                                   Outlook.com connector configuration
  HxStore.lock, ExternalCounters.ctr, TelemetryStorage/*.bin, FileSystemLoggingCache.log,
  rss/*.rep, nls, PreferencesSearchIndex   small binaries (fields + strings)

and then correlated: trace-log object IDs <-> store records, store attachment references <->
attachment files on disk, store records <-> EFMData bodies, all timestamps -> one timeline.

Outputs (in --out, default ./olk_forensic_out):
  profile.db           SQLite database with every table (see the report's "SQL" section)
  profile.json         all small tables; large tables go to json/<table>.jsonl
  report.html          main report page (summary + menu); each section is a page in report/
  report/<section>.html  one page per report section
  export/bodies/<record_id>_<source>.html     one file per e-mail body
  export/records/<record_id>_v<version>.bin   decompressed payload of every store record version
  export/attachments/<record_id>_<name>        attachment copies named by owning record ID
  export/attachments/unreferenced/             cached attachments no record references
  export/manifest.csv  every exported file with SHA-256 (also table export_files)

Input files are only read. The SQLite databases are opened from a temporary copy so that
their -wal journals are applied without touching the evidence.

Needs Python 3.10+ and the `lz4` package (for HxStore.hxd via ./hxstore-decode/src).

USAGE
  python3.12 -I olk_forensic.py "Main Profile" --out olk_forensic_out --tz 7
  python3.12 -I olk_forensic.py "Main Profile" --hfl-mode summary      # faster, errors only
  python3.12 -I olk_forensic.py --report-only olk_forensic_out/profile.db --tz 7
  python3.12 -I olk_forensic.py --rebuild olk_forensic_out/profile.db --tz 7   # export + JSON + report
"""
import sys
sys.dont_write_bytecode = True
import argparse
import collections
import datetime as dt
import gzip
import hashlib
import html
import json
import os
import plistlib
import re
import shutil
import sqlite3
import struct
import sys
import tempfile
import time
import uuid
import xml.etree.ElementTree as ET

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(HERE, "hxstore-decode", "src"))

import hfl_parse as hp  # noqa: E402

try:
    from hxdecode.parser import HxStoreFile                      # noqa: E402
    from hxdecode.decompress import decompress_record             # noqa: E402
    from hxdecode.folder import FolderIndex                       # noqa: E402
    from hxdecode.body import extract_html_body, html_to_text, extract_body_preview  # noqa: E402
    from hxdecode.extract import (extract_utf16le_strings, extract_emails,  # noqa: E402
                                  extract_timestamps, extract_email_fields, extract_display_time)
    HXDECODE_ERR = None
except Exception as ex:          # library missing or Python too old
    HXDECODE_ERR = "%s: %s" % (type(ex).__name__, ex)

TOOL = "olk_forensic.py"
VERSION = "1.0"
NET_EPOCH = 621355968000000000
COCOA_EPOCH = dt.datetime(2001, 1, 1)
UNIX_EPOCH = dt.datetime(1970, 1, 1)
U16_RUN = re.compile(rb"(?:[\x20-\x7e]\x00){4,}")
ASCII_RUN = re.compile(rb"[\x20-\x7e]{5,}")
EMAIL_RE = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")


# =========================================================================== helpers
def iso(d):
    return d.strftime("%Y-%m-%d %H:%M:%S.%f")[:23] if d else None


def from_unix(s):
    try:
        return iso(UNIX_EPOCH + dt.timedelta(seconds=s))
    except (OverflowError, ValueError, TypeError):
        return None


def from_ticks(t):
    try:
        return iso(UNIX_EPOCH + dt.timedelta(microseconds=(t - NET_EPOCH) // 10)) if 5e17 < t < 7e17 else None
    except (OverflowError, ValueError):
        return None


def from_cocoa(s):
    try:
        return iso(COCOA_EPOCH + dt.timedelta(seconds=s)) if -1e9 < s < 2e9 else None
    except (OverflowError, ValueError):
        return None


def strings_of(b, limit=60):
    out = []
    for m in U16_RUN.finditer(b):
        s = m.group().decode("utf-16-le", "replace").strip()
        if s not in out:
            out.append(s[:300])
        if len(out) >= limit:
            return out
    for m in ASCII_RUN.finditer(b):
        s = m.group().decode("ascii").strip()
        if len(s) >= 5 and s not in out and not re.fullmatch(r"(.)\1+", s):
            out.append(s[:300])
        if len(out) >= limit:
            break
    return out


def hashes(path):
    md5, sha = hashlib.md5(), hashlib.sha256()
    with open(path, "rb") as fh:
        for blk in iter(lambda: fh.read(1 << 20), b""):
            md5.update(blk)
            sha.update(blk)
    return md5.hexdigest(), sha.hexdigest()


MAGICS = [
    (b"Nostromoi", "HxStore database (Nostromoi)"), (b"Nostromo", "HxCore replication state (Nostromo)"),
    (b"bplist00", "binary property list"), (b"<?xml", "XML"), (b"\x1f\x8b", "gzip"),
    (b"SQLite format 3\x00", "SQLite database"), (b"\x89PNG", "PNG image"), (b"\xff\xd8\xff", "JPEG image"),
    (b"GIF8", "GIF image"), (b"%PDF", "PDF document"), (b"PK\x03\x04", "ZIP / OOXML document"),
    (b"BEGIN:VCALENDAR", "iCalendar"), (b"\xd0\x0d\x00\x00", "Outlook 2016 record (olk15)"),
    (b"\xef\xbe\xad\xde", "lock table (DEADBEEF)"), (b"XENO", "counter file (XENO)"),
    (b"\x00\x00\x00\x01Bud1", "Finder .DS_Store"), (b"Bud2", "buddy-allocator index (Bud2)"),
    (b"<html", "HTML"), (b"<!DOCTYPE", "HTML"), (b"<HTML", "HTML"), (b"<\x00", "UTF-16 XML/HTML"),
    (b"\xff\xfe", "UTF-16 text"),
]


def detect(head, path):
    for m, name in MAGICS:
        if head.startswith(m):
            return name
    if path.endswith(".hfl") and head[:4] == b"\x08\x00\x00\x00":
        return "HxCore trace log (.hfl)"
    low = head[:64].lower()
    if b"<html" in low or b"<!doctype html" in low:
        return "HTML"
    if b"received:" in low or b"from:" in low or b"mime-version" in low:
        return "e-mail message (RFC 822)"
    if head and all(32 <= c < 127 or c in (9, 10, 13) for c in head[:256]):
        return "text"
    return "binary"


def categorize(rel):
    p = rel.replace("\\", "/")
    if p.endswith(".hfl"):
        return "HxCore trace log"
    if p.endswith(".hxd"):
        return "HxCore store"
    if p.endswith(".bhxd"):
        return "Accounts backup"
    if p.startswith("Osa/OsaPinnedLogs"):
        return "Osa pinned logs"
    if p.startswith("Osa/"):
        return "Osa API logs"
    if "/Attachments/" in p:
        return "Attachment cache"
    if "/EFMData/" in p:
        return "Message bodies (EFMData)"
    if "/Photos/" in p:
        return "Contact photos"
    if "/AadLogos/" in p:
        return "Tenant logos"
    if p.startswith("Files/"):
        return "Files (other)"
    if ".olk15" in p:
        return "Legacy olk15 records"
    if p.startswith("Data/") and ".sqlite" in p:
        return "Legacy SQLite"
    if p.startswith("Data/"):
        return "Legacy data (other)"
    if p.startswith("Omc/"):
        return "Outlook.com connector"
    if p.startswith("rss/"):
        return "Replication state"
    if p.startswith("TelemetryStorage/"):
        return "Telemetry"
    if p.endswith(".plist") or p.endswith(".dat"):
        return "Preferences / config"
    return "Other"


# =========================================================================== database
SCHEMA = """
CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT);
CREATE TABLE files (id INTEGER PRIMARY KEY, path TEXT, category TEXT, size INTEGER,
  mtime_utc TEXT, birthtime_utc TEXT, mode TEXT, md5 TEXT, sha256 TEXT, magic_hex TEXT,
  detected_type TEXT, parser TEXT, parse_status TEXT, notes TEXT);
CREATE TABLE timeline (time_utc TEXT, source TEXT, artifact TEXT, kind TEXT, description TEXT, ref TEXT);
CREATE TABLE findings (severity TEXT, area TEXT, finding TEXT, detail TEXT);
CREATE TABLE correlations (kind TEXT, left_ref TEXT, right_ref TEXT, status TEXT, detail TEXT);

CREATE TABLE hfl_files (file TEXT PRIMARY KEY, size INTEGER, sha256 TEXT, office_build TEXT,
  created_utc TEXT, monotonic_zero_utc TEXT, first_utc TEXT, last_utc TEXT, chunks INTEGER,
  gaps INTEGER, gap_bytes INTEGER, records INTEGER, errors INTEGER, warnings INTEGER,
  threads INTEGER, activities INTEGER, events INTEGER, mode TEXT, header_json TEXT, settings_json TEXT);
CREATE TABLE hfl_records (file TEXT, chunk INTEGER, off INTEGER, time_utc TEXT, stamp_ns INTEGER,
  thread INTEGER, activity TEXT, ekey TEXT, level INTEGER, area INTEGER, sig TEXT, summary TEXT);
CREATE TABLE hfl_events (file TEXT, ekey TEXT, label TEXT, count INTEGER, levels TEXT,
  first_utc TEXT, last_utc TEXT, signature TEXT, example TEXT);
CREATE TABLE hfl_hourly (file TEXT, hour_utc TEXT, level INTEGER, n INTEGER);
CREATE TABLE hfl_object_activity (file TEXT, object_id INTEGER, mentions INTEGER, first_utc TEXT,
  last_utc TEXT, events TEXT, log_types TEXT, first_ref TEXT, last_ref TEXT);

CREATE TABLE store_info (store TEXT PRIMARY KEY, size INTEGER, sha256 TEXT, pages_json TEXT,
  primary_store_id TEXT, secondary_store_id TEXT, records INTEGER, distinct_ids INTEGER, note TEXT);
CREATE TABLE store_records (store TEXT, record_id INTEGER, version INTEGER, versions INTEGER,
  page INTEGER, file_offset INTEGER, size_compressed INTEGER, size_decompressed INTEGER,
  raw_format TEXT, format_name TEXT, object_type INTEGER, type_name TEXT, self_id INTEGER,
  is_email INTEGER, sender_email TEXT, sender_name TEXT, subject TEXT, display_time_utc TEXT,
  timestamps TEXT, emails TEXT, message_ids TEXT, folder TEXT, n_strings INTEGER,
  payload_sha256 TEXT, payload BLOB, raw BLOB);
CREATE TABLE store_strings (store TEXT, record_id INTEGER, version INTEGER, idx INTEGER, text TEXT);
CREATE TABLE store_folders (store TEXT, record_id INTEGER, name TEXT);
CREATE TABLE store_attachments (store TEXT, record_id INTEGER, versions TEXT, display_name TEXT,
  profile_path TEXT, rel_path TEXT, exists_on_disk INTEGER, size INTEGER, sha256 TEXT, sender_email TEXT);
CREATE TABLE store_bodies (store TEXT, record_id INTEGER, source TEXT, body_record_id INTEGER,
  efm_path TEXT, text TEXT, html TEXT);
CREATE TABLE account_backup (store TEXT, record_hash TEXT, file_offset INTEGER, section TEXT,
  prop TEXT, type INTEGER, type_name TEXT, value TEXT);

CREATE TABLE osa_logs (id INTEGER PRIMARY KEY, file TEXT, folder TEXT, pinned INTEGER,
  session_start_utc TEXT, seq INTEGER, account TEXT, channel TEXT, command TEXT, request_id TEXT,
  kind TEXT, root TEXT, time_utc TEXT, send_time TEXT, receive_time TEXT, start_ts TEXT, end_ts TEXT,
  duration_ms REAL, status TEXT, size INTEGER, backend TEXT, frontend TEXT, server_build TEXT,
  tag TEXT, app_state TEXT, app_version TEXT, client_version TEXT, device_os TEXT, device_type TEXT,
  device_id TEXT, socket_id TEXT, request_guid TEXT, client_session_id TEXT, user_agent TEXT,
  network_protocol TEXT, pii_values INTEGER, xml TEXT);
CREATE TABLE osa_fields (log_id INTEGER, path TEXT, value TEXT);

CREATE TABLE legacy_tables (db TEXT, tbl TEXT, rows INTEGER, copied_as TEXT, note TEXT);
CREATE TABLE wal_journals (db TEXT, wal_size INTEGER, page_size INTEGER, frames INTEGER,
  checkpoint_seq INTEGER, salt TEXT, note TEXT);
CREATE TABLE olk15_records (path TEXT, kind TEXT, record_type TEXT, uuid TEXT, folder_no INTEGER,
  name TEXT, modified_utc TEXT, n_props INTEGER, size INTEGER);
CREATE TABLE olk15_props (path TEXT, prop_id TEXT, prop_type TEXT, size INTEGER, value TEXT);
CREATE TABLE plist_values (file TEXT, keypath TEXT, type TEXT, value TEXT);
CREATE TABLE config_files (path TEXT, format TEXT, content TEXT);
CREATE TABLE attachment_files (path TEXT, filename TEXT, ref_no INTEGER, ext TEXT, size INTEGER,
  sha256 TEXT, detected_type TEXT, store_record_ids TEXT, store_names TEXT, senders TEXT);
CREATE TABLE efm_files (path TEXT, number INTEGER, size INTEGER, sha256 TEXT, format TEXT,
  title TEXT, text_preview TEXT, store_record_ids TEXT);
CREATE TABLE photos (path TEXT, kind TEXT, guid TEXT, time_utc TEXT, width INTEGER, height INTEGER,
  size INTEGER, sha256 TEXT);
CREATE TABLE binary_artifacts (path TEXT, parser TEXT, fields TEXT, strings TEXT);
"""

VIEWS = """
CREATE VIEW IF NOT EXISTS store_mail AS
  SELECT store, record_id, max(version) AS latest_version, versions, sender_email, sender_name,
         subject, display_time_utc, folder, raw_format FROM store_records
  WHERE is_email = 1 GROUP BY store, record_id;
CREATE VIEW IF NOT EXISTS hfl_store_objects AS
  SELECT a.file, a.object_id, a.mentions, a.first_utc, a.last_utc, a.events,
         s.type_name, s.subject, s.sender_email, s.folder, s.versions,
         CASE WHEN s.record_id IS NULL THEN 0 ELSE 1 END AS in_store
  FROM hfl_object_activity a LEFT JOIN
       (SELECT record_id, type_name, subject, sender_email, folder, versions
          FROM store_records WHERE store = 'HxStore.hxd' GROUP BY record_id) s
       ON s.record_id = a.object_id;
CREATE VIEW IF NOT EXISTS osa_commands AS
  SELECT channel, command, count(*) AS n, sum(status IS NOT NULL AND status NOT IN ('Success','Ok','OK','200','201','202','204','304')) AS not_success,
         min(time_utc) AS first_utc, max(time_utc) AS last_utc
  FROM osa_logs GROUP BY channel, command;
"""


class DB:
    def __init__(self, path):
        if os.path.exists(path):
            os.remove(path)
        self.c = sqlite3.connect(path)
        self.c.execute("PRAGMA journal_mode=OFF")
        self.c.execute("PRAGMA synchronous=OFF")
        self.c.executescript(SCHEMA)
        self.c.executescript(VIEWS)
        self.buf = collections.defaultdict(list)

    def add(self, table, row):
        b = self.buf[table]
        b.append(row)
        if len(b) >= 5000:
            self.flush(table)

    def flush(self, table=None):
        for t in ([table] if table else list(self.buf)):
            rows = self.buf[t]
            if rows:
                self.c.executemany("INSERT INTO %s VALUES (%s)" % (t, ",".join("?" * len(rows[0]))), rows)
                rows.clear()

    def meta(self, k, v):
        self.c.execute("INSERT OR REPLACE INTO meta VALUES (?,?)", (k, v if isinstance(v, str) else json.dumps(v)))

    def tl(self, t, source, artifact, kind, desc, ref=None):
        if t:
            self.add("timeline", (t, source, artifact, kind, (desc or "")[:500], ref))

    def finding(self, sev, area, text, detail=""):
        self.add("findings", (sev, area, text, detail))

    def corr(self, kind, left, right, status, detail=""):
        self.add("correlations", (kind, left, right, status, detail))

    def close(self):
        self.flush()
        self.c.execute("CREATE INDEX ix_tl ON timeline(time_utc)")
        self.c.execute("CREATE INDEX ix_hflrec ON hfl_records(file, level)")
        self.c.execute("CREATE INDEX ix_store ON store_records(store, record_id)")
        self.c.execute("CREATE INDEX ix_osa ON osa_logs(command)")
        self.c.execute("CREATE INDEX ix_osaf ON osa_fields(log_id)")
        self.c.execute("CREATE INDEX ix_hflobj ON hfl_object_activity(object_id)")
        self.c.commit()


def sg(v):
    """unsigned 64-bit -> signed for SQLite"""
    return v - (1 << 64) if v is not None and v >= (1 << 63) else v


# =========================================================================== inventory
def inventory(root, db):
    files = []
    for dp, dns, fns in os.walk(root):
        dns.sort()
        for fn in sorted(fns):
            full = os.path.join(dp, fn)
            rel = os.path.relpath(full, root).replace(os.sep, "/")
            try:
                st = os.lstat(full)
            except OSError:
                continue
            with open(full, "rb") as fh:
                head = fh.read(64)
            md5, sha = hashes(full)
            birth = getattr(st, "st_birthtime", None)
            files.append({"path": rel, "full": full, "size": st.st_size, "head": head,
                          "category": categorize(rel), "type": detect(head, rel),
                          "mtime": from_unix(st.st_mtime), "birth": from_unix(birth) if birth else None,
                          "mode": oct(st.st_mode & 0o7777), "md5": md5, "sha256": sha})
    # copies made without -p get the copy time: warn so mtimes are not read as evidence
    mt = sorted(f["mtime"] for f in files if f["mtime"])
    if mt:
        lo, hi = mt[0], mt[-1]
        span = (dt.datetime.fromisoformat(hi) - dt.datetime.fromisoformat(lo)).total_seconds()
        db.meta("fs_mtime_range", [lo, hi])
        if span < 3600 and len(mt) > 50:
            db.finding("warning", "Acquisition",
                       "All %d file modification times fall within %.0f minutes (%s .. %s UTC)." % (len(mt), span / 60, lo, hi),
                       "The profile was copied without preserving timestamps, so file-system times show the copy, "
                       "not original activity. Only timestamps inside the artifacts are used in the timeline.")
    return files


# =========================================================================== HFL trace logs
def parse_hfl(path, rel, db, mode, store_ids):
    d = open(path, "rb").read()
    hdr = hp.parse_header(d)
    boot = hdr["boot_epoch_unix_ns"]
    to_utc = lambda s: hp.fmt_unix_ns(boot + s)[:23]
    known = set()
    oid_re = re.compile(rb"\x08\x00{8}([\x01-\xff][\x00-\xff]{2}[\x00-\xff]\x00\x00\x00\x00)", re.S)
    chunks = []
    for kind, pos, length in hp.iter_chunks(d, hdr["data_start"]):
        dec = hp.lz4_block(d[pos + hp.CHUNK_HDR:pos + length]) if kind == "chunk" else None
        if dec:
            for m in oid_re.finditer(dec):
                known.add(int.from_bytes(m.group(1), "little"))
        chunks.append((kind, pos, length, dec))
    known.discard(0)
    known.update(store_ids)
    cat = hp.Catalog()
    tracker = hp.ObjectTracker()
    levels, threads, hourly = collections.Counter(), set(), collections.Counter()
    activities = set()
    ci = nrec = gaps = gap_bytes = 0
    smin = smax = None
    full = mode == "records"
    t0 = time.time()
    for kind, pos, length, dec in chunks:
        if kind == "gap":
            if length:
                gaps += 1
                gap_bytes += length
            continue
        if dec is None:
            ci += 1
            continue
        it = hp.iter_records(dec)
        while True:
            try:
                off, h = next(it)
            except StopIteration:
                break
            act_b, stamp, thread, argc, ln, aoff, event, level, area = h
            raw_args, _aend, _err = hp.decode_args(dec, off + aoff, off + ln, argc)
            nrec += 1
            levels[level] += 1
            threads.add(thread)
            smin = stamp if smin is None else min(smin, stamp)
            smax = stamp if smax is None else max(smax, stamp)
            activity = None if act_b == b"\x00" * 16 else str(uuid.UUID(bytes=act_b))
            if activity:
                activities.add(activity)
            ekey = "%d.%d" % (area, event)
            r = {"ekey": ekey, "event": event, "level": level, "area": area, "thread": thread,
                 "stamp": stamp, "sig": hp.arg_signature(raw_args), "activity": activity}
            ev = cat.ev.get(ekey)
            if full or level <= 3 or ev is None or len(ev["examples"]) < 3:
                iargs, render = hp.interpret(raw_args, known)
            else:
                iargs, render = None, None
            cat.add(r, raw_args, render or "")
            tu = to_utc(stamp)
            hourly[(tu[:13] + ":00", level)] += 1
            if iargs is not None:
                tracker.add(iargs, stamp, ekey, "%d:0x%x" % (ci, off))
            if full or level <= 3:
                db.add("hfl_records", (rel, ci, off, tu, stamp, thread, activity, ekey, level, area, r["sig"], render))
            if level <= 2:
                db.tl(tu, "hfl", rel, "trace error", "%s %s" % (ekey, (render or "")[:300]), "%d:0x%x" % (ci, off))
            if nrec % 100000 == 0:
                sys.stderr.write("    %s: %d records, %.0fs\r" % (rel, nrec, time.time() - t0))
        ci += 1
    sys.stderr.write("\n")
    labels = cat.labels()
    for ekey in sorted(cat.ev, key=hp.ekey_sort):
        e = cat.ev[ekey]
        db.add("hfl_events", (rel, ekey, labels.get(ekey), e["count"],
                              json.dumps({hp.LEVELS.get(k, k): v for k, v in e["levels"].items()}),
                              to_utc(e["first"]), to_utc(e["last"]), e["sigs"].most_common(1)[0][0],
                              e["examples"][0] if e["examples"] else None))
    for (hr, lv), n in sorted(hourly.items()):
        db.add("hfl_hourly", (rel, hr, lv, n))
    for oid, e in tracker.o.items():
        db.add("hfl_object_activity", (rel, sg(oid), e[0], to_utc(e[1]), to_utc(e[2]),
                                       json.dumps(dict(e[3].most_common(8))), json.dumps(dict(e[4])), e[5], e[6]))
    first, last = (to_utc(smin), to_utc(smax)) if smin is not None else (None, None)
    settings = hdr.pop("settings", {})
    db.add("hfl_files", (rel, len(d), hashlib.sha256(d).hexdigest(), hdr.get("office_build"),
                         hdr.get("created_utc", "")[:23], (hdr.get("monotonic_zero_utc") or "")[:23], first, last,
                         ci, gaps, gap_bytes, nrec, levels.get(2, 0) + levels.get(1, 0), levels.get(3, 0),
                         len(threads), len(activities), len(cat.ev), mode,
                         json.dumps(hdr, default=str), json.dumps(settings)))
    db.tl(hdr.get("created_utc", "")[:23], "hfl", rel, "trace log created", "Office build %s" % hdr.get("office_build"))
    db.tl(first, "hfl", rel, "first trace record", "%d records in file" % nrec)
    db.tl(last, "hfl", rel, "last trace record", "")
    return {"records": nrec, "first": first, "last": last, "errors": levels.get(2, 0)}


# =========================================================================== HxStore
def store_parse(path, rel, db, profile_root, efm_index):
    """Decode every record version of an HxStore.hxd with the hxstore-decode library."""
    raw_file = open(path, "rb").read()
    hx = HxStoreFile(path)
    recs = []
    for rec in hx.iter_data_records():
        sh = rec.slot_header
        rid, dec = decompress_record(rec.raw_data, sh.size_b)
        rawfmt = struct.unpack_from("<I", rec.raw_data, 8)[0] if len(rec.raw_data) >= 12 else 0
        recs.append((rid, sh, rawfmt, dec, rec.raw_data))
    versions = collections.Counter(r[0] for r in recs)
    try:
        fidx = FolderIndex(hx)
        folders = fidx.folders
    except Exception:
        fidx, folders = None, {}
    for fid, name in sorted(folders.items()):
        db.add("store_folders", (rel, fid, name))
    vno = collections.Counter()
    by_msgid = collections.defaultdict(set)
    html_rec, efm_rec, info = {}, collections.defaultdict(set), {}
    att = {}
    for rid, sh, rawfmt, dec, raw in recs:
        vno[rid] += 1
        utf16 = extract_utf16le_strings(dec)
        emails = list(extract_emails(dec))
        for s in utf16:
            for m in EMAIL_RE.finditer(s):
                if m.group().lower() not in {e.lower() for e in emails}:
                    emails.append(m.group())
        is_email = "IPM.Note" in utf16
        try:
            se, sn, subj = extract_email_fields(utf16, rawfmt)
        except Exception:
            se, sn, subj = "", "", ""
        try:
            disp = extract_display_time(dec, utf16)
        except Exception:
            disp = None
        try:
            tss = [iso(t) for t in extract_timestamps(dec)][:20]
        except Exception:
            tss = []
        otype = self_id = None
        if len(dec) >= 52 and struct.unpack_from("<I", dec, 0)[0] == 0:
            self_id = struct.unpack_from("<I", dec, 20)[0]
            otype = struct.unpack_from("<H", dec, 44)[0]
        fmt = "0x%X" % rawfmt
        msgids = [s for s in utf16 if s.startswith("<") and s.endswith(">") and "@" in s]
        folder = None
        if fidx is not None:
            try:
                folder = fidx.get_folder(dec)
            except Exception:
                folder = None
        disp_s = iso(disp.replace(tzinfo=None)) if disp else None
        db.add("store_records", (rel, rid, vno[rid], versions[rid], sh.file_offset // 4096, sh.file_offset,
                                 sh.size_a, len(dec), fmt, hp.HX_FORMATS.get(fmt), otype, hp.HX_TYPES.get(otype),
                                 self_id, int(is_email), se or (emails[0] if is_email and emails else None), sn or None,
                                 subj or None, disp_s, json.dumps(tss), json.dumps(emails[:30]),
                                 json.dumps(msgids[:10]), folder, len(utf16),
                                 hashlib.sha256(dec).hexdigest(), dec, raw))
        for i, s in enumerate(utf16):
            db.add("store_strings", (rel, rid, vno[rid], i, s))
        for s in msgids:
            by_msgid[s].add(rid)
        if b"<html" in dec or b"<HTML" in dec:
            html_rec[rid] = dec
        for s in utf16:
            m = re.search(r"EFMData/(\d+)\.dat", s)
            if m:
                efm_rec[rid].add(int(m.group(1)))
        info[rid] = (is_email, utf16, rawfmt, msgids, se, subj, disp_s)
        if is_email and disp_s:
            db.tl(disp_s, "store", rel, "e-mail time", "%s | %s" % (se or "?", subj or ""), "record %d v%d" % (rid, vno[rid]))
        # attachment references: "~/Files/S0/<n>/Attachments/..." with the display name before it
        for i, s in enumerate(utf16):
            if s.startswith("~/Files/") and "/Attachments/" in s:
                relp = s[2:]
                key = (rid, relp)
                if key not in att:
                    full = os.path.join(profile_root, relp)
                    ex = os.path.isfile(full)
                    att[key] = [utf16[i - 1] if i else os.path.basename(relp), s, relp, ex,
                                os.path.getsize(full) if ex else None, hashes(full)[1] if ex else None,
                                se if is_email else None, set()]
                att[key][7].add(vno[rid])
    for (rid, relp), a in att.items():
        db.add("store_attachments", (rel, rid, ",".join(map(str, sorted(a[7]))), a[0], a[1], a[2], int(a[3]), a[4], a[5], a[6]))
    # message bodies: inline HTML, EFMData file, sibling record (same Message-ID), preview
    nbody = collections.Counter()
    for rid, (is_email, utf16, rawfmt, msgids, se, subj, disp_s) in info.items():
        if not is_email:
            continue
        sib = set()
        for m in msgids:
            sib |= by_msgid[m]
        src = body_rid = efm_path = h = t = None
        if rid in html_rec:
            h = extract_html_body(html_rec[rid])
            src, body_rid = "inline", rid
        if not h:
            for r2 in [rid] + sorted(sib - {rid}):
                for n in sorted(efm_rec.get(r2, ())):
                    p = efm_index.get(n)
                    if p:
                        h = read_efm(os.path.join(profile_root, p))
                        if h:
                            src, body_rid, efm_path = "efmdata", r2, p
                            break
                if h:
                    break
        if not h:
            for r2 in sorted(sib - {rid}):
                if r2 in html_rec:
                    h = extract_html_body(html_rec[r2])
                    if h:
                        src, body_rid = "sibling", r2
                        break
        if h:
            t = html_to_text(h)
        else:
            t = extract_body_preview(utf16, rawfmt) or None
            src = "preview" if t else None
            body_rid = rid if t else None
        if src:
            nbody[src] += 1
            db.add("store_bodies", (rel, rid, src, body_rid, efm_path, t, h))
    st = hx.stats()
    db.add("store_info", (rel, len(raw_file), hashlib.sha256(raw_file).hexdigest(), json.dumps(st),
                          hx.primary_store_id.hex(), hx.secondary_store_id.hex(), len(recs), len(versions),
                          "hxstore-decode library; bodies: %s" % dict(nbody)))
    return {"records": len(recs), "ids": set(versions), "emails": sum(1 for v in info.values() if v[0]),
            "attachments": len(att), "bodies": dict(nbody), "efm_refs": efm_rec, "att": att, "folders": len(folders)}


def read_efm(path):
    try:
        data = open(path, "rb").read()
        if data[:2] == b"\x1f\x8b":
            data = gzip.decompress(data)
        s = data.decode("utf-8", "replace")
        return s if "<html" in s[:2000].lower() else None
    except OSError:
        return None


ACCT_TYPES = {1: "string", 2: "u32", 4: "u32", 7: "bool", 8: "u64", 9: "empty", 3: "i32", 5: "u16", 6: "u8"}


def parse_account_backup(path, rel, db):
    """AccountsBackup.bhxd: Nostromoi container whose 512-byte slots hold *uncompressed*
    records of key/value settings. Slot header: 8-byte hash, 8-byte store id, u32 section-name
    byte length, u32 size, u32 size, u32 0. Payload: UTF-16 section name, u64, u32 count, then
    per entry u32 name_bytes, UTF-16 name (NUL-terminated), u8 type, u32 value_len, value."""
    d = open(path, "rb").read()
    sids = collections.Counter(d[o + 8:o + 16] for o in range(4096, len(d), 512)
                               if d[o + 8:o + 16] != b"\x00" * 8 and 0 < struct.unpack_from("<I", d, o + 16)[0] < 256)
    if not sids:
        return 0
    sid = sids.most_common(1)[0][0]
    n = 0
    o = 4096
    while o + 32 <= len(d):
        if d[o + 8:o + 16] == sid:
            typ, sa, sb = struct.unpack_from("<III", d, o + 16)
            if 0 < sa <= len(d) - o - 32 and 0 < typ < 256:
                p = d[o + 32:o + 32 + sa]
                if sa != sb:
                    p = hp.lz4_block(p[8:]) or p
                n += decode_kv(p, rel, d[o:o + 8].hex(), o, db, typ)
                o += ((32 + sa + 511) // 512) * 512
                continue
        o += 512
    return n


def decode_kv(p, rel, rhash, off, db, name_len):
    """name_len = slot-header u32 at +16: byte length of the UTF-16 section name"""
    if name_len <= 0 or name_len + 12 > len(p):
        return 0
    section = p[:name_len].decode("utf-16-le", "replace")
    i = name_len + 8
    count = struct.unpack_from("<I", p, i)[0]
    i += 4
    n = 0
    while n < count and i + 4 <= len(p):
        nl = struct.unpack_from("<I", p, i)[0]
        if nl == 0 or nl > 512 or i + 4 + nl + 5 > len(p):
            break
        name = p[i + 4:i + 4 + nl].decode("utf-16-le", "replace").rstrip("\x00")
        i += 4 + nl
        typ = p[i]
        vl = struct.unpack_from("<I", p, i + 1)[0]
        i += 5
        if vl > len(p) - i:
            break
        v = p[i:i + vl]
        i += vl
        if typ == 1:
            val = v.decode("utf-16-le", "replace").rstrip("\x00")
        elif vl == 1:
            val = str(v[0])
        elif vl in (2, 4, 8):
            val = str(int.from_bytes(v, "little"))
            iv = int(val)
            if vl == 8 and from_ticks(iv):
                val += " (%s UTC)" % from_ticks(iv)
        else:
            val = v.hex()
        db.add("account_backup", (rel, rhash, off, section, name, typ, ACCT_TYPES.get(typ, "type %d" % typ), val))
        n += 1
    return n


# =========================================================================== Osa logs
OK_STATUS = ("Success", "Ok", "OK", "200", "201", "202", "204", "304")
OK_SQL = "(%s)" % ",".join("'%s'" % x for x in OK_STATUS)
OSA_NAME = re.compile(r"osa\{([\d-]+)\}_(\d+)_([^_]+)_(.+)\.xmlgz$")
OSA_FOLDER = re.compile(r"_([0-9A-F]{8})$")
OSA_KEYS = {"AccountId": "account", "LogTime": "log", "SendTime": "send", "ReceiveTime": "receive",
            "StartTimeStamp": "start", "EndTimeStamp": "end", "StatusCode": "status", "Size": "size",
            "BackEndServer": "backend", "FrontEndServer": "frontend", "ServerBuild": "build", "Tag": "tag",
            "AppState": "appstate", "AppVersion": "appver", "ClientVersion": "clientver", "DeviceOS": "os",
            "DeviceType": "devtype", "DeviceId": "devid", "SocketId": "socket", "RequestGuid": "rguid",
            "ClientSessionId": "csid", "NetworkProtocol": "proto", "CommandId": "cmd", "ChannelId": "chan",
            "RequestId": "rid"}


def osa_time(s):
    if not s:
        return None
    return s.replace("T", " ").rstrip("Z")[:23]


def parse_osa(files, db):
    n = 0
    sessions = collections.Counter()
    for f in files:
        rel = f["path"]
        m = OSA_NAME.search(os.path.basename(rel))
        folder = rel.split("/")[1] if rel.count("/") >= 2 else ""
        pinned = int("OsaPinnedLogs" in rel)
        fm = OSA_FOLDER.search(folder)
        sess = from_unix(int(fm.group(1), 16)) if fm else None
        seq = acct = chan = cmd = reqid = kind = None
        if m:
            seq, acct, rest = int(m.group(2)), m.group(3), m.group(4)
            parts = rest.split(".")
            chan, cmd = parts[0], (parts[1] if len(parts) > 1 else "")
            if len(parts) > 2 and parts[2].isdigit():
                reqid, kind = parts[2], ".".join(parts[3:])
            else:
                kind = ".".join(parts[2:])
            if sess is None:
                try:
                    sess = iso(dt.datetime.strptime(m.group(1), "%Y-%m-%d-%H-%M-%S"))
                except ValueError:
                    pass
        try:
            xml = gzip.decompress(open(f["full"], "rb").read()).decode("utf-8", "replace")
        except Exception as ex:
            db.add("binary_artifacts", (rel, "osa (unreadable)", json.dumps({"error": str(ex)}), "[]"))
            continue
        v, leaves, root = {}, [], None
        try:
            el = ET.fromstring(xml)
            root = el.tag

            def walk(e, path):
                kids = list(e)
                if not kids:
                    t = (e.text or "").strip()
                    if t:
                        leaves.append((path, t))
                for k in kids:
                    walk(k, path + "/" + k.tag)
            walk(el, el.tag)
            for c in el:
                if c.tag in OSA_KEYS and (c.text or "").strip():
                    v[OSA_KEYS[c.tag]] = c.text.strip()
                elif c.tag == "Headers":
                    ua = re.search(r"User-Agent: ([^\n]+)", c.text or "")
                    if ua:
                        v["ua"] = ua.group(1).strip()
        except ET.ParseError:
            root = "(malformed)"
            for k, key in OSA_KEYS.items():
                mm = re.search(r"<%s>([^<]*)</%s>" % (k, k), xml)
                if mm:
                    v[key] = mm.group(1)
        dur = None
        try:
            if v.get("start") and v.get("end"):
                a = dt.datetime.fromisoformat(osa_time(v["start"]))
                b = dt.datetime.fromisoformat(osa_time(v["end"]))
                dur = (b - a).total_seconds() * 1000
        except ValueError:
            pass
        t = osa_time(v.get("log") or v.get("send") or v.get("receive"))
        n += 1
        sessions[folder] += 1
        db.add("osa_logs", (n, rel, folder, pinned, sess, seq, v.get("account", acct), v.get("chan", chan),
                            v.get("cmd", cmd), v.get("rid", reqid), kind, root, t, osa_time(v.get("send")),
                            osa_time(v.get("receive")), osa_time(v.get("start")), osa_time(v.get("end")), dur,
                            v.get("status"), int(v["size"]) if v.get("size", "").isdigit() else None,
                            v.get("backend"), v.get("frontend"), v.get("build"), v.get("tag"), v.get("appstate"),
                            v.get("appver"), v.get("clientver"), v.get("os"), v.get("devtype"), v.get("devid"),
                            v.get("socket"), v.get("rguid"), v.get("csid"), v.get("ua"), v.get("proto"),
                            xml.count("pii:"), xml))
        for p, val in leaves:
            if not p.endswith("/Headers"):
                db.add("osa_fields", (n, p, val[:2000]))
        if not pinned:
            label = "%s.%s %s" % (chan or "", cmd or "", kind or "")
            st = v.get("status")
            if chan == "app" or (st and st not in OK_STATUS) or cmd in ("Initialize", "GetAttachment", "SendMessage",
                                                                     "SendMail", "DeleteItem", "MoveItem"):
                db.tl(t, "osa", rel, "api " + (chan or ""), label.strip() + (" [%s]" % st if st else ""), "osa_logs.id=%d" % n)
        if n % 2000 == 0:
            sys.stderr.write("    osa: %d files\r" % n)
    sys.stderr.write("\n")
    for folder, cnt in sessions.items():
        fm = OSA_FOLDER.search(folder)
        if fm:
            db.tl(from_unix(int(fm.group(1), 16)), "osa", "Osa/" + folder, "api log session start", "%d log files" % cnt)
    return n


# =========================================================================== legacy SQLite
def parse_legacy_sqlite(root, files, db, tmpdir):
    out = []
    for f in files:
        if not f["path"].endswith(".sqlite"):
            continue
        base = os.path.basename(f["path"])[:-7]
        dst = os.path.join(tmpdir, os.path.basename(f["path"]))
        shutil.copy2(f["full"], dst)
        for ext in ("-wal", "-shm"):
            if os.path.exists(f["full"] + ext):
                shutil.copy2(f["full"] + ext, dst + ext)
        wal = f["full"] + "-wal"
        if os.path.exists(wal) and os.path.getsize(wal) >= 32:
            w = open(wal, "rb").read()
            magic, ver, psz, ckpt = struct.unpack(">IIII", w[:16])
            frames = (len(w) - 32) // (psz + 24) if psz else 0
            db.add("wal_journals", (f["path"], len(w), psz, frames, ckpt, w[16:24].hex(),
                                  "uncheckpointed WAL frames may hold older or newer page versions"))
        try:
            src = sqlite3.connect(dst)
            tbls = src.execute("SELECT name, sql FROM sqlite_master WHERE type='table'").fetchall()
        except sqlite3.DatabaseError as ex:
            db.add("legacy_tables", (f["path"], None, None, None, "unreadable: %s" % ex))
            continue
        for name, sql in tbls:
            if sql and "VIRTUAL" in sql.upper():
                db.add("legacy_tables", (f["path"], name, None, None, "virtual table (module not available)"))
                continue
            try:
                cur = src.execute('SELECT * FROM "%s"' % name)
                cols = [c[0] for c in cur.description]
                rows = cur.fetchall()
            except sqlite3.DatabaseError as ex:
                db.add("legacy_tables", (f["path"], name, None, None, str(ex)))
                continue
            tname = "legacy_%s_%s" % (re.sub(r"\W", "_", base), re.sub(r"\W", "_", name))
            if rows:
                db.c.execute('CREATE TABLE "%s" (%s)' % (tname, ", ".join('"%s"' % c for c in cols)))
                db.c.executemany('INSERT INTO "%s" VALUES (%s)' % (tname, ",".join("?" * len(cols))), rows)
            db.add("legacy_tables", (f["path"], name, len(rows), tname if rows else None, ""))
            out.append((f["path"], name, len(rows)))
        src.close()
    return out


# =========================================================================== olk15 records
OLK_TYPES = {0x02: "i16", 0x03: "i32", 0x08: "binary", 0x0b: "bool", 0x0d: "object", 0x14: "i64",
             0x1f: "utf16", 0x20: "prop-index", 0x48: "guid", 0x4d: "date"}


def parse_olk15(f, db):
    d = open(f["full"], "rb").read()
    if len(d) < 0x34 or d[:4] != b"\xd0\x0d\x00\x00":
        return False
    magic = d[0x20:0x24].decode("latin-1")[::-1]
    n = struct.unpack_from("<I", d, 0x28)[0]
    pos, data = 0x34, 0x34 + n * 8
    name = modified = None
    props = 0
    for _ in range(n):
        if pos + 8 > len(d):
            break
        pid, _fl, typ, sz = struct.unpack_from("<HBBI", d, pos)
        pos += 8
        v = d[data:data + sz]
        data += sz
        tn = OLK_TYPES.get(typ, "0x%02x" % typ)
        if typ == 0x1f:
            val = v.decode("utf-16-le", "replace")
            if name is None and val:
                name = val
        elif typ in (0x02, 0x03, 0x0b, 0x14) and sz in (1, 2, 4, 8):
            val = str(int.from_bytes(v, "little", signed=True))
        elif typ == 0x48 and sz == 16:
            val = str(uuid.UUID(bytes_le=v))
        elif typ == 0x4d and sz == 8:
            val = from_cocoa(struct.unpack("<d", v)[0])
            if pid == 0x0004:
                modified = val
        else:
            val = v.hex()
        db.add("olk15_props", (f["path"], "0x%04X" % pid, tn, sz, val))
        props += 1
    parts = f["path"].split("/")
    kind = parts[1] if len(parts) > 2 else ""
    fno = int(parts[2]) if len(parts) > 3 and parts[2].isdigit() else None
    db.add("olk15_records", (f["path"], kind, magic, os.path.basename(f["path"]).split(".")[0], fno, name,
                             modified, props, len(d)))
    db.tl(modified, "olk15", f["path"], "legacy record date", "%s %s" % (kind, name or ""))
    return True


# =========================================================================== plists
def unarchive(top):
    """Minimal NSKeyedArchiver decoder -> plain Python objects."""
    objs = top.get("$objects", [])
    seen = {}

    def res(x, depth=0):
        if isinstance(x, plistlib.UID):
            i = x.data
            if i in seen:
                return seen[i]
            o = objs[i] if i < len(objs) else None
            if o == "$null":
                return None
            seen[i] = "<cycle>"
            r = res(o, depth + 1)
            seen[i] = r
            return r
        if isinstance(x, dict):
            if "NS.keys" in x and "NS.objects" in x:
                return {str(res(k)): res(v) for k, v in zip(x["NS.keys"], x["NS.objects"])}
            if "NS.objects" in x:
                return [res(v) for v in x["NS.objects"]]
            if "NS.string" in x:
                return x["NS.string"]
            if "NS.time" in x:
                return from_cocoa(x["NS.time"])
            if "NS.bytes" in x:
                return x["NS.bytes"]
            return {k: res(v) for k, v in x.items() if k != "$class"}
        if isinstance(x, list):
            return [res(v) for v in x]
        return x
    root = top.get("$top", {})
    return {k: res(v) for k, v in root.items()}


def load_plist_bytes(b):
    p = plistlib.loads(b)
    if isinstance(p, dict) and p.get("$archiver") == "NSKeyedArchiver":
        return unarchive(p)
    return p


def flatten(obj, path, out, depth=0):
    if depth > 30:
        return
    if isinstance(obj, dict):
        for k, v in obj.items():
            flatten(v, "%s/%s" % (path, k), out, depth + 1)
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            flatten(v, "%s[%d]" % (path, i), out, depth + 1)
    elif isinstance(obj, (bytes, bytearray)):
        if obj[:8] == b"bplist00":
            try:
                flatten(load_plist_bytes(bytes(obj)), path + "{bplist}", out, depth + 1)
                return
            except Exception:
                pass
        out.append((path, "bytes", obj[:256].hex()))
    elif isinstance(obj, dt.datetime):
        out.append((path, "date", iso(obj)))
    else:
        out.append((path, type(obj).__name__, str(obj)))


def parse_plist(f, db):
    try:
        p = load_plist_bytes(open(f["full"], "rb").read())
    except Exception:
        return False
    rows = []
    flatten(p, "", rows)
    for k, t, v in rows:
        db.add("plist_values", (f["path"], k or "/", t, v[:4000]))
    return True


# =========================================================================== Files/ caches
REF_RE = re.compile(r"^(.*)\[(\d+)\](\.[^.]*)?$")
PHOTO_RE = re.compile(r"^\{([0-9A-Fa-f-]{36})\}(\d{18})\.(\w+)$")


def png_size(b):
    if b[:8] == b"\x89PNG\r\n\x1a\n" and len(b) >= 24:
        return struct.unpack(">II", b[16:24])
    return None, None


def parse_files_area(files, db, store_att, efm_refs):
    by_rel = collections.defaultdict(list)
    for (rid, relp), a in store_att.items():
        by_rel[relp].append((rid, a[0], a[6]))
    efm_owner = collections.defaultdict(set)
    for rid, ns in efm_refs.items():
        for n in ns:
            efm_owner[n].add(rid)
    stats = collections.Counter()
    for f in files:
        p = f["path"]
        base = os.path.basename(p)
        if "/Attachments/" in p and base != ".DS_Store":
            m = REF_RE.match(base)
            refs = by_rel.get(p, [])
            db.add("attachment_files", (p, base, int(m.group(2)) if m else None,
                                        (m.group(3) or "") if m else os.path.splitext(base)[1], f["size"], f["sha256"],
                                        f["type"], ",".join(str(r[0]) for r in refs) or None,
                                        "; ".join(sorted({r[1] for r in refs if r[1]})) or None,
                                        "; ".join(sorted({r[2] for r in refs if r[2]})) or None))
            stats["attachments"] += 1
            if refs:
                db.corr("attachment file <-> store record", p, ",".join(str(r[0]) for r in refs), "linked", refs[0][1])
            else:
                db.corr("attachment file <-> store record", p, None, "on disk only",
                        "no HxStore record references this file (deleted message, inline image of an older version, or a reference in a record that was overwritten)")
        elif "/EFMData/" in p:
            data = open(f["full"], "rb").read()
            fmt = "gzip" if data[:2] == b"\x1f\x8b" else "plain"
            if fmt == "gzip":
                try:
                    data = gzip.decompress(data)
                except OSError:
                    pass
            s = data.decode("utf-8", "replace")
            title = re.search(r"<title>(.*?)</title>", s, re.I | re.S)
            txt = html_to_text(s) if HXDECODE_ERR is None else re.sub(r"<[^>]+>", " ", s)
            num = int(base.split(".")[0]) if base.split(".")[0].isdigit() else None
            owners = efm_owner.get(num, set())
            db.add("efm_files", (p, num, f["size"], f["sha256"], fmt, title.group(1).strip()[:200] if title else None,
                                 re.sub(r"\s+", " ", txt)[:600], ",".join(map(str, sorted(owners))) or None))
            db.corr("EFMData body <-> store record", p, ",".join(map(str, sorted(owners))) or None,
                    "linked" if owners else "unreferenced", "")
            stats["efm"] += 1
        elif "/Photos/" in p or "/AadLogos/" in p:
            with open(f["full"], "rb") as fh:
                head = fh.read(32)
            w, h = png_size(head)
            m = PHOTO_RE.match(base)
            t = from_ticks(int(m.group(2))) if m else None
            db.add("photos", (p, "contact photo" if "/Photos/" in p else "tenant logo", m.group(1) if m else base,
                              t, w, h, f["size"], f["sha256"]))
            db.tl(t, "files", p, "photo timestamp (filename ticks)", "contact photo %s" % (m.group(1) if m else ""))
            stats["photos"] += 1
        elif p.startswith("Files/") and base != ".DS_Store":
            data = open(f["full"], "rb").read()
            txt = data.decode("utf-16-le", "replace") if data[:2] == b"<\x00" else None
            db.add("binary_artifacts", (p, "Files cache", json.dumps({"size": len(data), "type": f["type"]}),
                                        json.dumps([txt[:3000]] if txt else strings_of(data, 40), ensure_ascii=False)))
    return stats


# =========================================================================== small binaries
def parse_small(f, db, root):
    p, base = f["path"], os.path.basename(f["path"])
    d = open(f["full"], "rb").read()
    fields = {"size": len(d), "type": f["type"]}
    parser = "generic"
    if base == "HxStore.lock" and d[:4] == b"\xef\xbe\xad\xde":
        parser = "HxStore lock table"
        fields["header"] = list(struct.unpack_from("<III", d, 4))
        ents = []
        for o in range(0x10, len(d) - 0x28 + 1, 0x28):   # +1: an entry may end exactly at EOF
            pid, tok, ctr, ticks, a, b = struct.unpack_from("<Q8sQQII", d, o)
            if pid == 0 and ticks == 0:
                continue
            t = from_ticks(ticks)
            ents.append({"offset": o, "pid": pid, "token": tok.hex(), "counter": ctr, "time_utc": t, "u32_a": a, "slot": b})
            db.tl(t, "lock", p, "store lock entry", "pid %d slot %d counter %d" % (pid, b, ctr))
        fields["entries"] = ents
    elif d[:4] == b"XENO":
        parser = "external counters"
        fields["u32"] = list(struct.unpack_from("<%dI" % ((len(d) - 4) // 4), d, 4))
    elif base == "FileSystemStatisticsTelemetry.bin" and len(d) >= 8:
        parser = "file-system telemetry"
        ver, ts = struct.unpack_from("<II", d, 0)
        fields.update({"version": ver, "time_utc": from_unix(ts),
                       "u64": list(struct.unpack_from("<%dQ" % ((len(d) - 8) // 8), d, 8))})
        db.tl(from_unix(ts), "telemetry", p, "telemetry snapshot", "file-system statistics")
    elif base == "MigrationTelemetry.bin":
        parser = "migration telemetry"
        fields["u32_nonzero"] = [(i * 4, v) for i, v in enumerate(struct.unpack_from("<%dI" % (len(d) // 4), d))
                                 if v not in (0, 0xFAFAFAFA)][:100]
    elif base == "FileSystemLoggingCache.log" and len(d) >= 8:
        parser = "file-system logging cache"
        ver, cnt = struct.unpack_from("<II", d, 0)
        vals = struct.unpack_from("<%dI" % ((len(d) - 8) // 4), d, 8)
        fields.update({"version": ver, "u32_1": cnt, "entries": len(vals),
                       "distinct_values": collections.Counter("%08x" % v for v in vals).most_common(30)})
    elif d[:8] == b"Nostromo" and d[8:9] != b"i":
        parser = "replication state"
        nz = [o for o in range(0, len(d), 4096) if d[o:o + 4096].strip(b"\x00")]
        fields.update({"header_u32": list(struct.unpack_from("<8I", d, 8)), "nonzero_pages": nz[:50]})
    elif d[:4] == b"Bud2" or d[4:8] == b"Bud1":
        parser = "buddy-allocator file (.DS_Store-like)"
        names = sorted({m.group().decode("utf-16-be", "replace") for m in re.finditer(rb"(?:\x00[\x20-\x7e]){3,}", d)})
        fields["utf16be_names"] = names[:200]
    elif base == "SortDefault.nls":
        parser = "NLS sort table"
        fields["note"] = "Windows-style NLS collation table shipped with Office; not user data"
    elif base == ".schema_version":
        parser = "schema version"
        fields["value"] = d.decode("latin-1", "replace")
    db.add("binary_artifacts", (p, parser, json.dumps(fields, default=str), json.dumps(strings_of(d, 60), ensure_ascii=False)))
    return parser


def parse_config(f, db):
    d = open(f["full"], "rb").read()
    if d.lstrip()[:1] == b"<":
        fmt, content = "xml", d.decode("utf-8", "replace")
    elif f["path"].endswith(".txt"):
        fmt, content = "text", d.decode("utf-8", "replace")
    else:
        fmt = "binary (j-serialized)"
        content = json.dumps({"hex": d[:512].hex(), "strings": strings_of(d, 60)}, ensure_ascii=False)
        # Omc binary cfg: 'G' + ascii id ... 'F' + name ... -> readable names
        names = re.findall(rb"F([\x20-\x7e]{3,60}?) I", d)
        if names:
            content = json.dumps({"names": [n.decode() for n in names], "hex": d[:512].hex()}, ensure_ascii=False)
    db.add("config_files", (f["path"], fmt, content))


# =========================================================================== correlation
def correlate(db, store_res):
    c = db.c
    db.flush()
    if store_res:
        rows = c.execute("""SELECT file, count(*), sum(in_store), sum(mentions), sum(CASE WHEN in_store THEN mentions ELSE 0 END)
                            FROM hfl_store_objects GROUP BY file""").fetchall() if table_has(c, "hfl_object_activity") else []
        for f, n, ins, men, mins in rows:
            db.corr("hfl object ids <-> HxStore records", f, "HxStore.hxd", "summary",
                    "%d logged object ids, %d present in the store, covering %d of %d mentions (%.0f%%)"
                    % (n, ins or 0, mins or 0, men or 0, 100.0 * (mins or 0) / max(men or 1, 1)))
            db.finding("info", "Correlation", "%s: %d of %d logged object IDs exist in HxStore.hxd" % (f, ins or 0, n),
                       "%d of %d object mentions refer to objects still in the store" % (mins or 0, men or 0))
        # store objects never mentioned in either trace log
        nm = c.execute("""SELECT count(DISTINCT record_id) FROM store_records WHERE store='HxStore.hxd'
                          AND record_id NOT IN (SELECT object_id FROM hfl_object_activity)""").fetchone()[0]
        db.corr("HxStore records never seen in trace logs", "HxStore.hxd", None, "summary", "%d records" % nm)
    # attachment refs whose file is missing
    for rid, name, relp in c.execute("SELECT record_id, display_name, rel_path FROM store_attachments WHERE exists_on_disk=0"):
        db.corr("store attachment reference -> file", "record %d" % rid, relp, "file missing", name or "")
    # trace logs vs Osa sessions
    hf = c.execute("SELECT file, first_utc, last_utc FROM hfl_files").fetchall()
    for f, a, b in hf:
        if a and b:
            n = c.execute("SELECT count(*), count(DISTINCT command) FROM osa_logs WHERE time_utc BETWEEN ? AND ?", (a, b)).fetchone()
            db.corr("hfl time range <-> Osa API logs", f, "Osa", "overlap",
                    "%s .. %s UTC: %d Osa log files (%d distinct commands) fall inside this trace log's range" % (a, b, n[0], n[1]))
    db.flush()


def table_has(c, t):
    return c.execute("SELECT count(*) FROM sqlite_master WHERE name=?", (t,)).fetchone()[0] > 0


# =========================================================================== content export
def safe_name(name, maxlen=120):
    name = re.sub(r'[\x00-\x1f/\\:*?"<>|]+', "_", name or "").strip(" .")
    return (name or "unnamed")[:maxlen]


def export_content(dbpath, outdir):
    """Write decoded content out as files::

       export/bodies/<record_id>_<source>.html     one per e-mail body (original HTML; text-only
                                                    bodies are wrapped in a minimal HTML page)
       export/records/<record_id>_v<version>.bin   decompressed payload of every store record version
       export/attachments/<record_id>_<name>        copies of attachment files referenced by a record
                                                    (<name> = cache file name without its [ref no])
       export/attachments/unreferenced/<file>       cached attachment files no record references
       export/manifest.csv                          every exported file with SHA-256 and source

    The table export_files in profile.db holds the same manifest."""
    import csv
    c = sqlite3.connect(dbpath)
    root = (c.execute("SELECT value FROM meta WHERE key='profile_path'").fetchone() or [None])[0]
    ex = os.path.join(outdir, "export")
    if os.path.isdir(ex):
        shutil.rmtree(ex)
    for sub in ("bodies", "records", "attachments/unreferenced"):
        os.makedirs(os.path.join(ex, sub), exist_ok=True)
    c.execute("DROP TABLE IF EXISTS export_files")
    c.execute("CREATE TABLE export_files (kind TEXT, path TEXT, record_id INTEGER, version INTEGER, "
              "source TEXT, size INTEGER, sha256 TEXT, detail TEXT)")
    rows = []
    used = set()

    def unique(rel):
        base, ext = os.path.splitext(rel)
        k, cand = 2, rel
        while cand.lower() in used:
            cand = "%s_%d%s" % (base, k, ext)
            k += 1
        used.add(cand.lower())
        return cand

    def write(rel, data, kind, rid, ver, source, detail):
        rel = unique(rel)
        with open(os.path.join(ex, rel), "wb") as fh:
            fh.write(data)
        rows.append((kind, "export/" + rel, rid, ver, source, len(data), hashlib.sha256(data).hexdigest(), detail))

    # e-mail bodies
    for rid, src, brid, efm, text, body, subj, sender, t in c.execute(
            """SELECT b.record_id, b.source, b.body_record_id, b.efm_path, b.text, b.html, m.subject, m.sender_email,
                      m.display_time_utc FROM store_bodies b LEFT JOIN store_mail m
                      ON m.record_id = b.record_id AND m.store = b.store ORDER BY b.record_id"""):
        if body:
            data = body.encode("utf-8")
        else:
            data = ("<!doctype html><html><head><meta charset=utf-8><title>%s</title></head><body>"
                    "<p><i>Preview text only - the full body was not found in the profile.</i></p><pre>%s</pre></body></html>"
                    % (html.escape(subj or ""), html.escape(text or ""))).encode("utf-8")
        write("bodies/%d_%s.html" % (rid, src), data, "e-mail body", rid, None,
              "record %s%s" % (brid, " via " + efm if efm else ""), "%s | %s | %s" % (t or "", sender or "", subj or ""))
    # store record versions
    for rid, ver, payload, tname, fmt, subj in c.execute(
            "SELECT record_id, version, payload, type_name, raw_format, subject FROM store_records ORDER BY record_id, version"):
        write("records/%d_v%d.bin" % (rid, ver), payload or b"", "store record (decompressed)", rid, ver,
              "HxStore.hxd", "%s %s %s" % (fmt or "", tname or "", subj or ""))
    # attachments referenced by records
    for rid, name, relp, exists in c.execute(
            "SELECT record_id, display_name, rel_path, exists_on_disk FROM store_attachments ORDER BY record_id"):
        src = os.path.join(root, relp) if root else None
        if not exists or not src or not os.path.isfile(src):
            rows.append(("attachment (missing on disk)", None, rid, None, relp, None, None, name))
            continue
        # the cache file name carries the real attachment name: "<name>[<ref no>].<ext>"
        m = REF_RE.match(os.path.basename(relp))
        nm = (m.group(1) + (m.group(3) or "")) if m else os.path.basename(relp)
        rel = unique("attachments/%d_%s" % (rid, safe_name(nm)))
        shutil.copy2(src, os.path.join(ex, rel))
        rows.append(("attachment", "export/" + rel, rid, None, relp, os.path.getsize(src), hashes(src)[1],
                     "name in record (heuristic): %s" % name if name else ""))
    # cached attachments that no record references
    for p, fn, size, sha in c.execute(
            "SELECT path, filename, size, sha256 FROM attachment_files WHERE store_record_ids IS NULL ORDER BY path"):
        src = os.path.join(root, p) if root else None
        if src and os.path.isfile(src):
            m = REF_RE.match(fn)
            rel = unique("attachments/unreferenced/" + safe_name((m.group(1) + (m.group(3) or "")) if m else fn))
            shutil.copy2(src, os.path.join(ex, rel))
            rows.append(("attachment (unreferenced)", "export/" + rel, None, None, p, size, sha, "not referenced by any HxStore record"))
    c.executemany("INSERT INTO export_files VALUES (?,?,?,?,?,?,?,?)", rows)
    c.commit()
    c.close()
    with open(os.path.join(ex, "manifest.csv"), "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["kind", "path", "record_id", "version", "source", "size", "sha256", "detail"])
        w.writerows(rows)
    return collections.Counter(r[0] for r in rows)


# =========================================================================== JSON export
def export_json(dbpath, outdir, big=20000):
    c = sqlite3.connect(dbpath)
    jdir = os.path.join(outdir, "json")
    os.makedirs(jdir, exist_ok=True)
    doc = {"generated_by": "%s %s" % (TOOL, VERSION), "tables": {}, "large_tables": {}}
    names = [r[0] for r in c.execute("SELECT name FROM sqlite_master WHERE type IN ('table','view') ORDER BY type, name")]
    for t in names:
        cur = c.execute('SELECT * FROM "%s"' % t)
        cols = [x[0] for x in cur.description]
        keep = [i for i, col in enumerate(cols) if col not in ("payload", "raw")]
        n = c.execute('SELECT count(*) FROM "%s"' % t).fetchone()[0]
        conv = lambda v: v.hex() if isinstance(v, (bytes, bytearray)) else v
        if n > big:
            path = os.path.join(jdir, t + ".jsonl")
            with open(path, "w", encoding="utf-8") as fh:
                for row in cur:
                    fh.write(json.dumps({cols[i]: conv(row[i]) for i in keep}, ensure_ascii=False) + "\n")
            doc["large_tables"][t] = {"rows": n, "file": os.path.relpath(path, outdir)}
        else:
            doc["tables"][t] = [{cols[i]: conv(row[i]) for i in keep} for row in cur]
    with open(os.path.join(outdir, "profile.json"), "w", encoding="utf-8") as fh:
        json.dump(doc, fh, ensure_ascii=False, indent=1)
    c.close()


# =========================================================================== main
def run(args):
    root = os.path.abspath(args.profile)
    if not os.path.isdir(root):
        sys.exit("error: %s is not a folder" % root)
    os.makedirs(args.out, exist_ok=True)
    dbpath = os.path.join(args.out, "profile.db")
    db = DB(dbpath)
    t0 = time.time()
    db.meta("tool", "%s %s" % (TOOL, VERSION))
    db.meta("profile_path", root)
    db.meta("run_started_utc", iso(dt.datetime.now(dt.timezone.utc).replace(tzinfo=None)))
    db.meta("python", sys.version.split()[0])
    db.meta("hfl_mode", args.hfl_mode)
    print("[1/9] inventory + hashing ...")
    files = inventory(root, db)
    status = {}
    print("      %d files, %.1f MB" % (len(files), sum(f["size"] for f in files) / 1e6))

    # ---- HxStore
    store_res, efm_index = None, {}
    for f in files:
        if "/EFMData/" in f["path"]:
            n = os.path.basename(f["path"]).split(".")[0]
            if n.isdigit():
                efm_index[int(n)] = f["path"]
    print("[2/9] HxStore.hxd / AccountsBackup.bhxd ...")
    for f in files:
        if f["path"].endswith(".hxd"):
            if HXDECODE_ERR:
                status[f["path"]] = ("skipped", "hxstore-decode unavailable: " + HXDECODE_ERR)
                db.finding("warning", "HxStore", "HxStore.hxd not decoded", HXDECODE_ERR)
                continue
            try:
                store_res = store_parse(f["full"], f["path"], db, root, efm_index)
                status[f["path"]] = ("hxstore", "%d record versions, %d ids, %d e-mail versions, %d attachment refs, bodies %s" % (
                    store_res["records"], len(store_res["ids"]), store_res["emails"], store_res["attachments"], store_res["bodies"]))
            except Exception as ex:
                status[f["path"]] = ("error", repr(ex))
        elif f["path"].endswith(".bhxd"):
            n = parse_account_backup(f["full"], f["path"], db)
            status[f["path"]] = ("accounts backup", "%d settings values" % n)
        if f["path"] in status:
            print("      %s: %s" % (f["path"], status[f["path"]][1]))
    store_ids = store_res["ids"] if store_res else set()

    print("[3/9] HFL trace logs (mode=%s) ..." % args.hfl_mode)
    for f in files:
        if f["path"].endswith(".hfl") and not args.skip_hfl:
            try:
                r = parse_hfl(f["full"], f["path"], db, args.hfl_mode, store_ids)
                status[f["path"]] = ("hfl", "%d records %s .. %s, %d errors" % (r["records"], r["first"], r["last"], r["errors"]))
            except Exception as ex:
                status[f["path"]] = ("error", repr(ex))
            db.flush()

    print("[4/9] Osa API logs ...")
    osa = [f for f in files if f["path"].startswith("Osa/") and f["path"].endswith(".xmlgz")]
    n = parse_osa(osa, db)
    for f in osa:
        status[f["path"]] = ("osa", "")
    print("      %d log files" % n)

    print("[5/9] legacy SQLite + olk15 ...")
    tmp = tempfile.mkdtemp(prefix="olkf_")
    try:
        parse_legacy_sqlite(root, files, db, tmp)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    for f in files:
        if ".olk15" in f["path"]:
            status[f["path"]] = ("olk15", "") if parse_olk15(f, db) else ("unparsed", "")
        elif ".sqlite" in f["path"]:
            status[f["path"]] = ("sqlite", "")

    print("[6/9] plists, configs, small binaries ...")
    for f in files:
        p = f["path"]
        if p in status:
            continue
        if f["head"].startswith(b"bplist00") or p.endswith(".plist") or f["head"].startswith(b"<?xml") and p.endswith(".plist"):
            status[p] = ("plist", "") if parse_plist(f, db) else ("unparsed", "")
        elif p.startswith("Omc/"):
            parse_config(f, db)
            status[p] = ("config", "")
        elif not p.startswith("Files/"):
            status[p] = ("binary", parse_small(f, db, root))

    print("[7/9] attachment / body / photo caches ...")
    st = parse_files_area([f for f in files if f["path"].startswith("Files/")], db,
                          store_res["att"] if store_res else {}, store_res["efm_refs"] if store_res else {})
    for f in files:
        if f["path"].startswith("Files/"):
            status.setdefault(f["path"], ("files cache", ""))
    print("      %s" % dict(st))

    for f in files:
        s = status.get(f["path"], ("not parsed", ""))
        db.add("files", (None, f["path"], f["category"], f["size"], f["mtime"], f["birth"], f["mode"], f["md5"],
                         f["sha256"], f["head"][:16].hex(), f["type"], s[0], "ok" if s[0] not in ("error", "unparsed", "skipped") else s[0], s[1]))

    print("[8/9] correlation ...")
    correlate(db, store_res)
    findings(db)
    db.meta("run_seconds", "%.0f" % (time.time() - t0))
    db.close()
    db.c.close()
    print("[9/9] export files, JSON, HTML ...")
    cnt = export_content(dbpath, args.out)
    print("      export: %s" % dict(cnt))
    export_json(dbpath, args.out)
    build_report(dbpath, os.path.join(args.out, "report.html"), args.tz)
    print("done in %.0fs -> %s" % (time.time() - t0, args.out))


def findings(db):
    c = db.c
    db.flush()
    q = lambda s, *a: c.execute(s, a).fetchall()
    for f, a, b, n, e in q("SELECT file, first_utc, last_utc, records, errors FROM hfl_files"):
        db.finding("info", "Trace logs", "%s covers %s .. %s UTC (%d records, %d errors)" % (f, a, b, n, e))
    acct = q("SELECT value FROM plist_values WHERE keypath LIKE '/DefaultAccountIdentifier%'")
    if acct:
        db.finding("info", "Account", "Default account: %s" % acct[0][0])
    for ua, n in q("SELECT user_agent, count(*) FROM osa_logs WHERE user_agent IS NOT NULL GROUP BY user_agent ORDER BY 2 DESC LIMIT 3"):
        db.finding("info", "Client", "Client user agent: %s" % ua, "%d Osa requests" % n)
    for be, n in q("SELECT backend, count(*) FROM osa_logs WHERE backend IS NOT NULL GROUP BY backend ORDER BY 2 DESC LIMIT 3"):
        db.finding("info", "Server", "Mailbox back-end server: %s" % be, "%d responses" % n)
    bad = q("SELECT status, count(*) FROM osa_logs WHERE status IS NOT NULL AND status NOT IN %s GROUP BY status ORDER BY 2 DESC" % OK_SQL)
    if bad:
        db.finding("notice", "Osa API", "Non-success API responses: " + ", ".join("%s=%d" % r for r in bad[:8]))
    n = q("SELECT count(*), sum(exists_on_disk=0) FROM store_attachments")[0]
    if n[0]:
        db.finding("info", "Attachments", "%d attachment references in HxStore, %d point to files that are not on disk" % (n[0], n[1] or 0))
    n = q("SELECT count(*) FROM attachment_files WHERE store_record_ids IS NULL")[0][0]
    if n:
        db.finding("notice", "Attachments", "%d cached attachment files are not referenced by any current HxStore record" % n,
                   "possible remnants of deleted or moved messages; see table attachment_files")
    n = q("SELECT count(*) FROM (SELECT record_id FROM store_records WHERE store='HxStore.hxd' GROUP BY record_id HAVING count(*)>1)")[0][0]
    if n:
        db.finding("notice", "HxStore", "%d store objects have more than one stored version (older versions still in the file)" % n,
                   "compare versions with: SELECT * FROM store_records WHERE record_id=? ORDER BY version")
    db.flush()


# =========================================================================== HTML report
CSS = """
:root{--bg:#f7f7f5;--fg:#1d1d1b;--mut:#6b6b66;--card:#fff;--line:#e2e1dc;--acc:#2f5f8a;--acc2:#b4552d;
--ok:#2e7d4f;--warn:#a86b00;--bad:#b3261e;--code:#f0efea;--bar:#2f5f8a}
@media (prefers-color-scheme:dark){:root:not([data-theme=light]){--bg:#161615;--fg:#e9e8e3;--mut:#9a9992;
--card:#1f1f1d;--line:#34332f;--acc:#7fb0dc;--acc2:#e08a62;--code:#2a2926;--bar:#7fb0dc}}
:root[data-theme=dark]{--bg:#161615;--fg:#e9e8e3;--mut:#9a9992;--card:#1f1f1d;--line:#34332f;--acc:#7fb0dc;
--acc2:#e08a62;--code:#2a2926;--bar:#7fb0dc}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:14px/1.5 -apple-system,
BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif}main{max-width:1200px;margin:0 auto;padding:24px 16px 80px}
h1{font-size:26px;margin:0 0 4px}h2{font-size:19px;margin:36px 0 10px;padding-top:8px;border-top:1px solid var(--line)}
h3{font-size:15px;margin:20px 0 6px}.mut{color:var(--mut)}a{color:var(--acc)}
nav{position:sticky;top:0;background:var(--bg);border-bottom:1px solid var(--line);padding:8px 16px;z-index:5;
overflow-x:auto;white-space:nowrap;font-size:13px}nav a{margin-right:14px;text-decoration:none}
.cards{display:grid;grid-template-columns:repeat(auto-fill,minmax(170px,1fr));gap:10px;margin:14px 0}
.card{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:10px 12px}
.card b{display:block;font-size:22px;font-variant-numeric:tabular-nums}.card span{color:var(--mut);font-size:12px}
.tw{overflow-x:auto;background:var(--card);border:1px solid var(--line);border-radius:8px;margin:8px 0}
table{border-collapse:collapse;width:100%;font-size:12.5px}th,td{padding:5px 8px;border-bottom:1px solid var(--line);
text-align:left;vertical-align:top}th{position:sticky;top:0;background:var(--card);font-weight:600}
td.n{text-align:right;font-variant-numeric:tabular-nums;white-space:nowrap}code,.mono{font-family:ui-monospace,
SFMono-Regular,Menlo,monospace;font-size:12px}td.mono{word-break:break-all}
.sev-warning{color:var(--warn);font-weight:600}.sev-notice{color:var(--acc2);font-weight:600}.sev-info{color:var(--mut)}
details{margin:6px 0}summary{cursor:pointer;color:var(--acc)}input.f{width:100%;max-width:420px;padding:6px 8px;
border:1px solid var(--line);border-radius:6px;background:var(--card);color:var(--fg);margin:6px 0}
pre{background:var(--code);padding:10px;border-radius:6px;overflow-x:auto;font-size:12px}
.pill{display:inline-block;padding:0 6px;border-radius:9px;background:var(--code);font-size:11px;margin-right:4px}
svg text{fill:var(--mut);font-size:10px}.legend span{margin-right:12px;font-size:12px}
.sw{display:inline-block;width:10px;height:10px;border-radius:2px;margin-right:4px;vertical-align:middle}
"""

SRC_COLORS = {"osa": "#2f7fb5", "hfl": "#c0392b", "store": "#2e8b57", "files": "#8e6bbf", "olk15": "#b8860b",
              "lock": "#777", "telemetry": "#999"}


def esc(v):
    return html.escape("" if v is None else str(v))


def shift(t, tz):
    if not t or not tz:
        return t
    try:
        return iso(dt.datetime.fromisoformat(t[:23]) + dt.timedelta(hours=tz))
    except ValueError:
        return t


class Link:
    """table cell rendered as a hyperlink (href relative to the section page in report/)"""

    def __init__(self, text, href):
        self.text, self.href = text, href


def table(cols, rows, num=(), mono=(), fid=None, maxrows=None, tzcols=(), tz=0):
    out = []
    if fid:
        out.append('<input class="f" placeholder="filter rows..." oninput="flt(this,\'%s\')">' % fid)
    out.append('<div class="tw"><table%s><thead><tr>%s</tr></thead><tbody>' % (
        ' id="%s"' % fid if fid else "", "".join("<th>%s</th>" % esc(c) for c in cols)))
    for i, r in enumerate(rows):
        if maxrows and i >= maxrows:
            break
        tds = []
        for j, v in enumerate(r):
            if j in tzcols:
                v = shift(v, tz)
            cls = ' class="n"' if j in num else (' class="mono"' if j in mono else "")
            if isinstance(v, Link):
                tds.append('<td%s><a href="%s">%s</a></td>' % (cls, esc(v.href), esc(v.text)))
                continue
            if isinstance(v, (int, float)) and j in num and not isinstance(v, bool):
                v = "{:,}".format(v) if isinstance(v, int) else "%.1f" % v
            tds.append("<td%s>%s</td>" % (cls, esc(v)))
        out.append("<tr>%s</tr>" % "".join(tds))
    out.append("</tbody></table></div>")
    if maxrows and len(rows) > maxrows:
        out.append('<p class="mut">showing %d of %d rows - the rest is in profile.db</p>' % (maxrows, len(rows)))
    return "".join(out)


def daily_chart(rows, tz):
    """rows: (day, source, n) -> stacked bar SVG"""
    days = sorted({r[0] for r in rows})
    if not days:
        return "<p class='mut'>no timestamps</p>"
    srcs = sorted({r[1] for r in rows}, key=lambda s: list(SRC_COLORS).index(s) if s in SRC_COLORS else 99)
    val = collections.defaultdict(dict)
    for d_, s, n in rows:
        val[d_][s] = n
    tot = {d_: sum(val[d_].values()) for d_ in days}
    mx = max(tot.values()) or 1
    W, H, pad = max(600, 14 * len(days) + 60), 200, 40
    bw = (W - pad - 10) / len(days)
    parts = ['<svg viewBox="0 0 %d %d" width="100%%" role="img" aria-label="events per day by source">' % (W, H + 40)]
    for k in range(5):
        y = 10 + H * k / 4
        parts.append('<line x1="%d" x2="%d" y1="%.1f" y2="%.1f" stroke="var(--line)"/>' % (pad, W - 10, y, y))
        parts.append('<text x="%d" y="%.1f" text-anchor="end">%s</text>' % (pad - 4, y + 3, "{:,}".format(int(mx * (4 - k) / 4))))
    for i, d_ in enumerate(days):
        y = 10 + H
        x = pad + i * bw
        for s in srcs:
            n = val[d_].get(s, 0)
            if not n:
                continue
            h = H * n / mx
            y -= h
            parts.append('<rect x="%.1f" y="%.1f" width="%.1f" height="%.1f" fill="%s"><title>%s %s: %d</title></rect>'
                         % (x + 1, y, max(bw - 2, 1), h, SRC_COLORS.get(s, "#888"), d_, s, n))
        if len(days) < 40 or i % max(1, len(days) // 20) == 0:
            parts.append('<text x="%.1f" y="%d" transform="rotate(45 %.1f %d)">%s</text>' % (x + bw / 2, H + 22, x + bw / 2, H + 22, d_[5:]))
    parts.append("</svg>")
    leg = '<div class="legend">' + "".join('<span><i class="sw" style="background:%s"></i>%s</span>' % (SRC_COLORS.get(s, "#888"), s) for s in srcs) + "</div>"
    return "".join(parts) + leg


def build_report(dbpath, out, tz):
    c = sqlite3.connect(dbpath)
    q = lambda s, *a: c.execute(s, a).fetchall()
    one = lambda s, *a: (c.execute(s, a).fetchone() or [None])[0]
    meta = dict(q("SELECT key, value FROM meta"))
    tzs = "UTC%+g" % tz if tz else "UTC"
    S = []
    has_exp = table_has(c, "export_files")
    body_link, att_link = {}, {}
    if has_exp:
        for kind, path, rid, src in q("SELECT kind, path, record_id, source FROM export_files WHERE path IS NOT NULL"):
            if kind == "e-mail body":
                body_link.setdefault(rid, "../" + path)
            elif kind.startswith("attachment"):
                att_link[(rid, src)] = "../" + path
    S.append("<h1>Outlook for Mac profile - forensic report</h1>")
    S.append('<p class="mut">%s &middot; profile <code>%s</code> &middot; generated %s UTC &middot; times shown in %s</p>'
             % (esc(meta.get("tool")), esc(meta.get("profile_path")), esc(meta.get("run_started_utc")), tzs))

    # ---- summary
    nfiles, tsize = q("SELECT count(*), sum(size) FROM files")[0]
    cards = [("files", nfiles), ("MB", round((tsize or 0) / 1e6, 1)),
             ("trace records", one("SELECT sum(records) FROM hfl_files") or 0),
             ("store record versions", one("SELECT count(*) FROM store_records WHERE store='HxStore.hxd'") or 0),
             ("store objects", one("SELECT count(DISTINCT record_id) FROM store_records WHERE store='HxStore.hxd'") or 0),
             ("e-mails in store", one("SELECT count(*) FROM store_mail WHERE store='HxStore.hxd'") or 0),
             ("message bodies", one("SELECT count(*) FROM store_bodies") or 0),
             ("attachment files", one("SELECT count(*) FROM attachment_files") or 0),
             ("Osa API logs", one("SELECT count(*) FROM osa_logs") or 0),
             ("timeline events", one("SELECT count(*) FROM timeline") or 0)]
    S.append('<h2 id="summary">Summary</h2><div class="cards">%s</div>' % "".join(
        '<div class="card"><b>%s</b><span>%s</span></div>' % ("{:,}".format(v) if isinstance(v, int) else v, esc(k)) for k, v in cards))
    tr = q("SELECT min(time_utc), max(time_utc) FROM timeline WHERE time_utc > '2000'")[0]
    S.append("<p>Activity found inside the artifacts spans <b>%s</b> to <b>%s</b> (%s). Run took %s s.</p>"
             % (esc(shift(tr[0], tz)), esc(shift(tr[1], tz)), tzs, esc(meta.get("run_seconds"))))
    S.append(table(["Category", "Files", "Bytes", "Parsed by"],
                   q("SELECT category, count(*), sum(size), group_concat(DISTINCT parser) FROM files GROUP BY category ORDER BY 3 DESC"),
                   num=(1, 2)))

    # ---- findings
    S.append('<h2 id="findings">Findings</h2>')
    S.append('<div class="tw"><table><thead><tr><th>Severity</th><th>Area</th><th>Finding</th><th>Detail</th></tr></thead><tbody>')
    for sev, area, f_, det in q("SELECT * FROM findings ORDER BY CASE severity WHEN 'warning' THEN 0 WHEN 'notice' THEN 1 ELSE 2 END"):
        S.append('<tr><td class="sev-%s">%s</td><td>%s</td><td>%s</td><td class="mut">%s</td></tr>' % (esc(sev), esc(sev), esc(area), esc(f_), esc(det)))
    S.append("</tbody></table></div>")

    # ---- inventory
    S.append('<h2 id="inventory">Artifact inventory</h2><p class="mut">Every file with MD5/SHA-256. Osa logs are '
             'summarised per folder below; the full list is in table <code>files</code>.</p>')
    S.append(table(["Path", "Category", "Bytes", "Detected type", "Parser", "Notes", "SHA-256"],
                   q("SELECT path, category, size, detected_type, parser, notes, sha256 FROM files WHERE category NOT IN "
                     "('Osa API logs','Osa pinned logs','Attachment cache','Message bodies (EFMData)','Contact photos') ORDER BY path"),
                   num=(2,), mono=(6,), fid="inv"))
    S.append(table(["Osa folder", "Files", "Bytes", "First log", "Last log"],
                   q("SELECT folder, count(*), sum(length(xml)), min(time_utc), max(time_utc) FROM osa_logs GROUP BY folder ORDER BY folder"),
                   num=(1, 2), tzcols=(3, 4), tz=tz))

    # ---- account & config
    S.append('<h2 id="account">Account &amp; configuration</h2>')
    S.append("<h3>ProfilePreferences.plist / clientConfigsForAM.dat</h3>")
    S.append(table(["File", "Key path", "Type", "Value"],
                   q("SELECT file, keypath, type, substr(value,1,300) FROM plist_values ORDER BY file, keypath"), fid="pl", maxrows=400, mono=(1,)))
    S.append("<h3>AccountsBackup.bhxd (account settings backup)</h3>")
    S.append(table(["Section", "Property", "Type", "Value"],
                   q("SELECT section, prop, type_name, value FROM account_backup ORDER BY section, CAST(prop AS INTEGER)"),
                   fid="ab", maxrows=600))
    S.append("<h3>Outlook.com connector (Omc) configuration</h3>")
    S.append(table(["Path", "Format", "Content"], q("SELECT path, format, substr(content,1,800) FROM config_files"), mono=(2,)))

    # ---- timeline
    S.append('<h2 id="timeline">Unified timeline</h2><p class="mut">Timestamps taken from inside the artifacts '
             '(not file-system times). Sources: osa = API logs (app state changes, non-success responses, key commands), '
             'hfl = trace-log errors and boundaries, store = e-mail times in HxStore, files = photo timestamps, olk15 = legacy record dates, lock = store lock entries.</p>')
    S.append(daily_chart(q("SELECT substr(time_utc,1,10), source, count(*) FROM timeline WHERE time_utc > '2020' GROUP BY 1,2"), tz))
    S.append(table(["Time (%s)" % tzs, "Source", "Kind", "Description", "Artifact", "Ref"],
                   q("SELECT time_utc, source, kind, description, artifact, ref FROM timeline WHERE source <> 'osa' OR kind LIKE '%session%' "
                     "ORDER BY time_utc"), fid="tl", maxrows=3000, tzcols=(0,), tz=tz))

    # ---- store
    S.append('<h2 id="store">HxStore.hxd</h2>')
    S.append(table(["Store", "Bytes", "SHA-256", "Pages", "Record versions", "Distinct IDs", "Note"],
                   q("SELECT store, size, sha256, pages_json, records, distinct_ids, note FROM store_info"), num=(1, 4, 5), mono=(2,)))
    S.append(table(["Object type", "Format", "Objects", "Versions"],
                   q("SELECT coalesce(type_name, object_type, '-'), coalesce(format_name, raw_format), count(DISTINCT record_id), count(*) "
                     "FROM store_records WHERE store='HxStore.hxd' GROUP BY 1,2 ORDER BY 3 DESC"), num=(2, 3)))
    S.append("<h3>Folders</h3>" + table(["Record ID", "Name"], q("SELECT record_id, name FROM store_folders ORDER BY name"), num=(0,)))
    S.append("<h3>Objects with several stored versions</h3>")
    S.append(table(["Record ID", "Versions", "Type", "Subject / label", "Offsets"],
                   q("SELECT record_id, count(*), max(coalesce(type_name, raw_format)), max(subject), group_concat(file_offset) "
                     "FROM store_records WHERE store='HxStore.hxd' GROUP BY record_id HAVING count(*)>1 ORDER BY 2 DESC"),
                   num=(0, 1), fid="ver", maxrows=300))

    # ---- mail
    S.append('<h2 id="mail">E-mail in HxStore</h2>')
    mail_rows = [list(r) for r in q("""SELECT m.display_time_utc, m.record_id, m.sender_email, m.sender_name, m.subject, m.folder, m.versions,
                        (SELECT source FROM store_bodies b WHERE b.record_id=m.record_id LIMIT 1),
                        (SELECT group_concat(display_name, '; ') FROM store_attachments a WHERE a.record_id=m.record_id)
                        FROM store_mail m ORDER BY m.display_time_utc DESC""")]
    for r in mail_rows:
        if r[1] in body_link:
            r[7] = Link(r[7] or "open", body_link[r[1]])
    S.append("<p class='mut'>Click a Body cell to open the exported message body.</p>")
    S.append(table(["Time (%s)" % tzs, "Record", "Sender", "Name", "Subject", "Folder", "Versions", "Body", "Attachments"],
                   mail_rows, num=(1, 6), fid="mail", tzcols=(0,), tz=tz))
    S.append("<h3>Message bodies</h3><p class='mut'>Source: inline = HTML inside the record, efmdata = Files/S0/*/EFMData file, "
             "sibling = another record with the same Message-ID, preview = the short preview text only.</p>")
    S.append(table(["Record", "Source", "Body record", "EFM file", "Text (first 400 chars)"],
                   q("SELECT record_id, source, body_record_id, efm_path, substr(replace(text, char(10), ' '),1,400) FROM store_bodies ORDER BY record_id"),
                   num=(0, 2), fid="bod", maxrows=600))

    # ---- attachments
    S.append('<h2 id="attach">Attachments</h2>')
    att_rows = [list(r) for r in q("SELECT record_id, display_name, rel_path, CASE exists_on_disk WHEN 1 THEN 'yes' ELSE 'NO' END, "
                                   "size, sha256, sender_email FROM store_attachments ORDER BY record_id")]
    for r in att_rows:
        if (r[0], r[2]) in att_link:
            r[1] = Link(r[1] or "open", att_link[(r[0], r[2])])
    S.append("<h3>References in HxStore</h3><p class='mut'>Click a display name to open the exported copy.</p>" + table(
        ["Record", "Display name", "Path in profile", "On disk", "Bytes", "SHA-256", "Sender"],
        att_rows, num=(0, 4), mono=(5,), fid="sat"))
    S.append("<h3>Files in the attachment cache</h3>" + table(
        ["File", "Ref no.", "Type", "Bytes", "SHA-256", "Referenced by records", "Senders"],
        q("SELECT filename, ref_no, detected_type, size, sha256, coalesce(store_record_ids, '- none -'), senders FROM attachment_files ORDER BY ref_no"),
        num=(1, 3), mono=(4,), fid="afi"))
    S.append("<h3>EFMData message bodies on disk</h3>" + table(
        ["File", "Bytes", "Format", "Title", "Referenced by", "Text preview"],
        q("SELECT path, size, format, title, store_record_ids, substr(text_preview,1,300) FROM efm_files ORDER BY number"), num=(1,), fid="efm", maxrows=300))
    S.append("<h3>Contact photos and tenant logos</h3>" + table(
        ["File", "Kind", "Time from filename (%s)" % tzs, "W", "H", "Bytes", "SHA-256"],
        q("SELECT path, kind, time_utc, width, height, size, sha256 FROM photos ORDER BY time_utc"), num=(3, 4, 5), mono=(6,), tzcols=(2,), tz=tz))

    # ---- hfl
    S.append('<h2 id="hfl">HxCore trace logs (.hfl)</h2>')
    S.append(table(["File", "Created (%s)" % tzs, "First record", "Last record", "Records", "Errors", "Warn", "Threads", "Activities",
                    "Events", "Chunks", "Gap bytes", "Office build", "SHA-256"],
                   q("SELECT file, created_utc, first_utc, last_utc, records, errors, warnings, threads, activities, events, chunks, gap_bytes, office_build, sha256 FROM hfl_files"),
                   num=tuple(range(4, 12)), mono=(13,), tzcols=(1, 2, 3), tz=tz))
    for (f_,) in q("SELECT file FROM hfl_files"):
        S.append("<h3>%s - most frequent events</h3>" % esc(f_))
        S.append(table(["Event", "Label", "Count", "Levels", "Signature", "Example"],
                       q("SELECT ekey, label, count, levels, signature, substr(example,1,200) FROM hfl_events WHERE file=? ORDER BY count DESC LIMIT 25", f_),
                       num=(2,)))
        S.append("<h3>%s - errors (level 2)</h3>" % esc(f_))
        S.append(table(["Time (%s)" % tzs, "Event", "Thread", "Decoded arguments"],
                       q("SELECT time_utc, ekey, thread, summary FROM hfl_records WHERE file=? AND level<=2 ORDER BY stamp_ns", f_),
                       num=(2,), fid="err" + str(abs(hash(f_)) % 9999), maxrows=400, tzcols=(0,), tz=tz))

    # ---- correlation
    S.append('<h2 id="corr">Cross-artifact correlation</h2>')
    S.append(table(["Kind", "Status", "Items"], q("SELECT kind, status, count(*) FROM correlations GROUP BY 1,2 ORDER BY 1,2"), num=(2,)))
    S.append(table(["Kind", "Left", "Right", "Detail"], q("SELECT kind, left_ref, right_ref, detail FROM correlations WHERE status IN ('summary','overlap')")))
    S.append("<h3>Store objects most active in the trace logs</h3>")
    S.append(table(["Trace log", "Object ID", "Mentions", "First (%s)" % tzs, "Last", "Type", "Subject", "Sender", "Folder", "Top events"],
                   q("SELECT file, object_id, mentions, first_utc, last_utc, type_name, subject, sender_email, folder, events FROM hfl_store_objects "
                     "WHERE in_store=1 ORDER BY mentions DESC LIMIT 200"), num=(1, 2), tzcols=(3, 4), tz=tz, fid="hso"))
    S.append("<h3>Objects active in the trace logs but absent from the store (deleted or never persisted)</h3>")
    S.append(table(["Trace log", "Object ID", "Mentions", "First (%s)" % tzs, "Last", "Top events"],
                   q("SELECT file, object_id, mentions, first_utc, last_utc, events FROM hfl_store_objects WHERE in_store=0 AND object_id BETWEEN 1000000 AND 99999999 "
                     "ORDER BY mentions DESC LIMIT 150"), num=(1, 2), tzcols=(3, 4), tz=tz))
    S.append("<h3>Cached attachment files with no store reference</h3>")
    S.append(table(["File", "Detail"], q("SELECT left_ref, detail FROM correlations WHERE status='on disk only' ORDER BY left_ref"), maxrows=300))

    # ---- osa
    S.append('<h2 id="osa">Outlook Service API logs (Osa)</h2><p class="mut">Each .xmlgz is one gzip-compressed XML request, '
             'response or app-state event. Content values are redacted by Outlook as <code>pii:&lt;hash&gt;</code>; structure, '
             'times, commands, servers and status codes remain.</p>')
    S.append(table(["Session folder", "Session start (%s)" % tzs, "Files", "First", "Last", "Accounts"],
                   q("SELECT folder, session_start_utc, count(*), min(time_utc), max(time_utc), group_concat(DISTINCT account) FROM osa_logs GROUP BY folder ORDER BY 2"),
                   num=(2,), tzcols=(1, 3, 4), tz=tz))
    S.append(table(["Channel", "Command", "Files", "Not success", "First (%s)" % tzs, "Last"],
                   q("SELECT * FROM osa_commands ORDER BY n DESC"), num=(2, 3), tzcols=(4, 5), tz=tz, fid="cmd"))
    S.append("<h3>Status codes</h3>" + table(["Status", "Count"], q("SELECT coalesce(status,'(none: request / app event)'), count(*) FROM osa_logs GROUP BY 1 ORDER BY 2 DESC"), num=(1,)))
    S.append("<h3>Servers and clients</h3>")
    S.append(table(["Back-end", "Front-end count", "Responses", "Server build"],
                   q("SELECT backend, count(DISTINCT frontend), count(*), group_concat(DISTINCT server_build) FROM osa_logs WHERE backend IS NOT NULL GROUP BY 1 ORDER BY 3 DESC"), num=(1, 2)))
    S.append(table(["User agent", "App version", "Client version", "Device ID", "Requests"],
                   q("SELECT user_agent, app_version, client_version, device_id, count(*) FROM osa_logs WHERE app_version IS NOT NULL GROUP BY 1,2,3,4 ORDER BY 5 DESC"), num=(4,)))
    S.append("<h3>App state events (suspend / resume / network)</h3>")
    S.append(table(["Time (%s)" % tzs, "Event", "App state", "File"],
                   q("SELECT time_utc, command, app_state, file FROM osa_logs WHERE channel='app' ORDER BY time_utc"), fid="app", maxrows=1500, tzcols=(0,), tz=tz))
    S.append("<h3>Non-success responses</h3>")
    S.append(table(["Time (%s)" % tzs, "Channel", "Command", "Status", "Back-end", "File"],
                   q("SELECT time_utc, channel, command, status, backend, file FROM osa_logs WHERE status IS NOT NULL AND status NOT IN %s ORDER BY time_utc" % OK_SQL),
                   fid="nos", maxrows=1000, tzcols=(0,), tz=tz))

    # ---- legacy
    S.append('<h2 id="legacy">Legacy Outlook 2016 data (Data/)</h2>')
    S.append(table(["Database", "Table", "Rows", "Copied as", "Note"], q("SELECT * FROM legacy_tables WHERE rows IS NULL OR rows > 0 OR note <> ''"), num=(2,)))
    S.append(table(["Database", "WAL bytes", "Page size", "Frames", "Checkpoint seq", "Salt", "Note"], q("SELECT * FROM wal_journals"), num=(1, 2, 3, 4)))
    S.append(table(["Path", "Kind", "Type", "Folder no.", "Name", "Modified (%s)" % tzs, "Props"],
                   q("SELECT path, kind, record_type, folder_no, name, modified_utc, n_props FROM olk15_records ORDER BY kind, name"), num=(3, 6), tzcols=(5,), tz=tz))
    S.append("<details><summary>All olk15 properties</summary>" + table(
        ["Path", "Prop", "Type", "Size", "Value"], q("SELECT path, prop_id, prop_type, size, substr(value,1,200) FROM olk15_props"), num=(3,), fid="olkp") + "</details>")

    # ---- other
    S.append('<h2 id="other">Other artifacts</h2>')
    for p, parser, fields, strs in q("SELECT path, parser, fields, strings FROM binary_artifacts ORDER BY path"):
        S.append("<details><summary><code>%s</code> &mdash; %s</summary><pre>%s</pre><p class='mut'>strings:</p><pre>%s</pre></details>"
                 % (esc(p), esc(parser), esc(json.dumps(json.loads(fields), indent=1, ensure_ascii=False)[:6000]),
                    esc(", ".join(json.loads(strs))[:3000])))

    # ---- exported files
    S.append('<h2 id="exports">Exported files</h2>')
    if has_exp:
        S.append("<p>Decoded content written out as files in <code>export/</code> next to this report. "
                 "<code>export/manifest.csv</code> and table <code>export_files</code> list every file with its SHA-256.</p>")
        S.append(table(["Kind", "Files", "Bytes"], q("SELECT kind, count(path), sum(size) FROM export_files GROUP BY kind ORDER BY 1"), num=(1, 2)))
        for kind, title, fid in (("e-mail body", "E-mail bodies (export/bodies/)", "xb"),
                                 ("attachment", "Attachments referenced by store records (export/attachments/)", "xa"),
                                 ("attachment (unreferenced)", "Cached attachments not referenced by any record (export/attachments/unreferenced/)", "xu"),
                                 ("attachment (missing on disk)", "Attachment references whose file is missing", "xm"),
                                 ("store record (decompressed)", "Store record versions (export/records/)", "xr")):
            rows = [[Link(os.path.basename(p), "../" + p) if p else "-", rid, ver, src, size, sha, det]
                    for p, rid, ver, src, size, sha, det in
                    q("SELECT path, record_id, version, source, size, sha256, detail FROM export_files WHERE kind=? ORDER BY record_id, version", kind)]
            if rows:
                S.append("<h3>%s</h3>" % esc(title))
                S.append(table(["File", "Record", "Version", "Source", "Bytes", "SHA-256", "Detail"], rows,
                               num=(1, 2, 4), mono=(5,), fid=fid))
    else:
        S.append("<p class='mut'>No export was made (run without --report-only to create export/).</p>")

    # ---- limitations
    S.append('<h2 id="limits">Limitations</h2><ul>'
             "<li>File-system timestamps of the copy reflect the copy operation unless the copy preserved them (see Findings).</li>"
             "<li>HxStore decoding uses the hxstore-decode library; field meaning (sender, subject, folder, display time) is heuristic, "
             "and folder names can be off by one or duplicated.</li>"
             "<li>HxStore index pages and unallocated/blob pages are not carved; only data records are decoded.</li>"
             "<li>Osa logs are redacted by Outlook (<code>pii:</code> hashes); only structure, timing, commands and servers are recoverable.</li>"
             "<li>Trace-log events have no names in the file; labels are derived from constant arguments. Object IDs are matched to "
             "store record IDs numerically; flagged IDs with high bits set are not matched.</li>"
             "<li>AccountsBackup.bhxd property names are numeric HxCore property IDs; their meaning is not documented.</li>"
             "<li>Legacy Outlook.sqlite virtual tables (Files) need Outlook's own SQLite module and cannot be read.</li></ul>")
    S.append('<h2 id="sql">SQL quick reference</h2><p>Open <code>profile.db</code> with <code>sqlite3</code> or DB Browser for SQLite.</p><pre>'
             + esc("""-- tables
SELECT name FROM sqlite_master WHERE type IN ('table','view');
-- everything that happened in one hour
SELECT * FROM timeline WHERE time_utc BETWEEN '2026-11-12 01:00' AND '2026-11-12 02:00' ORDER BY time_utc;
-- e-mail with body and attachments
SELECT m.*, b.text FROM store_mail m LEFT JOIN store_bodies b USING(record_id);
-- all versions of one store object, with its strings
SELECT * FROM store_records WHERE record_id = 5227890 ORDER BY version;
SELECT version, idx, text FROM store_strings WHERE record_id = 5227890;
-- trace-log activity for a store object
SELECT * FROM hfl_records WHERE summary LIKE '%#0x4F6D19%' LIMIT 50;
SELECT * FROM hfl_store_objects WHERE object_id = 5227890;
-- one Osa log as XML, and its fields
SELECT xml FROM osa_logs WHERE id = 1;
SELECT path, value FROM osa_fields WHERE log_id = 1;
-- legacy tables copied from Data/*.sqlite
SELECT * FROM legacy_tables;""") + "</pre>")

    c.close()
    write_pages(out, S, meta, tzs)


SECTION_INFO = {
    "findings": ("Findings", "Warnings and notable observations"),
    "inventory": ("Inventory", "Every file with hashes, type and parser"),
    "account": ("Account & config", "Preferences, account backup, connector config"),
    "timeline": ("Timeline", "All timestamps from inside the artifacts"),
    "store": ("HxStore", "Store pages, object types, folders, versions"),
    "mail": ("E-mail", "Messages in the store with bodies"),
    "attach": ("Attachments", "References, cached files, bodies, photos"),
    "hfl": ("Trace logs", "hxcore.hfl and previous-session log"),
    "corr": ("Correlation", "Links between logs, store and files"),
    "osa": ("Osa API logs", "Service requests, responses, app states"),
    "legacy": ("Legacy Outlook", "Outlook 2016 SQLite and olk15 records"),
    "other": ("Other artifacts", "Lock, counters, telemetry, caches"),
    "exports": ("Exported files", "Bodies, record payloads, attachment copies"),
    "limits": ("Limitations", "What could not be decoded"),
    "sql": ("SQL", "Query examples for profile.db"),
}

PAGE_JS = ("<script>function flt(i,id){var v=i.value.toLowerCase();document.querySelectorAll('#'+id+' tbody tr').forEach("
           "function(r){r.style.display=r.textContent.toLowerCase().indexOf(v)>=0?'':'none'})}</script>")
MENU_CSS = (".menu{display:grid;grid-template-columns:repeat(auto-fill,minmax(220px,1fr));gap:10px;margin:14px 0}"
            ".menu a{display:block;background:var(--card);border:1px solid var(--line);border-radius:8px;padding:12px;"
            "text-decoration:none;color:var(--fg)}.menu a:hover{border-color:var(--acc)}.menu b{color:var(--acc);display:block}"
            ".menu span{color:var(--mut);font-size:12px}.pn{display:flex;justify-content:space-between;margin-top:30px}"
            "nav a.cur{font-weight:700;color:var(--fg)}")


def write_pages(out, S, meta, tzs):
    """Main page (report.html: header, summary, menu) + one page per section in report/."""
    body = "".join(S)
    parts = re.split(r'(?=<h2 id=")', body)
    head = parts[0]
    secs = collections.OrderedDict()
    for p in parts[1:]:
        m = re.match(r'<h2 id="([^"]+)">', p)
        secs[m.group(1)] = p
    summary = secs.pop("summary", "")
    order = [k for k in SECTION_INFO if k in secs] + [k for k in secs if k not in SECTION_INFO]
    outdir = os.path.dirname(os.path.abspath(out))
    pdir = os.path.join(outdir, "report")
    if os.path.isdir(pdir):
        shutil.rmtree(pdir)
    os.makedirs(pdir)
    main_name = os.path.basename(out)

    def page(title, nav, content):
        return ("<!doctype html><html lang=en><head><meta charset=utf-8><meta name=viewport content='width=device-width,initial-scale=1'>"
                "<title>%s</title><style>%s%s</style></head><body><nav>%s</nav><main>%s</main>%s</body></html>"
                % (esc(title), CSS, MENU_CSS, nav, content, PAGE_JS))

    def nav(cur, prefix):
        home = ('<a href="%s%s"%s>Home</a>' % ("" if prefix else "../", main_name, "" if cur else ' class="cur"'))
        return home + "".join('<a href="%s%s.html"%s>%s</a>' % (prefix, k, ' class="cur"' if k == cur else "",
                                                                 esc(SECTION_INFO.get(k, (k,))[0])) for k in order)

    menu = '<h2>Report sections</h2><div class="menu">' + "".join(
        '<a href="report/%s.html"><b>%s</b><span>%s</span></a>' % (k, esc(SECTION_INFO.get(k, (k, ""))[0]), esc(SECTION_INFO.get(k, (k, ""))[1]))
        for k in order) + "</div>"
    with open(out, "w", encoding="utf-8") as fh:
        fh.write(page("Outlook Profile Forensics", nav(None, "report/"), head + menu + summary))
    sub = '<p class="mut"><a href="../%s">Outlook for Mac profile - forensic report</a> &middot; %s &middot; times in %s</p>' % (
        main_name, esc(meta.get("profile_path")), tzs)
    for i, k in enumerate(order):
        prv = '<a href="%s.html">&larr; %s</a>' % (order[i - 1], esc(SECTION_INFO.get(order[i - 1], (order[i - 1],))[0])) if i else "<span></span>"
        nxt = '<a href="%s.html">%s &rarr;</a>' % (order[i + 1], esc(SECTION_INFO.get(order[i + 1], (order[i + 1],))[0])) if i + 1 < len(order) else "<span></span>"
        content = sub + secs[k].replace('<h2 id="%s">' % k, '<h1 id="%s">' % k, 1).replace("</h2>", "</h1>", 1) + '<div class="pn">%s%s</div>' % (prv, nxt)
        with open(os.path.join(pdir, k + ".html"), "w", encoding="utf-8") as fh:
            fh.write(page("%s - Outlook Profile Forensics" % SECTION_INFO.get(k, (k,))[0], nav(k, ""), content))


def main():
    ap = argparse.ArgumentParser(description="Forensic parser for an Outlook for Mac profile folder.",
                                 formatter_class=argparse.RawDescriptionHelpFormatter, epilog=__doc__.split("USAGE", 1)[1])
    ap.add_argument("profile", nargs="?", help="profile folder (e.g. 'Main Profile')")
    ap.add_argument("--out", default="olk_forensic_out", help="output folder")
    ap.add_argument("--tz", type=float, default=0.0, help="report times in UTC+HOURS (stored times stay UTC)")
    ap.add_argument("--hfl-mode", choices=("records", "summary"), default="records",
                    help="records: every trace record decoded into hfl_records (slow); summary: errors/warnings + catalog only")
    ap.add_argument("--skip-hfl", action="store_true", help="do not decode .hfl files")
    ap.add_argument("--report-only", metavar="DB", help="rebuild report.html + report/ from an existing profile.db")
    ap.add_argument("--rebuild", metavar="DB", help="from an existing profile.db: redo export/, JSON and the report (no parsing)")
    a = ap.parse_args()
    if a.rebuild:
        od = os.path.dirname(a.rebuild) or "."
        print("export: %s" % dict(export_content(a.rebuild, od)))
        export_json(a.rebuild, od)
        build_report(a.rebuild, os.path.join(od, "report.html"), a.tz)
        return
    if a.report_only:
        build_report(a.report_only, os.path.join(os.path.dirname(a.report_only) or ".", "report.html"), a.tz)
        return
    if not a.profile:
        ap.error("profile folder required")
    run(a)


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""
hfl_parse.py v3 - decoder for the "hxcore.hfl" trace log written by Outlook for Mac's
HxCore sync engine. Reverse engineered from the data alone (no application code).

WHAT THE FILE IS
  A binary trace log (flight recorder) of events. Each event has a timestamp, thread, log level,
  event ID and a list of typed arguments. The event *names* are not stored in the file, only
  numeric IDs. The arguments often carry their own names (operation names, log-site tags,
  object IDs), so most events can still be read.

CONFIDENCE: (C) confirmed on all 2,131,696 records of the sample, (?) inferred / best guess.

FILE HEADER
  0x00 u32 8                                  (?)
  0x04 u32 0x00010000                         (?) format version
  0x08 u64 .NET DateTime ticks, UTC           (C) wall clock when the header was written
  0x10 u64 monotonic clock, nanoseconds       (C) same clock as the record stamps, at that moment
                                                  -> lets every record stamp be converted to UTC
  0x18 32B random bytes                       (?) file/session ID
  0x50 u32 offset of text block, 0x54 u32 its length  (C)
  text block: NUL-separated: Office build, two base64 tokens, "key:value;..." settings

CHUNKS (back to back from the end of the text block)
  +0x00 u32 total chunk length                       (C)
  +0x04 u32 decoded size + 0x28 (repeated at +0x14)  (C)
  +0x08 u32 decoded size + size of the record that did not fit (?) (multiple of 8)
  +0x10 u32 2, +0x18 u32 2 or 3                      (?) compression / flags
  +0x1c DE AD BE EF                                  (C)
  +0x20 u32 stream write offset; equals the chunk's end offset for the newest chunks (C/?)
  +0x24 u32 0x28 = header size                       (C)
  +0x28 raw LZ4 block                                (C)
  Chunks are flushed by several writers, so their time ranges overlap. The file is a ring
  buffer: the few bytes that belong to no chunk are the tail of an overwritten older chunk.
  For a timeline, sort by timestamp (--timeline does this).

RECORD (packed in the decoded chunk, each padded to a multiple of 8 bytes)  (C)
  +0x00 16B activity ID (GUID, RFC byte order; all zero = no activity)
  +0x10 u64 timestamp, nanoseconds of monotonic time (microsecond resolution)
  +0x18 u32 thread ID
  +0x1c u32 argument count
  +0x20 u16 record length (incl. header and padding)
  +0x22 u16 offset of the first argument (always 0x28)
  +0x24 u16 event ID
  +0x26 u8  level: 2=Error, 4=Info, 5=Verbose (ETW-style numbering; 1/3 never seen) (?)
  +0x27 u8  area = component/provider (0..16). Event IDs are local to an area: the pair
            area.event (written "7.43") always has the same argument signature  (C)
  +0x28 arguments, each = 1 type byte + value:
      01 str8   u32 byte count + UTF-8          02 str16  u32 char count + UTF-16LE
      03 i32    05 u32    13 u8    15 u16       04 u64    16 i64    06 bool
      07 f64    08 GUID/ID (16 bytes)           0c bytes  u32 count + raw bytes
  The 0-7 bytes after the last argument are alignment padding filled with stale memory.

VALUE INTERPRETATION (shown as "meaning", heuristics)
  * GUID whose first 8 bytes are zero  -> object ID (the last 8 bytes, LE). A u16 just before
    such an ID is the object's type number: shown as obj[77]#0x4F6C80.
  * 16-char upper-case hex text         -> object ID (LE 64-bit), e.g. '25724F0000000000' = 0x4F7225
  * longer upper-case hex text          -> serialized blob: decoded to bytes, embedded object IDs
    and readable text are listed
  * 'pii:XXXXXXXXXXXXXXXX'              -> value redacted by Outlook (hash of personal data)
  * 5-char lower-case code ('cyx9p')    -> Office log-site tag (identifies the line of code)
  * u64 0x1_0000_0000..0x7FFF_FFFF_FFFF -> memory address (pointer); object identity only
  * FILETIME / .NET ticks / unix-ms     -> date (UTC)
  * u32 0x8xxxxxxx                       -> HRESULT (known ones are named)

CORRELATION WITH HxStore.hxd (forensics)
  The object IDs in the log are the record IDs of Outlook's database HxStore.hxd. Extract the
  store with the hxstore-decode tool (Python 3.10+, ./hxstore-decode), then pass the folder:
      hxdecode mail|attachments|records --format json -n 1000000 --path HxStore.hxd > DIR/<name>.json
      hxdecode folders --format json --path HxStore.hxd > DIR/folders.json
      python3.12 hxstore_export.py HxStore.hxd DIR        # objects.json, folder_map.json, store_info.json
      python3 -I hfl_parse.py hxcore.hfl --hxstore-extract DIR --sqlite out.db --objects-csv objects.csv
  Every object ID in the log is then labelled with what the store holds for it (folder name,
  e-mail sender/subject, attachment names, object type, number of stored versions) and the
  output gains: SQLite tables store_objects + object_activity and views object_timeline,
  email_activity, deleted_or_missing_objects; a per-object CSV (first/last time each object was
  touched in the log, how often, by which events); and a correlation summary.
  Objects that the log touched but the store no longer holds are listed separately: they may
  have been deleted, or were transient (never persisted). Folder names come from the
  hxstore-decode heuristic and can be off by one entry for some folders.
  The u16 written before an object ID in the log is usually that object's store type (it matches
  for types 77, 170, 191, 680) but sometimes a relation/property number (61, 214, 460, 483 occur
  in front of folder IDs).

USAGE
  python3 -I hfl_parse.py hxcore.hfl --show 30                       # pretty-print records
  python3 -I hfl_parse.py hxcore.hfl --catalog catalog.txt           # every event ID explained
  python3 -I hfl_parse.py hxcore.hfl --timeline timeline.csv --tz 7  # time-sorted CSV
  python3 -I hfl_parse.py hxcore.hfl --sqlite hfl.db                 # everything, queryable
  python3 -I hfl_parse.py hxcore.hfl --jsonl hfl.jsonl
  python3 -I hfl_parse.py hxcore.hfl --show 50 --event 7.43,17 --level 2,4   # 17 = any area
  python3 -I hfl_parse.py hxcore.hfl --show 50 --grep PlayChangeList
  python3 -I hfl_parse.py hxcore.hfl --find-id 0x4F7225              # every mention of an object
  python3 -I hfl_parse.py hxcore.hfl --header-only
  python3 -I hfl_parse.py hxcore.hfl --dump-chunk 31 chunk31.bin
  python3 -I hfl_parse.py hxcore.hfl --hxstore-extract hxstore_extract --find-id 0x4F6D19
  --event-names names.json  ({"7.43": "ActorTask", "473": "..."}) overrides the automatic labels.
The input file is only read, never modified.
"""
import argparse
import collections
import csv
import datetime
import hashlib
import json
import os
import re
import sqlite3
import struct
import sys
import time
import uuid

TOOL_VERSION = "3.1"
MARKER = b"\xde\xad\xbe\xef"
CHUNK_HDR = 0x28
REC_HDR = 0x28
MAX_DECODED = 1 << 24
NET_EPOCH_TICKS = 621355968000000000          # .NET ticks at 1970-01-01
FILETIME_EPOCH = 116444736000000000           # FILETIME at 1970-01-01
LEVELS = {1: "CRIT", 2: "ERROR", 3: "WARN", 4: "INFO", 5: "VERB"}
HRESULTS = {
    0x80004001: "E_NOTIMPL", 0x80004002: "E_NOINTERFACE", 0x80004003: "E_POINTER",
    0x80004004: "E_ABORT", 0x80004005: "E_FAIL", 0x8000FFFF: "E_UNEXPECTED",
    0x80070005: "E_ACCESSDENIED", 0x80070006: "E_HANDLE", 0x8007000E: "E_OUTOFMEMORY",
    0x80070057: "E_INVALIDARG", 0x80070002: "ERROR_FILE_NOT_FOUND",
    0x800704C7: "ERROR_CANCELLED", 0x80070102: "WAIT_TIMEOUT", 0x8000000A: "E_PENDING",
    0x8000000B: "E_BOUNDS", 0x8000000C: "E_CHANGED_STATE", 0x8000000D: "E_ILLEGAL_STATE_CHANGE",
    0x80000012: "E_STRING_NOT_NULL_TERMINATED", 0x8000001B: "E_ILLEGAL_DELEGATE_ASSIGNMENT",
    0x800C0007: "INET_E_DATA_NOT_AVAILABLE", 0x800C000B: "INET_E_CONNECTION_TIMEOUT",
}
TYPE_CODES = {"str8": "s", "str16": "S", "i32": "i", "u64": "Q", "u32": "I", "bool": "?",
              "f64": "d", "guid": "G", "bytes": "b", "u8": "B", "u16": "H", "i64": "q"}
HEX_RE = re.compile(r"(?:[0-9A-F]{2}){8,}")
TAG_RE = re.compile(r"[0-9a-z]{5}")
WORDISH_RE = re.compile(r"[A-Za-z][A-Za-z0-9_:. \-/]{3,}")
ASCII_RUN = re.compile(rb"[\x20-\x7e]{4,}")
U16_RUN = re.compile(rb"(?:[\x20-\x7e]\x00){4,}")


class HflError(Exception):
    pass


# =========================================================================== header
def parse_header(d):
    if len(d) < 0x60:
        raise HflError("file too small to be an .hfl")
    u32 = lambda o: struct.unpack_from("<I", d, o)[0]
    u64 = lambda o: struct.unpack_from("<Q", d, o)[0]
    h = collections.OrderedDict()
    h["magic_0x00"] = u32(0x00)
    h["version_0x04"] = "0x%08x" % u32(0x04)
    h["created_ticks"] = u64(0x08)
    h["created_monotonic_ns"] = u64(0x10)
    h["file_id_0x18"] = d[0x18:0x38].hex()
    h["u32_0x38"], h["u32_0x44"], h["u32_0x48"], h["u32_0x4c"] = u32(0x38), u32(0x44), u32(0x48), u32(0x4C)
    to, tl = u32(0x50), u32(0x54)
    h["text_off"], h["text_len"] = to, tl
    if to < 0x58 or to + tl > len(d):
        raise HflError("text block offset/length out of range - not the expected format")
    h["data_start"] = to + tl
    parts = [p.decode("utf-8", "replace") for p in d[to:to + tl].split(b"\x00") if p]
    h["office_build"] = parts[0] if parts else None
    h["text_fields"] = parts
    settings = collections.OrderedDict()
    for p in parts:
        if ";" in p and ":" in p:
            for item in p.split(";"):
                k, _, v = item.partition(":")
                if k:
                    settings[k] = v
    h["settings"] = settings
    # wall clock (unix ns) = boot_epoch_ns + monotonic stamp
    created_unix_ns = (h["created_ticks"] - NET_EPOCH_TICKS) * 100
    h["created_utc"] = fmt_unix_ns(created_unix_ns)
    h["boot_epoch_unix_ns"] = created_unix_ns - h["created_monotonic_ns"]
    h["monotonic_zero_utc"] = fmt_unix_ns(h["boot_epoch_unix_ns"])
    return h


def fmt_unix_ns(ns, tz_minutes=0):
    try:
        t = datetime.datetime(1970, 1, 1) + datetime.timedelta(microseconds=ns // 1000 + tz_minutes * 60_000_000)
        return t.strftime("%Y-%m-%d %H:%M:%S.%f")
    except (OverflowError, ValueError):
        return None


# =========================================================================== chunks / LZ4
def iter_chunks(d, start):
    """Yield ('chunk', pos, length) or ('gap', pos, length)."""
    n = len(d)
    pos = start
    while pos + 0x20 <= n:
        length = struct.unpack_from("<I", d, pos)[0]
        if length >= CHUNK_HDR and pos + length <= n and d[pos + 0x1C:pos + 0x20] == MARKER:
            yield ("chunk", pos, length)
            pos += length
            continue
        m = d.find(MARKER, pos + 0x20)
        if m < 0:
            yield ("gap", pos, n - pos)
            return
        yield ("gap", pos, m - 0x1C - pos)
        pos = m - 0x1C
    if pos < n:
        yield ("gap", pos, n - pos)


def chunk_header(d, pos):
    w = struct.unpack_from("<10I", d, pos)
    return {"comp_len": w[0], "decoded_size": w[1] - CHUNK_HDR, "size_plus_overflow": w[2] - CHUNK_HDR,
            "u32_0x10": w[4], "u32_0x18": w[6], "stream_offset": w[8]}


def lz4_block(buf, max_out=MAX_DECODED):
    """Decode a raw LZ4 block. Returns bytes or None."""
    i, n = 0, len(buf)
    out = bytearray()
    while i < n:
        t = buf[i]
        i += 1
        lit = t >> 4
        if lit == 15:
            while True:
                if i >= n:
                    return None
                b = buf[i]
                i += 1
                lit += b
                if b != 255:
                    break
        if i + lit > n:
            return None
        out += buf[i:i + lit]
        i += lit
        if i == n:
            return bytes(out)
        if i + 2 > n:
            return None
        off = buf[i] | (buf[i + 1] << 8)
        i += 2
        if off == 0 or off > len(out):
            return None
        ml = t & 15
        if ml == 15:
            while True:
                if i >= n:
                    return None
                b = buf[i]
                i += 1
                ml += b
                if b != 255:
                    break
        ml += 4
        start = len(out) - off
        if off >= ml:
            out += out[start:start + ml]
        else:
            pat = bytes(out[start:])
            out += (pat * (ml // off + 1))[:ml]
        if len(out) > max_out:
            return None
    return bytes(out)


# =========================================================================== typed arguments
_FIXED = {
    0x03: ("i32", struct.Struct("<i")), 0x04: ("u64", struct.Struct("<Q")),
    0x05: ("u32", struct.Struct("<I")), 0x06: ("bool", struct.Struct("<B")),
    0x07: ("f64", struct.Struct("<d")), 0x13: ("u8", struct.Struct("<B")),
    0x15: ("u16", struct.Struct("<H")), 0x16: ("i64", struct.Struct("<q")),
}
_U32 = struct.Struct("<I")


def decode_args(buf, pos, end, count):
    """Return (list of (type, value), end_of_args, error or None)."""
    out = []
    try:
        for _ in range(count):
            if pos >= end:
                return out, pos, "ran out of bytes"
            t = buf[pos]
            f = _FIXED.get(t)
            if f is not None:
                v = f[1].unpack_from(buf, pos + 1)[0]
                pos += 1 + f[1].size
                out.append((f[0], v))
            elif t == 0x02:
                c = _U32.unpack_from(buf, pos + 1)[0]
                e = pos + 5 + 2 * c
                if e > end:
                    return out, pos, "string past end"
                out.append(("str16", buf[pos + 5:e].decode("utf-16-le", "replace")))
                pos = e
            elif t == 0x01:
                c = _U32.unpack_from(buf, pos + 1)[0]
                e = pos + 5 + c
                if e > end:
                    return out, pos, "string past end"
                out.append(("str8", buf[pos + 5:e].decode("utf-8", "replace")))
                pos = e
            elif t == 0x08:
                out.append(("guid", bytes(buf[pos + 1:pos + 17])))
                pos += 17
            elif t == 0x0C:
                c = _U32.unpack_from(buf, pos + 1)[0]
                e = pos + 5 + c
                if e > end:
                    return out, pos, "bytes past end"
                out.append(("bytes", bytes(buf[pos + 5:e])))
                pos = e
            else:
                return out, pos, "unknown type byte 0x%02x" % t
        if pos > end:
            return out, pos, "value past end"
        return out, pos, None
    except struct.error:
        return out, pos, "value past end"


# --------------------------------------------------------------------------- interpretation
def date_from_int(v):
    """Return a date string if v looks like FILETIME, .NET ticks or unix ms (2000..2040)."""
    if 125911584000000000 <= v <= 138534048000000000:          # FILETIME 2000..2040
        return fmt_unix_ns((v - FILETIME_EPOCH) * 100) + " UTC (FILETIME)"
    if 630822816000000000 <= v <= 643445280000000000:          # .NET ticks 2000..2040
        return fmt_unix_ns((v - NET_EPOCH_TICKS) * 100) + " UTC (.NET ticks)"
    if 946684800000 <= v <= 2208988800000:                     # unix ms 2000..2040
        return fmt_unix_ns(v * 1000000) + " UTC (unix ms)"
    return None


def objid_str(v):
    return "#0x%X" % v


def readable_bits(b):
    found = [m.group().decode("ascii") for m in ASCII_RUN.finditer(b)
             if sum(ch.isalnum() for ch in m.group().decode("ascii")) >= 3]
    found += [m.group().decode("utf-16-le") for m in U16_RUN.finditer(b)]
    return found


def embedded_ids(b, known):
    hits = []
    for k in range(0, len(b) - 7):
        v = int.from_bytes(b[k:k + 8], "little")
        if v in known:
            hits.append((k, v))
    return hits


def interpret(args, known_ids):
    """Turn [(type, value)] into a list of dicts with JSON-friendly value + meaning, and a
    compact one-line rendering. known_ids is updated with object IDs seen."""
    res, parts = [], []
    pos_of = {}
    local_ids = set()
    for idx, (t, v) in enumerate(args):
        a = {"i": idx, "type": t}
        text = None
        if t in ("str16", "str8"):
            a["value"] = v
            if len(v) == 16 and HEX_RE.fullmatch(v):
                oid = int.from_bytes(bytes.fromhex(v), "little", signed=True)
                a["object_id"] = oid
                a["meaning"] = "object id %s" % (objid_str(oid) if oid >= 0 else oid)
                if oid > 0:
                    known_ids.add(oid)
                    local_ids.add(oid)
                text = "id" + (objid_str(oid) if oid >= 0 else str(oid))
            elif len(v) > 16 and len(v) % 2 == 0 and HEX_RE.fullmatch(v):
                b = bytes.fromhex(v)
                ids = embedded_ids(b, local_ids | known_ids if len(b) <= 512 else local_ids)
                rd = readable_bits(b)
                m = "hex blob, %d bytes" % len(b)
                if ids:
                    m += "; object ids at " + ", ".join("+%d=%s" % (k, objid_str(x)) for k, x in ids[:8])
                if rd:
                    m += "; text " + ", ".join(repr(s) for s in rd[:6])
                a["meaning"] = m
                a["blob_u32"] = list(struct.unpack("<%dI" % (len(b) // 4), b[:len(b) // 4 * 4]))
                if ids:
                    a["embedded_ids"] = [x for _, x in ids]
                text = "blob[%dB%s]" % (len(b), (" " + ",".join(objid_str(x) for _, x in ids[:3])) if ids else "")
            elif v.startswith("pii:"):
                a["meaning"] = "redacted personal data (hash)"
                text = v
            elif t == "str8" and TAG_RE.fullmatch(v) or (TAG_RE.fullmatch(v) and any(c.isdigit() for c in v)):
                a["meaning"] = "log-site tag"
                text = "tag:" + v
            else:
                text = repr(v) if len(v) <= 120 else repr(v[:117] + "...")
        elif t == "guid":
            if v[:8] == b"\x00" * 8:
                oid = int.from_bytes(v[8:], "little")
                a["value"] = v.hex()
                a["object_id"] = oid
                otype = None
                if idx > 0 and args[idx - 1][0] == "u16":
                    otype = args[idx - 1][1]
                    a["object_type"] = otype
                a["meaning"] = ("object id %s" % objid_str(oid) if oid else "no object (null id)") + \
                    (" of type %d" % otype if otype is not None else "")
                if oid:
                    known_ids.add(oid)
                    local_ids.add(oid)
                text = ("obj[%d]" % otype if otype is not None else "obj") + (objid_str(oid) if oid else "#none")
                if otype is not None and parts:
                    parts.pop()              # the u16 type is folded into this token
                    res[-1]["meaning"] = "object type (for the next argument)"
            else:
                g = str(uuid.UUID(bytes_le=v))
                a["value"] = g
                text = "{%s}" % g
        elif t == "u64":
            a["value"] = v
            dt = date_from_int(v)
            if dt:
                a["meaning"] = dt
                text = dt.split(" UTC")[0]
            elif 0x100000000 <= v < 0x800000000000:
                a["meaning"] = "memory address"
                text = "ptr:0x%x" % v
            else:
                text = "0x%x" % v if v > 0xFFFF else str(v)
        elif t == "i64":
            a["value"] = v
            dt = date_from_int(v)
            if dt:
                a["meaning"] = dt
                text = dt.split(" UTC")[0]
            elif v in known_ids or v in local_ids or (STORE is not None and v in STORE.objs):
                a["meaning"] = "object id %s" % objid_str(v)
                a["object_id"] = v
                text = "id" + objid_str(v)
            else:
                text = str(v)
        elif t == "u32":
            a["value"] = v
            if v == 0xFFFFFFFF:
                a["meaning"] = "-1 / none"
                text = "-1"
            elif v >= 0x80000000 and (v in HRESULTS or (v >> 16) & 0x7FF in (0, 7, 0xC)):
                a["meaning"] = "HRESULT 0x%08X %s" % (v, HRESULTS.get(v, "(facility %d, code %d)" % ((v >> 16) & 0x7FF, v & 0xFFFF)))
                text = HRESULTS.get(v, "hr:0x%08X" % v)
            else:
                text = str(v)
        elif t == "bytes":
            a["value"] = v.hex()
            rd = readable_bits(v)
            ids = embedded_ids(v, known_ids | local_ids) if len(v) <= 512 else []
            m = "%d bytes" % len(v)
            if rd:
                m += "; text " + ", ".join(repr(s) for s in rd[:6])
            if ids:
                m += "; object ids at " + ", ".join("+%d=%s" % (k, objid_str(x)) for k, x in ids[:8])
                a["embedded_ids"] = [x for _, x in ids]
            a["meaning"] = m
            text = "bytes[%d%s]" % (len(v), (" " + repr(rd[0][:40])) if rd else "")
        elif t == "bool":
            a["value"] = bool(v)
            text = "true" if v else "false"
        elif t == "f64":
            a["value"] = v if v == v and v not in (float("inf"), float("-inf")) else str(v)
            text = "%g" % v
        else:
            a["value"] = v
            text = str(v)
        res.append(a)
        parts.append(text)
        pos_of[idx] = len(parts) - 1
    if STORE is not None:
        for a in res:
            oid = a.get("object_id")
            if oid and oid in STORE.objs:
                d = STORE.describe(oid)
                a["store"] = d
                a["meaning"] = (a.get("meaning") or "") + " -> HxStore: " + d["label"]
                p_ = pos_of.get(a["i"])
                if p_ is not None and p_ < len(parts):
                    parts[p_] += " <" + d["short"] + ">"
            elif oid and oid > 0 and a["type"] in ("guid", "str16", "str8"):
                a["store"] = {"in_store": False}
            emb = [x for x in a.get("embedded_ids", []) if x in STORE.objs]
            if emb:
                a["meaning"] += "; in HxStore: " + "; ".join("%s=%s" % (objid_str(x), STORE.describe(x)["short"]) for x in emb[:4])
    return res, ", ".join(parts)


def arg_signature(args):
    return "".join(TYPE_CODES[t] for t, _ in args)


# =========================================================================== HxStore correlation
# Object type numbers as documented by hxstore-decode (HXSTORE.md sections 8 and 14)
HX_TYPES = {73: "Account", 77: "View/Folder", 104: "Calendar", 107: "Appointment",
            170: "type170", 191: "Email (MessageHeader)", 201: "MessageHeader", 202: "DataReplication",
            212: "AttachmentHeader", 224: "Contact", 288: "SearchSession", 359: "Person"}
# Record format families (first u32 of the LZ4 stream), names per hxstore-decode HXSTORE.md section 7
HX_FORMATS = {"0x3B0": "Email record", "0x3B1": "Email record", "0x10013": "Object record",
              "0x190": "Entity/container record", "0x191": "Email summary record",
              "0x30FF1": "Rich email record", "0x310F4": "Rich email record", "0x210F4": "Rich email record",
              "0x150": "Small metadata record", "0x1A0": "Attachment/entity record"}
STORE = None          # HxStoreIndex when --hxstore-extract is given


class HxStoreIndex:
    """Objects of HxStore.hxd, loaded from the JSON written by hxstore_export.py and the
    hxdecode CLI (hxstore-decode). Keys are store record IDs, which are the same numbers
    as the object IDs logged in hxcore.hfl."""

    def __init__(self, folder):
        self.folder = folder
        self.objs = {}
        self.mail, self.attach, self.folders, self.info = {}, {}, {}, {}
        load = lambda name: self._load(os.path.join(folder, name))
        objects = load("objects.json")
        if objects is None:
            raise HflError("%s/objects.json not found - run hxstore_export.py first" % folder)
        for o in objects:
            self.objs.setdefault(int(o["record_id"]), []).append(o)
        for m in load("mail.json") or []:
            rid = int(m["record_id"])
            if rid not in self.mail:
                self.mail[rid] = {k: m.get(k) for k in ("sender_email", "sender_name", "subject",
                                                        "timestamp", "is_email", "folder")}
        for a in load("attachments.json") or []:
            self.attach.setdefault(int(a["record_id"]), []).append(a.get("filename"))
        self.folders = {int(k): v for k, v in (load("folder_map.json") or {}).items()}
        self.info = load("store_info.json") or {}
        self._cache = {}

    @staticmethod
    def _load(path):
        if not os.path.exists(path):
            return None
        with open(path, "r", encoding="utf-8") as fh:
            return json.load(fh)

    def describe(self, rid):
        d = self._cache.get(rid)
        if d is not None:
            return d
        vers = self.objs[rid]
        otypes = sorted({v["object_type"] for v in vers if v.get("object_type") is not None})
        otype = otypes[0] if otypes else None
        if otype is not None:
            tname = HX_TYPES.get(otype, "type %d" % otype)
        else:
            raw = vers[0].get("raw_format_type")
            tname = HX_FORMATS.get(raw, "record format %s" % raw)
        strings = []
        for v in vers:
            for x in v.get("strings", []):
                if x not in strings and x != "IPM.Note":
                    strings.append(x)
        m = self.mail.get(rid)
        if rid in self.folders:
            short = "Folder '%s'" % self.folders[rid]
        elif m and (m.get("subject") or m.get("sender_email")):
            short = "Email %s'%s'" % (("from %s " % m["sender_email"]) if m.get("sender_email") else "",
                                      (m.get("subject") or "")[:60])
        elif rid in self.attach:
            short = "Attachments %s" % ", ".join("'%s'" % f for f in self.attach[rid][:3])
        elif strings:
            good = [x for x in strings if not x.isdigit()] or strings
            short = "%s: %s" % (tname, ", ".join("'%s'" % x[:50] for x in good[:3]))
        else:
            short = tname
        label = short + " [%s, %d stored version%s]" % (tname, len(vers), "s" if len(vers) > 1 else "")
        d = {"in_store": True, "object_type": otype, "type_name": tname, "versions": len(vers),
             "short": short, "label": label}
        if m:
            d["mail"] = m
        if rid in self.attach:
            d["attachments"] = self.attach[rid]
        if rid in self.folders:
            d["folder"] = self.folders[rid]
        self._cache[rid] = d
        return d

    def rows(self):
        for rid in sorted(self.objs):
            d = self.describe(rid)
            vers = self.objs[rid]
            m = self.mail.get(rid) or {}
            strings = []
            for v in vers:
                for x in v.get("strings", []):
                    if x not in strings:
                        strings.append(x)
            yield (rid, d["object_type"], d["type_name"], len(vers), vers[0].get("format"),
                   ",".join(sorted({str(v.get("raw_format_type")) for v in vers})), d["short"],
                   self.folders.get(rid), m.get("sender_email"), m.get("sender_name"), m.get("subject"),
                   m.get("timestamp"), json.dumps(self.attach.get(rid), ensure_ascii=False) if rid in self.attach else None,
                   json.dumps(strings[:40], ensure_ascii=False),
                   ",".join(str(v.get("file_offset")) for v in vers))


class ObjectTracker:
    """Per-object activity in the trace log, for correlation with the store."""

    def __init__(self):
        self.o = {}

    def add(self, iargs, stamp, ekey, rid):
        for a in iargs:
            oid = a.get("object_id")
            ids = [oid] if oid and oid > 0 else []
            ids += [x for x in a.get("embedded_ids", []) if x not in ids]
            for x in ids:
                e = self.o.get(x)
                if e is None:
                    e = self.o[x] = [0, stamp, stamp, collections.Counter(), collections.Counter(), rid, rid]
                e[0] += 1
                if stamp < e[1]:
                    e[1], e[5] = stamp, rid
                if stamp > e[2]:
                    e[2], e[6] = stamp, rid
                e[3][ekey] += 1
                if a.get("object_type") is not None and x == oid:
                    e[4][a["object_type"]] += 1


# =========================================================================== records
_REC = struct.Struct("<16sQIIHHHBB")


def iter_records(buf):
    """Yield (offset, header tuple) for every record; returns via StopIteration when the
    chain ends. Sets .complete attribute on the generator owner through a list."""
    pos, n = 0, len(buf)
    while pos + REC_HDR <= n:
        h = _REC.unpack_from(buf, pos)
        ln = h[4]
        if ln < REC_HDR or pos + ln > n:
            return pos
        yield pos, h
        pos += ln
    return pos


class Catalog:
    """Collects per-event statistics to explain what every event ID carries."""

    def __init__(self):
        self.ev = {}

    def add(self, r, args, render):
        e = self.ev.get(r["ekey"])
        if e is None:
            e = self.ev[r["ekey"]] = {
                "count": 0, "levels": collections.Counter(), "areas": collections.Counter(),
                "threads": collections.Counter(), "sigs": collections.Counter(),
                "strs": collections.defaultdict(collections.Counter), "first": r["stamp"],
                "last": r["stamp"], "examples": [], "activities": 0}
        e["count"] += 1
        e["levels"][r["level"]] += 1
        e["areas"][r["area"]] += 1
        if len(e["threads"]) < 64 or r["thread"] in e["threads"]:
            e["threads"][r["thread"]] += 1
        e["sigs"][r["sig"]] += 1
        e["first"] = min(e["first"], r["stamp"])
        e["last"] = max(e["last"], r["stamp"])
        if r["activity"]:
            e["activities"] += 1
        for k, (t, v) in enumerate(args):
            if t in ("str8", "str16") and not HEX_RE.fullmatch(v) and not v.startswith("pii:"):
                c = e["strs"][k]
                if len(c) < 200 or v in c:
                    c[v] += 1
        if len(e["examples"]) < 3 and render not in e["examples"]:
            e["examples"].append(render)

    def labels(self):
        return {ev: self.label_for(ev) for ev in self.ev}

    def label_for(self, ev):
        """Automatic label: the constant log-site tag and/or a constant/dominant word-like
        string argument of this event."""
        e = self.ev.get(ev)
        if e is None:
            return None
        if True:
            tag, word = None, None
            for k, c in sorted(e["strs"].items()):
                v, n = c.most_common(1)[0]
                if n < 0.6 * e["count"]:
                    continue
                if TAG_RE.fullmatch(v) and tag is None:
                    tag = v
                elif word is None and WORDISH_RE.fullmatch(v) and not v.startswith("hx_"):
                    word = v
            lab = word or ""
            if tag:
                lab = (lab + " " if lab else "") + "[" + tag + "]"
            return lab or None


def load_names(path):
    if not path:
        return {}
    with open(path, "r", encoding="utf-8") as fh:
        return {str(k): v for k, v in json.load(fh).items()}


def ekey_sort(k):
    a, _, e = k.partition(".")
    return (int(a), int(e))


def user_label(names, ekey):
    return names.get(ekey) or names.get(ekey.partition(".")[2])


# =========================================================================== sinks
class JsonlSink:
    def __init__(self, path):
        self.f = open(path, "w", encoding="utf-8")

    def record(self, r):
        o = {k: r[k] for k in ("chunk", "off", "time_utc", "stamp_ns", "activity", "thread",
                               "ekey", "event", "level", "level_name", "area", "sig", "summary")}
        o["args"] = r["args"]
        self.f.write(json.dumps(o, ensure_ascii=False) + "\n")

    def close(self, meta, catalog, labels):
        self.f.close()


class SqliteSink:
    SCHEMA = """
    CREATE TABLE meta    (key TEXT PRIMARY KEY, value TEXT);
    CREATE TABLE chunks  (idx INTEGER PRIMARY KEY, file_off INTEGER, comp_len INTEGER,
                          decoded_len INTEGER, stream_offset INTEGER, records INTEGER,
                          first_time TEXT, last_time TEXT, size_ok INTEGER, chain_ok INTEGER);
    CREATE TABLE gaps    (file_off INTEGER, length INTEGER, note TEXT);
    CREATE TABLE events  (event_key TEXT PRIMARY KEY, area INTEGER, event INTEGER, label TEXT,
                          count INTEGER, level TEXT, signature TEXT, threads TEXT, first_time TEXT,
                          last_time TEXT, string_args TEXT, examples TEXT);
    CREATE TABLE records (id INTEGER PRIMARY KEY, chunk INTEGER, off INTEGER, time_utc TEXT,
                          stamp_ns INTEGER, activity TEXT, thread INTEGER, event_key TEXT, event INTEGER,
                          level INTEGER, level_name TEXT, area INTEGER, argc INTEGER, sig TEXT,
                          summary TEXT, args TEXT, raw BLOB);
    CREATE TABLE args    (record_id INTEGER, i INTEGER, type TEXT, value_text TEXT,
                          value_int INTEGER, value_real REAL, object_id INTEGER,
                          object_type INTEGER, meaning TEXT, store_label TEXT);
    CREATE VIEW record_view AS
      SELECT r.id, r.time_utc, r.thread, r.level_name, r.event_key, e.label, r.summary, r.activity
      FROM records r LEFT JOIN events e ON e.event_key = r.event_key;
    """
    INDEXES = """
    CREATE INDEX idx_rec_time  ON records(stamp_ns);
    CREATE INDEX idx_rec_event ON records(event_key);
    CREATE INDEX idx_rec_thr   ON records(thread);
    CREATE INDEX idx_rec_act   ON records(activity);
    CREATE INDEX idx_args_rec  ON args(record_id);
    CREATE INDEX idx_args_obj  ON args(object_id);
    CREATE INDEX idx_args_text ON args(value_text);
    CREATE INDEX idx_args_int  ON args(value_int);
    CREATE INDEX idx_args_store ON args(store_label);
    """

    def __init__(self, path, with_args=True, with_raw=True):
        self.db = sqlite3.connect(path)
        self.db.execute("PRAGMA journal_mode=OFF")
        self.db.execute("PRAGMA synchronous=OFF")
        self.db.executescript(self.SCHEMA)
        self.with_args, self.with_raw = with_args, with_raw
        self.next_id = 1
        self.rec_rows, self.arg_rows = [], []
        self.db.execute("BEGIN")

    def chunk(self, row):
        self.db.execute("INSERT INTO chunks VALUES (?,?,?,?,?,?,?,?,?,?)", row)

    def gap(self, off, length, note):
        self.db.execute("INSERT INTO gaps VALUES (?,?,?)", (off, length, note))

    def record(self, r):
        rid = self.next_id
        self.next_id += 1
        self.rec_rows.append((rid, r["chunk"], r["off"], r["time_utc"], r["stamp_ns"], r["activity"],
                              r["thread"], r["ekey"], r["event"], r["level"], r["level_name"], r["area"],
                              len(r["args"]), r["sig"], r["summary"],
                              json.dumps(r["args"], ensure_ascii=False),
                              r["raw"] if self.with_raw else None))
        if self.with_args:
            for a in r["args"]:
                v = a.get("value")
                vt = vi = vr = None
                if isinstance(v, bool):
                    vi = int(v)
                elif isinstance(v, int):
                    if -(1 << 63) <= v < (1 << 63):
                        vi = v
                    else:
                        vt = str(v)
                elif isinstance(v, float):
                    vr = v
                else:
                    vt = v
                oid = a.get("object_id")
                if oid is not None and oid >= (1 << 63):
                    oid -= 1 << 64           # SQLite integers are signed 64-bit
                self.arg_rows.append((rid, a["i"], a["type"], vt, vi, vr, oid,
                                      a.get("object_type"), a.get("meaning"),
                                      (a.get("store") or {}).get("short")))
        if len(self.rec_rows) >= 20000:
            self.flush()

    def flush(self):
        self.db.executemany("INSERT INTO records VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", self.rec_rows)
        if self.arg_rows:
            self.db.executemany("INSERT INTO args VALUES (?,?,?,?,?,?,?,?,?,?)", self.arg_rows)
        self.rec_rows, self.arg_rows = [], []

    CORR_SCHEMA = """
    CREATE TABLE store_objects  (record_id INTEGER PRIMARY KEY, object_type INTEGER, type_name TEXT,
                                 versions INTEGER, format INTEGER, raw_format_types TEXT, label TEXT,
                                 folder TEXT, sender_email TEXT, sender_name TEXT, subject TEXT,
                                 mail_timestamp TEXT, attachments TEXT, strings TEXT, file_offsets TEXT);
    CREATE TABLE object_activity(object_id INTEGER PRIMARY KEY, in_store INTEGER, store_type TEXT,
                                 store_label TEXT, log_mentions INTEGER, first_seen_utc TEXT,
                                 last_seen_utc TEXT, first_record TEXT, last_record TEXT,
                                 log_object_types TEXT, top_events TEXT);
    CREATE VIEW object_timeline AS
      SELECT a.object_id, s.label AS store_label, s.type_name, r.time_utc, r.thread, r.event_key,
             r.level_name, r.summary, r.activity, r.id AS record_id
      FROM args a JOIN records r ON r.id = a.record_id
      LEFT JOIN store_objects s ON s.record_id = a.object_id
      WHERE a.object_id IS NOT NULL AND a.object_id > 0;
    CREATE VIEW deleted_or_missing_objects AS
      SELECT * FROM object_activity WHERE in_store = 0 ORDER BY log_mentions DESC;
    CREATE VIEW email_activity AS
      SELECT o.*, s.sender_email, s.subject, s.mail_timestamp, s.folder
      FROM object_activity o JOIN store_objects s ON s.record_id = o.object_id
      WHERE s.sender_email IS NOT NULL OR s.subject IS NOT NULL;
    """

    def write_correlation(self, store_rows, activity_rows):
        self.flush()
        self.db.executescript(self.CORR_SCHEMA)       # commits pending rows first
        self.db.executemany("INSERT INTO store_objects VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                            [((r[0] - (1 << 64) if r[0] >= (1 << 63) else r[0]),) + tuple(r[1:]) for r in store_rows])
        sg = lambda v: v - (1 << 64) if v >= (1 << 63) else v       # SQLite integers are signed 64-bit
        self.db.executemany("INSERT INTO object_activity VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                            [(sg(r[0]),) + tuple(r[1:]) for r in activity_rows])

    def close(self, meta, catalog_rows, labels):
        self.flush()
        self.db.executemany("INSERT INTO events VALUES (?,?,?,?,?,?,?,?,?,?,?,?)", catalog_rows)
        self.db.executemany("INSERT INTO meta VALUES (?,?)",
                            [(k, v if isinstance(v, str) else json.dumps(v, ensure_ascii=False))
                             for k, v in meta.items()])
        self.db.execute("COMMIT")
        sys.stderr.write("  building SQLite indexes...\n")
        self.db.executescript(self.INDEXES)
        self.db.commit()
        self.db.close()


# =========================================================================== output helpers
def format_record(n, r, lab):
    head = "#%d  %s  T%-5d %-5s event %s%s" % (
        n, r["time_local"], r["thread"], r["level_name"], r["ekey"],
        (" (%s)" % lab) if lab else "")
    lines = [head, "     chunk %d +0x%x  activity=%s  args=%s" % (
        r["chunk"], r["off"], r["activity"] or "-", r["sig"] or "(none)")]
    for a in r["args"]:
        v = a.get("value")
        if a["type"] in ("str16", "str8"):
            vs = repr(v) if len(v) <= 200 else repr(v[:197] + "...")
        elif a["type"] == "u64":
            vs = "0x%x" % v
        elif a["type"] == "bytes":
            vs = v[:96] + ("..." if len(v) > 96 else "")
        else:
            vs = str(v)
        m = a.get("meaning")
        lines.append("       [%d] %-5s %s%s" % (a["i"], a["type"], vs, ("   <- " + m) if m else ""))
    return "\n".join(lines)


def catalog_rows(cat, labels, user_names, to_utc):
    rows = []
    for ev in sorted(cat.ev, key=lambda k: -cat.ev[k]["count"]):
        e = cat.ev[ev]
        lab = user_label(user_names, ev) or labels.get(ev)
        lvl = ",".join("%s:%d" % (LEVELS.get(k, k), n) for k, n in e["levels"].most_common())
        sig = ",".join("%s:%d" % (k or "-", n) for k, n in e["sigs"].most_common(3))
        thr = ",".join("%d:%d" % (k, n) for k, n in e["threads"].most_common(5))
        strs = {str(k): [[v, n] for v, n in c.most_common(8)] for k, c in sorted(e["strs"].items())}
        a_, _, e_ = ev.partition(".")
        rows.append((ev, int(a_), int(e_), lab, e["count"], lvl, sig, thr,
                     to_utc(e["first"]), to_utc(e["last"]), json.dumps(strs, ensure_ascii=False),
                     json.dumps(e["examples"], ensure_ascii=False)))
    return rows


def write_catalog(path, rows):
    out = open(path, "w", encoding="utf-8") if path != "-" else sys.stdout
    out.write("EVENT CATALOG - %d distinct events (area.event), most frequent first\n" % len(rows))
    out.write("signature letters: s=str8 S=str16 i=i32 I=u32 q=i64 Q=u64 H=u16 B=u8 ?=bool "
              "d=f64 G=guid/object-id b=bytes\n\n")
    for (ev, area, _e, lab, cnt, lvl, sig, thr, first, last, strs, ex) in rows:
        out.write("event %s%s\n" % (ev, ("  \"%s\"" % lab) if lab else ""))
        out.write("  count %d | level %s | threads %s\n" % (cnt, lvl, thr))
        out.write("  signature %s | %s .. %s UTC\n" % (sig, first, last))
        for k, vals in json.loads(strs).items():
            out.write("  string arg[%s]: %s\n" % (k, ", ".join("%r x%d" % (v, n) for v, n in vals)))
        for x in json.loads(ex):
            out.write("  e.g. %s\n" % x[:300])
        out.write("\n")
    if out is not sys.stdout:
        out.close()


def prepare_output(path, force):
    if path and path != "-" and os.path.exists(path):
        if not force:
            raise HflError("%s already exists (use --force to overwrite)" % path)
        os.remove(path)


def parse_int_set(s):
    return {int(x, 0) for x in s.split(",") if x.strip()} if s else None


# =========================================================================== main
def main():
    ap = argparse.ArgumentParser(description="Decode an Outlook for Mac hxcore.hfl trace log.",
                                 formatter_class=argparse.RawDescriptionHelpFormatter,
                                 epilog=__doc__.split("USAGE", 1)[1])
    ap.add_argument("input")
    ap.add_argument("--show", type=int, metavar="N", help="pretty-print the first N matching records")
    ap.add_argument("--catalog", metavar="PATH", help="write the event catalog ('-' = stdout)")
    ap.add_argument("--timeline", metavar="PATH", help="write a time-sorted CSV of matching records")
    ap.add_argument("--jsonl", metavar="PATH", help="write one JSON object per matching record")
    ap.add_argument("--sqlite", metavar="PATH", help="write an SQLite database")
    ap.add_argument("--no-args-table", action="store_true", help="SQLite: skip the per-argument table")
    ap.add_argument("--raw", action="store_true", help="SQLite: also store each record's raw bytes")
    ap.add_argument("--force", action="store_true", help="overwrite existing output files")
    ap.add_argument("--tz", type=float, default=0.0, metavar="HOURS",
                    help="display times in UTC+HOURS (e.g. 7 for WIB); stored times stay UTC")
    ap.add_argument("--event", metavar="E[,E..]", help="only these events: area.event (7.43) or event ID in any area (43)")
    ap.add_argument("--level", metavar="L[,L..]", help="only these levels (2=Error 4=Info 5=Verbose)")
    ap.add_argument("--thread", metavar="T[,T..]", help="only these thread IDs")
    ap.add_argument("--grep", metavar="TEXT", help="only records whose decoded summary contains TEXT (case-insensitive)")
    ap.add_argument("--find-id", metavar="N", help="only records that mention this object ID (decimal or 0x..)")
    ap.add_argument("--event-names", metavar="JSON", help='JSON {"event id": "name"} to label events')
    ap.add_argument("--hxstore-extract", metavar="DIR",
                    help="correlate with HxStore.hxd: folder written by hxstore_export.py + hxdecode CLI")
    ap.add_argument("--objects-csv", metavar="PATH",
                    help="with --hxstore-extract: write per-object correlation (log activity vs store) as CSV")
    ap.add_argument("--limit-chunks", type=int, metavar="N", help="decode only the first N chunks")
    ap.add_argument("--header-only", action="store_true", help="print the header and stop")
    ap.add_argument("--dump-chunk", nargs=2, metavar=("N", "PATH"), help="write decoded chunk N to PATH")
    args = ap.parse_args()

    with open(args.input, "rb") as fh:
        d = fh.read()
    hdr = parse_header(d)
    tzm = int(round(args.tz * 60))
    boot = hdr["boot_epoch_unix_ns"]
    to_utc = lambda st: fmt_unix_ns(boot + st)
    to_local = lambda st: fmt_unix_ns(boot + st, tzm)
    tzlabel = "UTC" if tzm == 0 else "UTC%+g" % args.tz

    print("HEADER")
    for k, v in hdr.items():
        if k not in ("settings", "text_fields"):
            print("  %-22s %s" % (k, v))
    print("  %-22s %s" % ("text_fields", hdr["text_fields"][:3]))
    print("  settings (%d):" % len(hdr["settings"]))
    for k, v in hdr["settings"].items():
        print("     %s = %s" % (k, v))
    if args.header_only:
        return

    user_names = load_names(args.event_names)
    f_event = {x.strip() for x in args.event.split(",") if x.strip()} if args.event else None
    f_level, f_thread = parse_int_set(args.level), parse_int_set(args.thread)
    grep = args.grep.lower() if args.grep else None
    find_id = None
    if args.find_id:
        try:
            find_id = int(args.find_id, 0)
        except ValueError:
            sys.exit("error: --find-id needs a number")
        if not args.show and not (args.sqlite or args.jsonl or args.timeline):
            args.show = 50
    filtering = any(x is not None for x in (f_event, f_level, f_thread, grep, find_id))

    sinks = []
    try:
        for p in (args.jsonl, args.sqlite, args.timeline, args.catalog, args.objects_csv):
            prepare_output(p, args.force)
        if args.jsonl:
            sinks.append(JsonlSink(args.jsonl))
        if args.sqlite:
            sinks.append(SqliteSink(args.sqlite, not args.no_args_table, args.raw))
    except HflError as ex:
        sys.exit("error: %s" % ex)
    sqlite_sink = next((s for s in sinks if isinstance(s, SqliteSink)), None)
    need_full = bool(sinks or args.show or args.timeline or grep or find_id is not None)
    global STORE
    tracker = None
    if args.hxstore_extract:
        try:
            STORE = HxStoreIndex(args.hxstore_extract)
        except HflError as ex:
            sys.exit("error: %s" % ex)
        tracker = ObjectTracker()
        need_full = True
        print("HXSTORE (%s)" % args.hxstore_extract)
        for k in ("source_file", "size", "sha256", "records", "distinct_record_ids"):
            if k in STORE.info:
                print("  %-22s %s" % (k, STORE.info[k]))
        print("  %-22s %d e-mail records, %d attachment owners, %d folders" % (
            "decoded by hxdecode", len(STORE.mail), len(STORE.attach), len(STORE.folders)))
        if find_id is not None and find_id in STORE.objs:
            print("  object %s in store: %s" % (objid_str(find_id), STORE.describe(find_id)["label"]))
        elif find_id is not None:
            print("  object %s is NOT in the store (deleted, never persisted, or not an object id)" % objid_str(find_id))

    cat = Catalog()
    known_ids = set()
    stat = collections.Counter()
    levels, threads, areas = collections.Counter(), collections.Counter(), collections.Counter()
    activities = set()
    timeline = [] if args.timeline else None
    gaps, warnings = [], []
    smin = smax = None
    ci = shown = 0
    t0 = time.time()
    dump_n = int(args.dump_chunk[0]) if args.dump_chunk else None

    # pass 1: decompress every chunk and collect object IDs (so that plain integers that
    # are object IDs can be recognised everywhere, even before the ID's first typed mention)
    chunk_list = []
    oid_re = re.compile(rb"\x08\x00{8}([\x01-\xff][\x00-\xff]{2}[\x00-\xff]\x00\x00\x00\x00)", re.S)
    nch = 0
    for kind_, pos, length in iter_chunks(d, hdr["data_start"]):
        if kind_ == "chunk":
            if args.limit_chunks is not None and nch >= args.limit_chunks:
                break
            nch += 1
            dec = lz4_block(d[pos + CHUNK_HDR:pos + length])
            if dec is not None:
                for m in oid_re.finditer(dec):
                    known_ids.add(int.from_bytes(m.group(1), "little"))
            chunk_list.append((kind_, pos, length, dec))
            if nch % 200 == 0:
                sys.stderr.write("  pass 1: %d chunks decompressed, %.0fs\r" % (nch, time.time() - t0))
        else:
            chunk_list.append((kind_, pos, length, None))
    known_ids.discard(0)
    sys.stderr.write("\n")

    if STORE is not None:
        known_ids.update(k for k in STORE.objs if 0 < k < 0xFFFFFF00)
    for kind_, pos, length, dec in chunk_list:
        if kind_ == "gap":
            if length:
                note = "bytes belonging to no chunk (probably the tail of an overwritten chunk in the ring buffer)"
                gaps.append((pos, length))
                if sqlite_sink:
                    sqlite_sink.gap(pos, length, note)
            continue
        if args.limit_chunks is not None and ci >= args.limit_chunks:
            break
        ch = chunk_header(d, pos)
        if dec is None:
            stat["lz4_fail"] += 1
            warnings.append("chunk %d at 0x%x: LZ4 decode failed" % (ci, pos))
            if sqlite_sink:
                sqlite_sink.chunk((ci, pos, length, None, ch["stream_offset"], 0, None, None, 0, 0))
            ci += 1
            continue
        size_ok = len(dec) == ch["decoded_size"]
        stat["size_ok" if size_ok else "size_mismatch"] += 1
        if dump_n == ci:
            with open(args.dump_chunk[1], "wb") as out:
                out.write(dec)
        it = iter_records(dec)
        nrec = 0
        cmin = cmax = None
        end = 0
        while True:
            try:
                off, h = next(it)
            except StopIteration as st:
                end = st.value if st.value is not None else len(dec)
                break
            act_b, stamp, thread, argc, ln, aoff, event, level, area = h
            nrec += 1
            raw_args, aend, err = decode_args(dec, off + aoff, off + ln, argc)
            if err:
                stat["arg_errors"] += 1
                if len(warnings) < 1000:
                    warnings.append("chunk %d +0x%x event %d: %s" % (ci, off, event, err))
            stat["padding_bytes"] += off + ln - aend if not err else 0
            cmin = stamp if cmin is None else min(cmin, stamp)
            cmax = stamp if cmax is None else max(cmax, stamp)
            levels[level] += 1
            threads[thread] += 1
            areas[area] += 1
            activity = None if act_b == b"\x00" * 16 else str(uuid.UUID(bytes=act_b))
            if activity:
                activities.add(activity)
            sig = arg_signature(raw_args)
            ekey = "%d.%d" % (area, event)
            r = {"ekey": ekey, "event": event, "level": level, "area": area, "thread": thread, "stamp": stamp,
                 "sig": sig, "activity": activity}
            # interpretation is needed for the catalog examples too, but it is the slow part:
            # do it fully when output needs it, else only for the first few per event
            ev_seen = cat.ev.get(ekey)
            if need_full or ev_seen is None or len(ev_seen["examples"]) < 3:
                iargs, render = interpret(raw_args, known_ids)
            else:
                iargs, render = None, None
            cat.add(r, raw_args, render or "")
            if not need_full:
                continue
            if tracker is not None:
                tracker.add(iargs, stamp, ekey, "%d:0x%x" % (ci, off))
            if f_event is not None and ekey not in f_event and str(event) not in f_event:
                continue
            if f_level is not None and level not in f_level:
                continue
            if f_thread is not None and thread not in f_thread:
                continue
            if grep is not None and grep not in render.lower():
                continue
            if find_id is not None and not any(
                    a.get("object_id") == find_id or a.get("value") == find_id or
                    ("blob_u32" in a and objid_str(find_id) in a.get("meaning", "")) for a in iargs):
                continue
            stat["matched"] += 1

            r.update({"chunk": ci, "off": off, "time_utc": to_utc(stamp), "time_local": to_local(stamp),
                      "stamp_ns": stamp, "level_name": LEVELS.get(level, str(level)),
                      "args": iargs, "summary": render, "raw": bytes(dec[off:off + ln])})
            if args.show and shown < args.show:
                shown += 1
                print(format_record(shown, r, user_label(user_names, ekey) or cat.label_for(ekey)))
            for s in sinks:
                s.record(r)
            if timeline is not None:
                timeline.append((stamp, ci, off, thread, r["level_name"], ekey,
                                 activity or "", render))
        complete = end == len(dec)
        stat["chain_ok" if complete else "chain_break"] += 1
        if not complete:
            warnings.append("chunk %d: record chain stops at 0x%x of 0x%x" % (ci, end, len(dec)))
        stat["records"] += nrec
        if cmin is not None:
            smin = cmin if smin is None else min(smin, cmin)
            smax = cmax if smax is None else max(smax, cmax)
        if sqlite_sink:
            sqlite_sink.chunk((ci, pos, length, len(dec), ch["stream_offset"], nrec,
                               to_utc(cmin) if cmin is not None else None,
                               to_utc(cmax) if cmax is not None else None, int(size_ok), int(complete)))
        ci += 1
        if ci % 100 == 0:
            sys.stderr.write("  %d chunks, %d records, %.0fs\r" % (ci, stat["records"], time.time() - t0))
    sys.stderr.write("\n")

    labels = cat.labels()
    for k in labels:
        labels[k] = user_label(user_names, k) or labels[k]
    crow = catalog_rows(cat, labels, user_names, to_utc)
    corr = None
    if tracker is not None:
        act_rows = []
        for oid, (n, f, l, evs, lts, frid, lrid) in tracker.o.items():
            ins = oid in STORE.objs
            dsc = STORE.describe(oid) if ins else None
            act_rows.append((oid, int(ins), dsc["type_name"] if dsc else None, dsc["label"] if dsc else None,
                             n, to_utc(f), to_utc(l), frid, lrid,
                             ",".join("%d:%d" % kv for kv in lts.most_common(5)),
                             ",".join("%s:%d" % kv for kv in evs.most_common(6))))
        for oid in STORE.objs:
            if oid not in tracker.o:
                dsc = STORE.describe(oid)
                act_rows.append((oid, 1, dsc["type_name"], dsc["label"], 0, None, None, None, None, "", ""))
        act_rows.sort(key=lambda r: -r[4])
        in_log = [r for r in act_rows if r[4] > 0]
        corr = {
            "log_object_ids": len(in_log),
            "log_ids_in_store": sum(1 for r in in_log if r[1]),
            "log_mentions": sum(r[4] for r in in_log),
            "log_mentions_resolved": sum(r[4] for r in in_log if r[1]),
            "store_ids": len(STORE.objs),
            "store_ids_never_logged": sum(1 for r in act_rows if r[4] == 0),
            "emails_in_store": len(STORE.mail),
            "emails_with_log_activity": sum(1 for r in in_log if r[1] and r[0] in STORE.mail),
            "folders_with_log_activity": sum(1 for r in in_log if r[0] in STORE.folders),
        }
        if sqlite_sink:
            sqlite_sink.write_correlation(list(STORE.rows()), act_rows)
        if args.objects_csv:
            with open(args.objects_csv, "w", newline="", encoding="utf-8") as fh:
                w = csv.writer(fh)
                w.writerow(["object_id", "object_id_hex", "in_store", "store_type", "store_label", "log_mentions",
                            "first_seen_" + tzlabel, "last_seen_" + tzlabel, "log_object_types", "top_events"])
                for r in act_rows:
                    w.writerow([r[0], "0x%X" % r[0], r[1], r[2] or "", r[3] or "", r[4],
                                to_local(tracker.o[r[0]][1]) if r[4] else "",
                                to_local(tracker.o[r[0]][2]) if r[4] else "", r[9], r[10]])
    meta = collections.OrderedDict([
        ("tool_version", TOOL_VERSION), ("source_file", os.path.basename(args.input)),
        ("source_size", len(d)), ("source_sha256", hashlib.sha256(d).hexdigest()),
        ("header", hdr), ("chunks", ci), ("stats", dict(stat)), ("gaps", gaps),
        ("first_record_utc", to_utc(smin) if smin is not None else None),
        ("last_record_utc", to_utc(smax) if smax is not None else None),
        ("filters", {"event": args.event, "level": args.level, "thread": args.thread,
                     "grep": args.grep, "find_id": args.find_id}),
        ("warnings", warnings[:200]),
    ])
    if STORE is not None:
        meta["hxstore"] = {"extract_dir": args.hxstore_extract, "info": STORE.info, "correlation": corr}
    for s in sinks:
        s.close(meta, crow, labels)
    if args.catalog:
        write_catalog(args.catalog, crow)
    if timeline is not None:
        sys.stderr.write("  sorting %d timeline rows...\n" % len(timeline))
        timeline.sort()
        with open(args.timeline, "w", newline="", encoding="utf-8") as fh:
            w = csv.writer(fh)
            w.writerow(["time_" + tzlabel.replace("+", "plus").replace("-", "minus"), "thread", "level",
                        "event", "event_label", "summary", "activity", "chunk", "offset"])
            for (st, c, off, thr, lv, ev, act, summ) in timeline:
                w.writerow([to_local(st), thr, lv, ev, labels.get(ev) or "", summ, act, c, off])

    print("\nRESULT")
    print("  chunks: %d  %s" % (ci, dict(stat)))
    for (gp, gl) in gaps:
        print("  orphan bytes at file offset %d (%d bytes): tail of an overwritten chunk, not decodable" % (gp, gl))
    if smin is not None:
        print("  time range: %s .. %s %s (%.1f hours)" % (to_local(smin), to_local(smax), tzlabel,
                                                         (smax - smin) / 3.6e12))
    print("  levels: %s" % ", ".join("%s=%d" % (LEVELS.get(k, k), n) for k, n in levels.most_common()))
    print("  threads: %d distinct; busiest %s" % (len(threads), threads.most_common(6)))
    print("  activities: %d distinct activity IDs" % len(activities))
    print("  events: %d distinct area.event keys; most frequent:" % len(cat.ev))
    for ev, e in sorted(cat.ev.items(), key=lambda kv: -kv[1]["count"])[:15]:
        print("     %-7s x%-7d %s" % (ev, e["count"], labels.get(ev) or ""))
    if stat["arg_errors"]:
        print("  argument decode errors: %d (see warnings)" % stat["arg_errors"])
    else:
        print("  every record's arguments decoded completely (padding bytes ignored: %d)" % stat["padding_bytes"])
    if filtering:
        print("  records matching filters: %d" % stat["matched"])
    if corr:
        print("\nCORRELATION WITH HxStore.hxd")
        print("  object IDs mentioned in the log: %d, of which in the store: %d (%.0f%%)" % (
            corr["log_object_ids"], corr["log_ids_in_store"], 100.0 * corr["log_ids_in_store"] / max(1, corr["log_object_ids"])))
        print("  object mentions resolved to a stored object: %d of %d (%.0f%%)" % (
            corr["log_mentions_resolved"], corr["log_mentions"], 100.0 * corr["log_mentions_resolved"] / max(1, corr["log_mentions"])))
        print("  store objects never mentioned in the log: %d of %d" % (corr["store_ids_never_logged"], corr["store_ids"]))
        print("  e-mails in store with log activity: %d of %d; folders with log activity: %d" % (
            corr["emails_with_log_activity"], corr["emails_in_store"], corr["folders_with_log_activity"]))
        print("  most active stored objects:")
        for r in [r for r in act_rows if r[1] and r[4]][:12]:
            print("     %-10s x%-6d %s .. %s  %s" % (objid_str(r[0]), r[4], to_local(tracker.o[r[0]][1])[:19],
                                                 to_local(tracker.o[r[0]][2])[:19], r[3][:90]))
        print("  most active objects NOT in the store (deleted / transient / never persisted):")
        for r in [r for r in act_rows if not r[1]][:8]:
            print("     %-10s x%-6d %s .. %s  log types %s" % (objid_str(r[0]), r[4], to_local(tracker.o[r[0]][1])[:19],
                                                         to_local(tracker.o[r[0]][2])[:19], r[9]))
    for label, p in (("jsonl", args.jsonl), ("sqlite", args.sqlite), ("timeline", args.timeline),
                     ("catalog", args.catalog), ("objects-csv", args.objects_csv)):
        if p and p != "-":
            print("  wrote %s: %s (%.1f MB)" % (label, p, os.path.getsize(p) / 1e6))


if __name__ == "__main__":
    try:
        main()
    except HflError as ex:
        sys.exit("error: %s" % ex)
    except BrokenPipeError:
        pass

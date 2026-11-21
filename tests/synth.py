"""
Builders for small synthetic Outlook-for-Mac artifacts used by the unit tests.

Every builder produces bytes that follow the on-disk layouts documented in olk_forensic.py,
hfl_parse.py and the paper, so the tests never depend on private evidence.
"""
import datetime as dt
import gzip
import plistlib
import struct
import uuid

NET_EPOCH = 621355968000000000
UNIX_EPOCH = dt.datetime(1970, 1, 1)
COCOA_EPOCH = dt.datetime(2001, 1, 1)


# ----------------------------------------------------------------------------- clocks
def ticks(d):
    """datetime (naive UTC) -> .NET ticks"""
    td = d - UNIX_EPOCH                       # integer arithmetic: no float rounding
    return NET_EPOCH + (td.days * 86400 + td.seconds) * 10_000_000 + td.microseconds * 10


def unix(d):
    return int((d - UNIX_EPOCH).total_seconds())


def cocoa(d):
    return (d - COCOA_EPOCH).total_seconds()


# ----------------------------------------------------------------------------- LZ4
def lz4_literals(data):
    """A valid raw LZ4 block that stores `data` as one literal run (no matches)."""
    n = len(data)
    if n < 15:
        return bytes([n << 4]) + data
    out = bytearray([0xF0])
    rest = n - 15
    while rest >= 255:
        out.append(255)
        rest -= 255
    out.append(rest)
    return bytes(out) + data


# ----------------------------------------------------------------------------- HFL trace log
def tlv_str8(s):
    b = s.encode("utf-8")
    return b"\x01" + struct.pack("<I", len(b)) + b


def tlv_str16(s):
    return b"\x02" + struct.pack("<I", len(s)) + s.encode("utf-16-le")


def tlv_i32(v):
    return b"\x03" + struct.pack("<i", v)


def tlv_u64(v):
    return b"\x04" + struct.pack("<Q", v)


def tlv_u32(v):
    return b"\x05" + struct.pack("<I", v)


def tlv_bool(v):
    return b"\x06" + bytes([1 if v else 0])


def tlv_f64(v):
    return b"\x07" + struct.pack("<d", v)


def tlv_guid(b16):
    return b"\x08" + b16


def tlv_bytes(b):
    return b"\x0c" + struct.pack("<I", len(b)) + b


def tlv_u8(v):
    return b"\x13" + bytes([v])


def tlv_u16(v):
    return b"\x15" + struct.pack("<H", v)


def tlv_i64(v):
    return b"\x16" + struct.pack("<q", v)


def hfl_record(stamp, event, level, area, args, thread=7, activity=b"\x00" * 16):
    """One 0x28-byte record header followed by the TLV argument block."""
    body = b"".join(args)
    length = 0x28 + len(body)
    hdr = struct.pack("<16sQIIHHHBB", activity, stamp, thread, len(args), length, 0x28, event, level, area)
    return hdr + body


def hfl_chunk(records):
    """0x28-byte chunk header (DEADBEEF at +0x1C) + LZ4 block of the concatenated records."""
    raw = b"".join(records)
    comp = lz4_literals(raw)
    length = 0x28 + len(comp)
    words = [length, len(raw) + 0x28, len(raw) + 0x28, 0, 0, 0, 0, 0, 0, 0]
    hdr = bytearray(struct.pack("<10I", *words))
    hdr[0x1C:0x20] = b"\xde\xad\xbe\xef"
    return bytes(hdr) + comp


def hfl_file(created, mono_ns, chunks, build="16.0.20622.33801", settings="Level:4;Areas:all", gap=b""):
    """Header: magic 8, version 0x00010000, .NET ticks at 0x08, monotonic ns at 0x10,
    32-byte id at 0x18, text block offset/length at 0x50/0x54. `gap` is inserted
    between the first and second chunk to exercise gap detection."""
    text = build.encode() + b"\x00" + settings.encode() + b"\x00"
    hdr = bytearray(0x58)
    struct.pack_into("<II", hdr, 0, 8, 0x00010000)
    struct.pack_into("<QQ", hdr, 0x08, ticks(created), mono_ns)
    hdr[0x18:0x38] = bytes(range(32))
    struct.pack_into("<II", hdr, 0x50, 0x58, len(text))
    body = chunks[0] + gap + b"".join(chunks[1:]) if chunks else b""
    return bytes(hdr) + text + body


# ----------------------------------------------------------------------------- AccountsBackup.bhxd
def kv_entry(name, typ, value):
    nb = (name + "\x00").encode("utf-16-le")
    return struct.pack("<I", len(nb)) + nb + bytes([typ]) + struct.pack("<I", len(value)) + value


def account_backup(section, entries, store_id=b"\x11" * 8, rhash=b"\xaa" * 8):
    """4096-byte file header page, then one uncompressed slot record:
    slot header = hash(8) store id(8) u32 name_len u32 size u32 size u32 0."""
    name = section.encode("utf-16-le")
    payload = name + struct.pack("<Q", 0) + struct.pack("<I", len(entries)) + b"".join(entries)
    slot = rhash + store_id + struct.pack("<IIII", len(name), len(payload), len(payload), 0) + payload
    slot += b"\x00" * (-len(slot) % 512)
    return b"Nostromoi" + b"\x00" * (4096 - 9) + slot


# ----------------------------------------------------------------------------- Osa logs
def osa_xml(**kw):
    kids = "".join("<%s>%s</%s>" % (k, v, k) for k, v in kw.items())
    return ("<?xml version='1.0'?><Log>%s</Log>" % kids).encode()


def gz(b):
    return gzip.compress(b, mtime=0)


# ----------------------------------------------------------------------------- olk15
def olk15(tag, props):
    """props: list of (pid, type, value bytes). Magic D0 0D 00 00, byte-reversed tag at
    0x20, count at 0x28, 8-byte entries from 0x34, values after the entry table."""
    head = bytearray(0x34)
    head[0:4] = b"\xd0\x0d\x00\x00"
    head[0x20:0x24] = tag.encode("latin-1")[::-1]
    struct.pack_into("<I", head, 0x28, len(props))
    table = b"".join(struct.pack("<HBBI", pid, 0, typ, len(v)) for pid, typ, v in props)
    return bytes(head) + table + b"".join(v for _, _, v in props)


# ----------------------------------------------------------------------------- plists
def keyed_archive(key, value):
    """NSKeyedArchiver plist whose root is the dictionary {key: value}."""
    top = {
        "$archiver": "NSKeyedArchiver", "$version": 100000,
        "$top": {"root": plistlib.UID(1)},
        "$objects": ["$null",
                     {"NS.keys": [plistlib.UID(2)], "NS.objects": [plistlib.UID(3)], "$class": plistlib.UID(4)},
                     key, value, {"$classname": "NSDictionary", "$classes": ["NSDictionary", "NSObject"]}],
    }
    return plistlib.dumps(top, fmt=plistlib.FMT_BINARY)


# ----------------------------------------------------------------------------- small binaries
def lock_table(entries):
    """entries: list of (pid, token8, counter, datetime, a, slot); magic EF BE AD DE."""
    d = b"\xef\xbe\xad\xde" + struct.pack("<III", 1, 2, 3)
    for pid, tok, ctr, when, a, slot in entries:
        d += struct.pack("<Q8sQQII", pid, tok, ctr, ticks(when), a, slot)
    return d


def png(w, h):
    return b"\x89PNG\r\n\x1a\n" + struct.pack(">I", 13) + b"IHDR" + struct.pack(">II", w, h) + b"\x08\x06\x00\x00\x00"


def photo_name(guid, when, ext="png"):
    return "{%s}%018d.%s" % (guid, ticks(when), ext)


def new_guid():
    return str(uuid.UUID(int=0x1234567890ABCDEF1234567890ABCDEF))

#!/usr/bin/env python3
"""
hxstore_export.py - export every object in HxStore.hxd to JSON with the hxstore-decode
library (./hxstore-decode/src), so hfl_parse.py can correlate trace-log object IDs with it.

Needs Python 3.10+ and the `lz4` package (the requirements of hxstore-decode). The store
file is only read.

    python3.12 hxstore_export.py HxStore.hxd hxstore_extract/

Writes into the output directory:
    objects.json     one entry per stored record version: record_id, format, object type,
                     self id, file offset, sizes, UTF-16 strings, e-mail addresses
    folder_map.json  folder record id -> folder name (hxstore-decode FolderIndex heuristic)
    store_info.json  file size, page counts, store ids, SHA-256
The e-mail / attachment / folder / record lists are produced by the hxdecode CLI itself:
    hxdecode mail|attachments|records --format json -n 1000000 --path HxStore.hxd
    hxdecode folders --format json --path HxStore.hxd
"""
import hashlib
import json
import os
import re
import struct
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "hxstore-decode", "src"))

from hxdecode.decompress import decompress_record          # noqa: E402
from hxdecode.folder import FolderIndex                     # noqa: E402
from hxdecode.parser import HxStoreFile                     # noqa: E402

U16 = re.compile(rb"(?:[\x20-\x7e]\x00){3,}")
EMAIL = re.compile(rb"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")


def main():
    if len(sys.argv) != 3:
        sys.exit(__doc__)
    src, outdir = sys.argv[1], sys.argv[2]
    os.makedirs(outdir, exist_ok=True)
    raw = open(src, "rb").read()
    hx = HxStoreFile(src)
    objs = []
    for rec in hx.iter_data_records():
        sh = rec.slot_header
        rid, dec = decompress_record(rec.raw_data, sh.size_b)
        fmt = struct.unpack_from("<I", dec, 0)[0] if len(dec) >= 4 else None
        # 0x10013-style records (first u32 = 0) carry a 64-byte header: self id at 20,
        # ObjectType at 44 (see hxstore-decode/HXSTORE.md section 8)
        otype = self_id = None
        if fmt == 0 and len(dec) >= 52:
            self_id = struct.unpack_from("<I", dec, 20)[0]
            otype = struct.unpack_from("<H", dec, 44)[0]
        strings = []
        for m in U16.finditer(dec):
            s = m.group().decode("utf-16-le").strip()
            if len(s) >= 3 and s not in strings:
                strings.append(s[:300])
            if len(strings) >= 40:
                break
        emails = sorted({e.decode("ascii", "replace") for e in EMAIL.findall(dec)})[:20]
        objs.append({
            "record_id": rid, "format": fmt, "raw_format_type": "0x%X" % struct.unpack_from("<I", rec.raw_data, 8)[0]
            if len(rec.raw_data) >= 12 else None,
            "object_type": otype, "self_id": self_id, "file_offset": sh.file_offset,
            "page": sh.file_offset // 4096, "size_compressed": sh.size_a, "size_decompressed": len(dec),
            "strings": strings, "emails": emails,
        })
    folders = FolderIndex(hx).folders
    st = hx.stats()
    info = {"source_file": os.path.basename(src), "size": len(raw),
            "sha256": hashlib.sha256(raw).hexdigest(), "pages": st,
            "primary_store_id": hx.primary_store_id.hex(), "secondary_store_id": hx.secondary_store_id.hex(),
            "records": len(objs), "distinct_record_ids": len({o["record_id"] for o in objs}),
            "tool": "hxstore-decode (hxdecode 0.1.0) library"}
    with open(os.path.join(outdir, "objects.json"), "w", encoding="utf-8") as fh:
        json.dump(objs, fh, ensure_ascii=False, indent=1)
    with open(os.path.join(outdir, "folder_map.json"), "w", encoding="utf-8") as fh:
        json.dump({str(k): v for k, v in sorted(folders.items())}, fh, ensure_ascii=False, indent=1)
    with open(os.path.join(outdir, "store_info.json"), "w", encoding="utf-8") as fh:
        json.dump(info, fh, indent=1)
    print("objects: %d records (%d distinct ids), folders: %d -> %s"
          % (len(objs), info["distinct_record_ids"], len(folders), outdir))


if __name__ == "__main__":
    main()

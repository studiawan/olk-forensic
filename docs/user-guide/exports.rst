Exported files
==============

The ``export/`` folder holds decoded content as ordinary files, so that it can be opened,
hashed, or loaded into other tools.

E-mail bodies
-------------

``export/bodies/<record_id>_<source>.html`` — one file per e-mail. ``record_id`` is the HxStore
record of the e-mail; ``source`` says where the body was found. The tool tries the sources in
this order and uses the first one that yields HTML:

.. list-table::
   :header-rows: 1
   :widths: 15 85

   * - Source
     - Meaning
   * - ``inline``
     - HTML stored inside the e-mail's own store record
   * - ``efmdata``
     - A cached body file in ``Files/S0/*/EFMData/`` referenced by the record (or by a record
       with the same Message-ID)
   * - ``sibling``
     - HTML in another store record with the same Message-ID
   * - ``preview``
     - Only the short preview text survives; it is wrapped in a minimal, escaped HTML page
       marked *Preview text only*

The original HTML is written unchanged. Remote content referenced by a body is **not**
fetched. Open bodies in a browser without network access if remote images must not be
loaded.

Store record versions
---------------------

``export/records/<record_id>_v<version>.bin`` — the decompressed payload of **every** version of
every HxStore record. Versions are numbered in file order (1 = first found). The SHA-256 of
each payload is also stored in ``store_records.payload_sha256``.

Attachments
-----------

``export/attachments/<record_id>_<filename>`` — a copy of each cached attachment referenced by a
store record. The file name is taken from the cache file name with its ``[N]`` reference
suffix removed (``Quarterly report[12].pdf`` → ``5218940_Quarterly report.pdf``). Characters
that are not allowed in file names are replaced by ``_``. A file referenced by several records
is copied once per record. Copies keep the original file times.

``export/attachments/unreferenced/<filename>`` — cached attachment files that **no** current
store record references. These may be remnants of deleted or moved messages.

Attachment references whose file is not on disk are listed in the manifest with kind
``attachment (missing on disk)`` and an empty path.

Name clashes
------------

If two exported files would get the same name (compared case-insensitively, as on macOS),
the second gets ``_2``, the third ``_3``, and so on, before the extension.

Manifest
--------

``export/manifest.csv`` lists every exported file; the table ``export_files`` in
``profile.db`` holds the same rows.

.. list-table::
   :header-rows: 1
   :widths: 18 82

   * - Column
     - Meaning
   * - ``kind``
     - ``e-mail body``, ``store record (decompressed)``, ``attachment``,
       ``attachment (unreferenced)`` or ``attachment (missing on disk)``
   * - ``path``
     - Path relative to the output folder (empty for missing attachments)
   * - ``record_id``
     - Owning HxStore record
   * - ``version``
     - Record version (store records only)
   * - ``source``
     - Origin: body source record and EFMData path, ``HxStore.hxd``, or the cache path of
       the attachment in the profile
   * - ``size``
     - Size in bytes
   * - ``sha256``
     - SHA-256 of the exported file
   * - ``detail``
     - Time, sender and subject for bodies; format, type and subject for records; the name
       stored in the record for attachments

Verifying the export
--------------------

.. code-block:: bash

   cd olk_forensic_out
   python3 - <<'EOF'
   import csv, hashlib
   bad = 0
   for r in csv.DictReader(open("export/manifest.csv", encoding="utf-8")):
       if r["path"]:
           h = hashlib.sha256(open(r["path"], "rb").read()).hexdigest()
           bad += h != r["sha256"]
   print("mismatches:", bad)
   EOF

Legacy Outlook 2016 data (``Data/``)
====================================

Profiles migrated from Outlook 2016 for Mac keep its data in ``Data/``.

SQLite databases
----------------

``Data/*.sqlite`` (for example ``Outlook.sqlite`` and lock databases) are copied, together with
any ``-wal`` and ``-shm`` file, to a temporary folder and opened there. Opening the copy applies
the write-ahead log, so rows that exist only in the WAL become visible, while the evidence is
never opened by SQLite.

* Every table with rows is copied into ``profile.db`` as ``legacy_<database>_<table>``.
* ``legacy_tables`` lists every table, its row count and its copied name.
* Virtual tables (such as the ``Files`` table, which needs Outlook's own SQLite module) are
  listed but cannot be read.
* ``wal_journals`` summarizes each WAL header: size, page size, number of frames, checkpoint
  sequence and salt. Uncheckpointed frames may hold older or newer versions of pages.

olk15 record files
------------------

Files whose name contains ``.olk15`` (``.olk15Category``, ``.olk15Folder``,
``.olk15Signature``, ``.olk15Contact``, ...) store one record each:

.. list-table::
   :header-rows: 1
   :widths: 14 86

   * - Offset
     - Meaning
   * - 0x00
     - Magic ``D0 0D 00 00``
   * - 0x20
     - 4-character record tag, stored byte-reversed (``olk15_records.record_type``)
   * - 0x28
     - u32 property count *n*
   * - 0x34
     - *n* entries of 8 bytes: u16 property ID, u8 flags, u8 type, u32 value size
   * - 0x34 + 8n
     - Property values, in entry order

.. list-table:: Property types
   :header-rows: 1
   :widths: 12 18 70

   * - Type
     - Name
     - Decoding
   * - 0x02, 0x03, 0x14
     - i16, i32, i64
     - signed integer
   * - 0x0B
     - bool
     - integer
   * - 0x1F
     - utf16
     - UTF-16 text; the first non-empty one becomes the record name
   * - 0x48
     - guid
     - GUID (``bytes_le``)
   * - 0x4D
     - date
     - Cocoa time as f64; property 0x0004 is the record's modification time
   * - 0x08, 0x0D, 0x20
     - binary, object, prop-index
     - hexadecimal

The path gives the record kind and folder number: ``Data/<Kind>/<number>/<UUID>.olk15<Kind>``.

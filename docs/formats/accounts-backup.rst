Account backup (``AccountsBackup.bhxd``)
========================================

``AccountsBackup.bhxd`` uses the same ``Nostromoi`` container as the store (4096-byte pages,
512-byte slots, 32-byte slot headers), but its records are mostly **uncompressed** key/value
lists. This layout was decoded by this project.

Slot header
-----------

.. list-table::
   :header-rows: 1
   :widths: 12 12 76

   * - Offset
     - Type
     - Meaning
   * - 0x00
     - 8 bytes
     - Record hash (``account_backup.record_hash``)
   * - 0x08
     - 8 bytes
     - Store identifier (the most common non-zero value is used)
   * - 0x10
     - u32
     - Byte length of the UTF-16 **section name** (1–255)
   * - 0x14
     - u32
     - Record size ``size_a``
   * - 0x18
     - u32
     - Record size ``size_b``; equal to ``size_a`` when the record is uncompressed
   * - 0x1C
     - u32
     - 0

When the two sizes differ, the payload after its first 8 bytes is an LZ4 block and is
decompressed first.

Payload
-------

.. code-block:: text

   section name   UTF-16, name_len bytes (from the slot header)
   u64            unknown
   u32            entry count
   entry * count:
       u32        name byte length (including the UTF-16 NUL)
       UTF-16     property name, NUL-terminated
       u8         value type
       u32        value length
       bytes      value

.. list-table:: Value types
   :header-rows: 1
   :widths: 12 18 70

   * - Type
     - Name
     - Decoding
   * - 1
     - string
     - UTF-16, trailing NUL removed
   * - 2, 4
     - u32
     - integer
   * - 7
     - bool
     - one byte
   * - 8
     - u64
     - integer; if it is a plausible .NET-ticks value the UTC time is appended
   * - 9
     - empty
     - no value
   * - 12
     - binary
     - hexadecimal

Other lengths are decoded as little-endian integers (1, 2, 4 or 8 bytes) or hexadecimal.
Property names are mostly numeric HxCore identifiers whose meaning is not documented.

Records continue across slots: after a record, decoding resumes at the next 512-byte boundary
after ``32 + size_a`` bytes.

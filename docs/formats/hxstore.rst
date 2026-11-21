HxCore object store (``HxStore.hxd``)
=====================================

``HxStore.hxd`` is the main database of the new Outlook. It is decoded with the bundled
hxstore-decode library (``tools/hxstore-decode/src``, MIT licence), whose ``HXSTORE.md`` documents
the format in detail. This page summarizes what ``olk_forensic`` relies on and what it adds.

Container
---------

* Magic ``Nostromoi`` at offset 0; 4096-byte **pages**; page 0 is the header.
* A data page holds eight 512-byte **slots**. Each slot starts with a 32-byte header:

  .. list-table::
     :header-rows: 1
     :widths: 12 10 78

     * - Offset
       - Type
       - Meaning
     * - 0x00
       - u64
       - Hash (lookup key)
     * - 0x08
       - 8 bytes
       - Store identifier (matches the primary store ID)
     * - 0x10
       - u32
       - Record type (``8`` for data records)
     * - 0x14
       - u32
       - ``size_a``: stored record size
     * - 0x18
       - u32
       - ``size_b``: decompressed payload size
     * - 0x1C
       - u32
       - Unknown

* The record data that follows is an 8-byte **record identifier** and a raw LZ4 block. Records
  larger than one slot continue into the following slots.

Versions
--------

A record identifier can occur several times in the file. ``olk_forensic`` keeps **every**
occurrence as a separate version (``store_records.version``, numbered in file order, with
``versions`` = total count), with its page, file offset, sizes, decompressed payload and
SHA-256. Older versions can reveal earlier states of an object, for example a message list
before entries were added. All versions are exported to ``export/records/``.

Record header and object types
------------------------------

Records whose decompressed payload starts with a zero u32 have a 64-byte header. The tool
reads the object's own identifier at offset 20 (u32) and the **object type** at offset 44
(u16):

.. list-table::
   :header-rows: 1
   :widths: 15 85

   * - Type
     - Meaning
   * - 73
     - Account
   * - 77
     - View / folder
   * - 104, 107
     - Calendar, appointment
   * - 191, 201
     - Message header
   * - 202
     - Data replication
   * - 212
     - Attachment header
   * - 224, 359
     - Contact, person
   * - 288
     - Search session

The first u32 of the stored record (``raw_format``) identifies the record format family, for
example ``0x3B0`` (e-mail record), ``0x10013`` (object record), ``0x191`` (e-mail summary),
``0x30FF1``/``0x310F4`` (rich e-mail record), ``0x1A0`` (entity record).

Extracted fields
----------------

For each version the tool stores all UTF-16 strings (``store_strings``), e-mail addresses,
Message-IDs, timestamps, and, through the hxstore-decode heuristics, sender, subject, display
time and folder. A record is treated as an e-mail if its strings contain ``IPM.Note``.

Attachment references are strings of the form ``~/Files/S0/<n>/Attachments/<name>[<N>].<ext>``;
the string before it is taken as the display name. Body references are ``EFMData/<n>.dat``.

Decompression
-------------

Some stored blocks do not end cleanly for strict LZ4 decoders. hxstore-decode uses the
``lz4`` package when available and a lenient pure-Python decoder otherwise; the decompressed
size can differ slightly from ``size_b`` for such records. Both sizes are kept.

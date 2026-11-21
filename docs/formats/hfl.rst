HxCore trace log (``.hfl``)
===========================

``hxcore.hfl`` holds the trace log of the current session and
``hxcore_previous_session.hfl`` that of the previous one. A new file is started when the
application starts. Each file is a **ring buffer**: when it is full, the oldest chunks are
overwritten, so a log may begin well after its creation time.

Layout
------

.. code-block:: text

   0x00            file header (0x58 bytes)
   text_off        text block (NUL-separated UTF-8 strings)
   text_off+len    chunk | chunk | (gap) | chunk | ...  until end of file

File header
-----------

.. list-table::
   :header-rows: 1
   :widths: 12 10 18 60

   * - Offset
     - Size
     - Type
     - Meaning
   * - 0x00
     - 4
     - u32
     - Magic, always ``8``
   * - 0x04
     - 4
     - u32
     - Version, ``0x00010000``
   * - 0x08
     - 8
     - u64
     - Creation time :math:`T_c` in .NET ticks (wall clock, UTC)
   * - 0x10
     - 8
     - u64
     - Monotonic clock :math:`M_c` at creation, nanoseconds
   * - 0x18
     - 32
     - bytes
     - File identifier
   * - 0x38–0x4C
     -
     - u32
     - Further fields, recorded but not interpreted
   * - 0x50
     - 4
     - u32
     - Text block offset (≥ 0x58)
   * - 0x54
     - 4
     - u32
     - Text block length

The **text block** contains NUL-separated UTF-8 strings. The first is the Office build (for
example ``16.0.20622.33801``); strings of the form ``key:value;key:value`` are logging settings
and are stored in ``hfl_files.settings_json``.

Chunks
------

After the text block the file is a sequence of chunks. A chunk is recognized by its length
field and the marker ``DE AD BE EF`` at offset 0x1C.

.. list-table::
   :header-rows: 1
   :widths: 12 10 78

   * - Offset
     - Type
     - Meaning
   * - 0x00
     - u32
     - Total chunk length including this header
   * - 0x04
     - u32
     - Decompressed size + 0x28
   * - 0x08
     - u32
     - Decompressed size including overflow + 0x28
   * - 0x10, 0x18
     - u32
     - Unknown
   * - 0x1C
     - 4 bytes
     - Marker ``DE AD BE EF``
   * - 0x20
     - u32
     - Offset in the logical stream
   * - 0x28
     - bytes
     - Raw LZ4 block (no frame header) of length *total − 0x28*

Bytes between chunks that do not start a valid chunk are a **gap** (typically the remains of an
overwritten chunk). The decoder searches for the next marker and records each gap's offset and
length (``hfl_files.gaps``, ``gap_bytes``).

Records
-------

A decompressed chunk is a sequence of records, each with a 0x28-byte header:

.. list-table::
   :header-rows: 1
   :widths: 12 10 14 64

   * - Offset
     - Size
     - Type
     - Meaning
   * - 0x00
     - 16
     - GUID
     - Activity identifier (all zero = none)
   * - 0x10
     - 8
     - u64
     - Monotonic stamp :math:`s`, nanoseconds
   * - 0x18
     - 4
     - u32
     - Thread identifier
   * - 0x1C
     - 4
     - u32
     - Number of arguments
   * - 0x20
     - 2
     - u16
     - Record length including header
   * - 0x22
     - 2
     - u16
     - Offset of the first argument (0x28)
   * - 0x24
     - 2
     - u16
     - Event number
   * - 0x26
     - 1
     - u8
     - Level: 1 CRIT, 2 ERROR, 3 WARN, 4 INFO, 5 VERB
   * - 0x27
     - 1
     - u8
     - Area

The **event key** is ``area.event`` (for example ``4.1011``). Event names are not stored in the
file; the tool labels events automatically from constant string arguments and the 5-character
log-site tags that many events carry.

Typed arguments
---------------

Arguments follow the header as type-length-value items:

.. list-table::
   :header-rows: 1
   :widths: 10 14 26 10 40

   * - Code
     - Type
     - Encoding
     - Sig.
     - Typical use
   * - 0x01
     - str8
     - u32 byte count + UTF-8
     - ``s``
     - names, tags
   * - 0x02
     - str16
     - u32 character count + UTF-16
     - ``S``
     - names, hex object IDs, hashed values
   * - 0x03
     - i32
     - 4 bytes
     - ``i``
     - HRESULTs, counts
   * - 0x04
     - u64
     - 8 bytes
     - ``Q``
     - object IDs, times
   * - 0x05
     - u32
     - 4 bytes
     - ``I``
     - counts, line numbers
   * - 0x06
     - bool
     - 1 byte
     - ``?``
     - flags
   * - 0x07
     - f64
     - 8 bytes
     - ``d``
     - durations
   * - 0x08
     - GUID
     - 16 bytes
     - ``G``
     - identifiers
   * - 0x0C
     - bytes
     - u32 count + bytes
     - ``b``
     - binary blobs
   * - 0x13
     - u8
     - 1 byte
     - ``B``
     - small enums
   * - 0x15
     - u16
     - 2 bytes
     - ``H``
     - small enums
   * - 0x16
     - i64
     - 8 bytes
     - ``q``
     - signed values

The **signature** of a record is the concatenation of its type letters (for example ``SSI``).
Every event key was observed with exactly one signature, which is the basis of
well-formedness check W4 (:doc:`../forensics/validation`).

The tool interprets argument values where possible: 16-character hexadecimal strings as
little-endian object identifiers, integers that fall into plausible FILETIME, .NET-ticks or
Unix-millisecond ranges as dates, known HRESULT codes by name, and values beginning with
``pii:`` as client-side hashes of personal data.

Time conversion
---------------

The header pairs a wall-clock time with the monotonic clock, which gives the wall-clock time
of the monotonic zero point. A record's UTC time in nanoseconds since the Unix epoch is

.. math::

   t_{\text{UTC}} = (T_c - 621\,355\,968\,000\,000\,000)\cdot 100 - M_c + s

For example, with :math:`T_c` = 2025-11-10 22:57:40 UTC and :math:`M_c` = 3 s, a record with
:math:`s` = 6.335 s is at 22:57:43.335 UTC. The derived zero point is stored as
``hfl_files.monotonic_zero_utc``.

Annotated example
-----------------

A real error record (event ``4.1011``) with no personal content:

.. code-block:: text

   0000 44 e6 8b dc 47 90 40 7e a8 44 5b 0a 09 5c e2 25  activity GUID
   0010 38 b9 7b 39 7e df 00 00                          stamp s (ns)
   0018 98 12 00 00                                      thread 4760
   001c 09 00 00 00                                      n = 9 arguments
   0020 68 00 | 28 00 | f3 03 | 02 | 04                  length 104, arg offset 0x28, event 1011,
                                                         ERROR, area 4
   0028 16 19 6d 4f 00 00 00 00 00                       i64  0x4F6D19 (object id)
   0031 02 04 00 00 00 73 00 79 00 6e 00 63 00           str16 "sync"
   003e 05 ad 00 00 00                                   u32  173
   0043 13 02                                            u8   2
   0045 03 00 00 00 00                                   i32  0
   004a 05 9d 74 00 00                                   u32  29853
   004f 05 06 00 00 00                                   u32  6
   0054 16 00 00 00 00 00 00 00 00                       i64  0
   005d 01 05 00 00 00 62 65 32 78 6b                    str8 "be2xk" (log-site tag)
   0067 00                                               padding

Decoding with ``hfl_parse.py``
------------------------------

``tools/hfl_parse.py`` decodes one trace log on its own with more options
(catalog, JSONL, search by object ID, store cross-reference). ``olk_forensic.py`` imports its
functions. Run ``python3 tools/hfl_parse.py -h`` for its options.

Format overview
===============

This part documents the on-disk layouts that the tool decodes. Unless stated otherwise all
integers are **little-endian**, offsets are hexadecimal, and "UTF-16" means UTF-16LE without
a byte-order mark.

.. list-table::
   :header-rows: 1
   :widths: 28 22 50

   * - Artifact
     - Magic / signature
     - Summary
   * - Trace log (``.hfl``)
     - u32 ``8`` at 0x00, version ``0x00010000``
     - Header with clocks and a text block, then LZ4 chunks marked ``DE AD BE EF`` holding
       records with typed arguments. :doc:`hfl`
   * - Object store (``HxStore.hxd``)
     - ``Nostromoi``
     - 4096-byte pages of eight 512-byte slots; records are an 8-byte ID plus an LZ4 block.
       :doc:`hxstore`
   * - Account backup (``.bhxd``)
     - ``Nostromoi``
     - Same container; uncompressed key/value records. :doc:`accounts-backup`
   * - Osa API logs (``.xmlgz``)
     - gzip
     - One gzip-compressed XML document per request or response; meaning carried by the
       file and folder names. :doc:`osa`
   * - olk15 records
     - ``D0 0D 00 00``
     - Property table of the legacy Outlook 2016 record files. :doc:`olk15`
   * - Lock table (``HxStore.lock``)
     - ``EF BE AD DE``
     - Fixed-size entries with process ID and .NET-ticks time. :doc:`small-binaries`
   * - Caches (``Files/S0/...``)
     - file names
     - Attachment, body and photo caches whose names carry reference numbers and
       timestamps. :doc:`caches`

Clocks
------

.. list-table::
   :header-rows: 1
   :widths: 22 30 48

   * - Clock
     - Epoch / unit
     - Where
   * - .NET ticks
     - 0001-01-01, 100 ns
     - ``.hfl`` header, lock table, photo file names, account backup u64 values
   * - Monotonic stamp
     - since boot, ns
     - ``.hfl`` records (converted with the header, see :doc:`hfl`)
   * - Unix seconds
     - 1970-01-01, s
     - Osa folder name (8 hex digits), telemetry
   * - ISO 8601
     - text, UTC
     - Osa XML (``LogTime``, ``SendTime``, ...)
   * - Cocoa
     - 2001-01-01, s (double)
     - olk15 dates, NSKeyedArchiver ``NS.time``

Conversions used by the tool:

.. math::

   t_{\text{unix}} = (\text{ticks} - 621\,355\,968\,000\,000\,000) / 10^7 \;\text{s}
   \qquad
   t_{\text{unix}} = t_{\text{cocoa}} + 978\,307\,200 \;\text{s}

A .NET-ticks value is accepted as a date only between :math:`5\cdot10^{17}` and
:math:`7\cdot10^{17}` (years 1585–2219); Cocoa values only between :math:`-10^9` and
:math:`2\cdot10^9` seconds.

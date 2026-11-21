Parsed artifacts
================

Every file in the profile is first **inventoried**: relative path, size, modification and
birth time, permissions, MD5, SHA-256, the first 16 bytes and a detected type. Then each file
is passed to the decoder for its category. Files without a dedicated decoder are still
hashed, typed and reduced to their readable strings, so the coverage is total.

.. list-table::
   :header-rows: 1
   :widths: 32 48 20

   * - Artifact
     - What is extracted
     - Format page
   * - ``hxcore.hfl``, ``hxcore_previous_session.hfl``
     - Every trace record with UTC time, thread, activity, event key, level and decoded
       arguments; event catalog with automatic labels; hourly counts; object identifiers and
       their activity
     - :doc:`../formats/hfl`
   * - ``HxStore.hxd``
     - Every record **version**: identifier, type, format, sizes, offset, sender, subject,
       display time, e-mail addresses, Message-IDs, folder, all UTF-16 strings, decompressed
       payload and its SHA-256; attachment references; message bodies
     - :doc:`../formats/hxstore`
   * - ``AccountsBackup.bhxd``
     - Account settings as typed key/value pairs per section
     - :doc:`../formats/accounts-backup`
   * - ``Osa/**/*.xmlgz``
     - One row per API log: session, sequence, account, channel, command, request ID,
       request/response, times, duration, status, servers, client version, app state, user
       agent; every XML leaf as a path/value pair; full XML
     - :doc:`../formats/osa`
   * - ``Data/*.sqlite`` (+ ``-wal``)
     - Legacy Outlook 2016 tables copied into ``legacy_*`` tables with the WAL applied;
       WAL header summary
     - :doc:`../formats/olk15`
   * - ``Data/**/*.olk15*``
     - Legacy record files (categories, folders, signatures, saved searches, contacts) with
       all properties and dates
     - :doc:`../formats/olk15`
   * - ``ProfilePreferences.plist``, ``clientConfigsForAM.dat``
     - Property lists, NSKeyedArchiver archives and nested binary plists, flattened into key
       paths
     - :doc:`../formats/small-binaries`
   * - ``Files/S0/*/Attachments/``
     - Cached attachments: name, reference number, hash, type, owning store records
     - :doc:`../formats/caches`
   * - ``Files/S0/*/EFMData/``
     - Cached message bodies (HTML, plain or gzip), linked to store records
     - :doc:`../formats/caches`
   * - ``Files/S0/*/Photos/``, ``AadLogos/``
     - Contact photos (timestamp decoded from the file name, image size) and tenant logos
     - :doc:`../formats/caches`
   * - ``Omc/**``
     - Outlook.com connector configuration (XML, text, binary with readable names)
     - :doc:`../formats/small-binaries`
   * - ``HxStore.lock``
     - Lock table entries: process ID, counter, .NET-ticks timestamp, slot
     - :doc:`../formats/small-binaries`
   * - ``ExternalCounters.ctr``, ``TelemetryStorage/*.bin``, ``FileSystemLoggingCache.log``,
       ``rss/*.rep``, ``nls/``, ``PreferencesSearchIndex/``
     - Decoded header fields where the layout is known, plus readable strings
     - :doc:`../formats/small-binaries`

File categories
---------------

The *Inventory* page and the ``files.category`` column group files by path:

.. list-table::
   :header-rows: 1

   * - Path rule
     - Category
   * - ``*.hfl``
     - HxCore trace log
   * - ``*.hxd``
     - HxCore store
   * - ``*.bhxd``
     - Accounts backup
   * - ``Osa/OsaPinnedLogs/...``
     - Osa pinned logs
   * - ``Osa/...``
     - Osa API logs
   * - ``.../Attachments/...``
     - Attachment cache
   * - ``.../EFMData/...``
     - Message bodies (EFMData)
   * - ``.../Photos/...``, ``.../AadLogos/...``
     - Contact photos, Tenant logos
   * - ``Files/...`` (other)
     - Files (other)
   * - ``*.olk15*``
     - Legacy olk15 records
   * - ``Data/*.sqlite*``, ``Data/...``
     - Legacy SQLite, Legacy data (other)
   * - ``Omc/...``, ``rss/...``, ``TelemetryStorage/...``
     - Outlook.com connector, Replication state, Telemetry
   * - ``*.plist``, ``*.dat``
     - Preferences / config
   * - anything else
     - Other

Type detection
--------------

``files.detected_type`` comes from the leading bytes (``Nostromoi``, ``bplist00``,
``SQLite format 3``, gzip, PNG, JPEG, PDF, ZIP, the olk15 magic ``D0 0D 00 00``, the lock
magic ``EF BE AD DE``, ``XENO``, ...), with fallbacks for ``.hfl`` files, HTML, RFC 822 e-mail
and plain text.

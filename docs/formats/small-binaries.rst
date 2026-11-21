Other artifacts
===============

Every remaining file is stored in ``binary_artifacts`` with the name of the decoder used, the
decoded fields as JSON, and up to 60 readable strings.

Store lock table (``HxStore.lock``)
-----------------------------------

.. list-table::
   :header-rows: 1
   :widths: 14 86

   * - Offset
     - Meaning
   * - 0x00
     - Magic ``EF BE AD DE`` (``DEADBEEF`` little-endian)
   * - 0x04
     - Three u32 header values
   * - 0x10
     - Entries of 0x28 bytes until the end of the file

Each entry: u64 process ID, 8-byte token, u64 counter, u64 time in .NET ticks, u32 unknown,
u32 slot. Entries with zero process ID and zero time are skipped. Each entry's time is put on
the timeline as *store lock entry*; it typically lies within a fraction of a second of the
application start.

External counters (``ExternalCounters.ctr``)
--------------------------------------------

Magic ``XENO`` followed by u32 counter values.

File-system logging cache (``FileSystemLoggingCache.log``)
----------------------------------------------------------

u32 version, u32 value, then u32 entries; the tool reports the number of entries and the most
frequent values.

Telemetry (``TelemetryStorage/``)
---------------------------------

``FileSystemStatisticsTelemetry.bin``: u32 version, u32 Unix time (put on the timeline), then
u64 statistics. ``MigrationTelemetry.bin``: non-zero u32 values with their offsets.

Replication state (``rss/*.rep``)
---------------------------------

Magic ``Nostromo`` (not ``Nostromoi``): eight u32 header values and the list of non-empty
4096-byte pages.

Index files (``PreferencesSearchIndex/`` and others)
----------------------------------------------------

Files starting with ``Bud2``, or with ``Bud1`` at offset 4, use a buddy-allocator layout similar
to ``.DS_Store``; the tool lists the UTF-16BE names they contain.

Property lists
--------------

``ProfilePreferences.plist``, ``clientConfigsForAM.dat`` and any other file starting with
``bplist00`` or named ``*.plist`` are loaded with ``plistlib``. NSKeyedArchiver archives are
unarchived (``NS.keys``/``NS.objects`` dictionaries, arrays, ``NS.string``, ``NS.time`` as Cocoa
time, ``NS.bytes``; reference cycles are marked ``<cycle>``). Binary values that are themselves
binary plists are decoded recursively. Every value is stored in ``plist_values`` under its key
path, for example ``/DefaultAccountIdentifier`` or ``/root/items[0]/name``.

Connector configuration (``Omc/``)
----------------------------------

XML and text files are stored as text in ``config_files``. Binary configuration files are stored
as hexadecimal and strings, with the readable names they contain.

Other
-----

``nls/SortDefault.nls`` is an Office collation table, not user data. ``.schema_version`` files
contain a version string.

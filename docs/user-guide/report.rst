HTML report
===========

The report is split into a short main page and one page per section, so that no single page
becomes too long to open.

Main page
---------

``report.html`` shows the tool version, the profile path, the generation time and the time
zone used, a summary with key numbers (files, store records, e-mails, trace records, API logs,
attachments, timeline events) and a **menu** of cards, one per section. Clicking a card opens
the section page.

Section pages
-------------

Every section page in ``report/`` has the same navigation bar (Home plus all sections, with the
current one highlighted), a link back to the main page, and *previous* / *next* links at the
bottom. Large tables have a filter box that hides non-matching rows as you type.

.. list-table::
   :header-rows: 1
   :widths: 20 80

   * - Page
     - Content
   * - Findings
     - Warnings and notable observations generated from the data (acquisition problems,
       default account, client user agent, back-end servers, non-success API responses,
       missing or unreferenced attachments, objects with several stored versions, trace-log
       coverage)
   * - Inventory
     - Every file with category, size, times, MD5, SHA-256, detected type, parser and status
   * - Account & config
     - Preferences, account backup values, connector configuration
   * - Timeline
     - All timestamps found inside the artifacts, merged, with a stacked per-day chart by
       source
   * - HxStore
     - Store pages, record types and formats, folders, objects with several versions
   * - E-mail
     - Messages in the store with sender, subject, time and folder; the *Body* link opens the
       exported body
   * - Attachments
     - Attachment references, cached files (linked or unreferenced), cached bodies, photos;
       links open the exported copies
   * - Trace logs
     - Per-file summary, top events with labels and signatures, errors and warnings, hourly
       activity
   * - Correlation
     - Links between trace logs, store, caches and API logs
   * - Osa API logs
     - Sessions, commands, status codes, app states, servers, client versions
   * - Legacy Outlook
     - Outlook 2016 SQLite tables, WAL journals and olk15 records
   * - Other artifacts
     - Lock table, counters, telemetry, replication state, other caches
   * - Exported files
     - Clickable list of every file in ``export/``
   * - Limitations
     - What could not be decoded
   * - SQL
     - Query examples for ``profile.db``

Time zone
---------

All times are stored in UTC. ``--tz`` shifts the times shown in the report only, and the shift
is printed on every page (for example *times in UTC+7*). Regenerate the report for another
zone with ``--report-only``.

Links
-----

All links are relative, so the report works from any location, from a zip file extracted
elsewhere, or from a read-only medium. The test suite checks that every link resolves.

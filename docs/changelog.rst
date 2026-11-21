Changelog
=========

1.0 (2026)
----------

* First release.
* Whole-profile inventory with MD5 and SHA-256.
* Decoders for the HxCore trace log, HxStore (via hxstore-decode), the account backup, Osa API
  logs, legacy SQLite with WAL, olk15 records, property lists, connector configuration, caches
  and small binaries.
* Correlation of trace-log objects, store records, attachments, bodies and API logs; unified
  timeline.
* Outputs: SQLite, JSON/JSON Lines, multi-page HTML report, ``export/`` folder with SHA-256
  manifest.
* Options ``--hfl-mode``, ``--skip-hfl``, ``--rebuild``, ``--report-only``, ``--tz``.
* Unit test suite (91 tests) with synthetic artifacts.
* Fix: the last lock-table entry is decoded when it ends exactly at the end of the file.

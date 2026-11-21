Output folder
=============

.. code-block:: text

   olk_forensic_out/
   ├── report.html              main page: summary + menu of all sections
   ├── report/                  one HTML page per section
   │   ├── findings.html
   │   ├── inventory.html
   │   ├── account.html
   │   ├── timeline.html
   │   ├── store.html
   │   ├── mail.html
   │   ├── attach.html
   │   ├── hfl.html
   │   ├── corr.html
   │   ├── osa.html
   │   ├── legacy.html
   │   ├── other.html
   │   ├── exports.html
   │   ├── limits.html
   │   └── sql.html
   ├── export/
   │   ├── bodies/<record_id>_<source>.html
   │   ├── records/<record_id>_v<version>.bin
   │   ├── attachments/<record_id>_<filename>
   │   ├── attachments/unreferenced/<filename>
   │   └── manifest.csv
   ├── profile.db               SQLite database (all tables and views)
   ├── profile.json             all tables and views with at most 20,000 rows
   └── json/<table>.jsonl       larger tables, one JSON object per line

``profile.db``
   The primary result. Every decoded value is stored here with a reference to the file and
   offset it came from. See :doc:`database`.

``profile.json`` and ``json/*.jsonl``
   The same tables as JSON for tools that do not read SQLite. Tables with more than 20,000
   rows (typically ``hfl_records``, ``osa_fields``, ``store_strings``, ``timeline``) are written
   as JSON Lines in ``json/``, and ``profile.json`` lists them under ``large_tables`` with their
   row count and file. The binary columns ``payload`` and ``raw`` of ``store_records`` are
   left out of JSON (they are in ``export/records/`` and in the database); other binary
   values are written as hexadecimal strings.

``report.html`` and ``report/``
   Static HTML, no server or internet connection needed. See :doc:`report`.

``export/``
   Decoded content written out as files, with a SHA-256 manifest. See :doc:`exports`.

The whole folder can be zipped and handed over. Its size is dominated by the per-record
trace-log table; use ``--hfl-mode summary`` for a smaller result.

Quick start
===========

1. Run the tool
---------------

.. code-block:: bash

   cd /path/to/hxcore
   python3.12 -I tools/olk_forensic.py "Main Profile" --out olk_forensic_out --tz 7

``--tz 7`` shows times in the report in UTC+7. Use your own offset, or leave it out for UTC.
Times stored in the database are always UTC.

The run prints its nine stages:

.. code-block:: text

   [1/9] inventory + hashing ...
         22122 files, 298.9 MB
   [2/9] HxStore.hxd / AccountsBackup.bhxd ...
   [3/9] HFL trace logs (mode=records) ...
   [4/9] Osa API logs ...
   [5/9] legacy SQLite + olk15 ...
   [6/9] plists, configs, small binaries ...
   [7/9] attachment / body / photo caches ...
   [8/9] correlation ...
   [9/9] export files, JSON, HTML ...
   done in 208s -> olk_forensic_out

A profile of about 22,000 files and 300 MB takes three to four minutes. Most of the time is
spent decoding the trace logs record by record; ``--hfl-mode summary`` is much faster.

2. Open the report
------------------

.. code-block:: bash

   open olk_forensic_out/report.html          # macOS
   xdg-open olk_forensic_out/report.html      # Linux

The main page shows the summary and a menu; each menu card opens one section page (Findings,
Inventory, Timeline, E-mail, Attachments, Trace logs, Correlation, Osa API logs, ...). See
:doc:`../user-guide/report`.

3. Query the database
---------------------

.. code-block:: bash

   sqlite3 olk_forensic_out/profile.db

.. code-block:: sql

   -- the unified timeline around one hour (UTC)
   SELECT time_utc, source, kind, description FROM timeline
   WHERE time_utc BETWEEN '2025-11-10 22:00' AND '2025-11-10 23:00' ORDER BY time_utc;

More queries are in :doc:`../user-guide/queries`.

4. Use the exported files
-------------------------

``olk_forensic_out/export/`` holds the e-mail bodies, the decompressed store records and the
attachment copies, with ``manifest.csv`` listing the SHA-256 of each one. See
:doc:`../user-guide/exports`.

Re-running only the last stage
------------------------------

After changing the time zone or updating the tool, rebuild the outputs from the existing
database without parsing the profile again:

.. code-block:: bash

   python3.12 -I tools/olk_forensic.py --rebuild olk_forensic_out/profile.db --tz 7      # export + JSON + report
   python3.12 -I tools/olk_forensic.py --report-only olk_forensic_out/profile.db --tz 0  # report only

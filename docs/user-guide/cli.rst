Command-line reference
======================

Synopsis
--------

.. code-block:: text

   python -I tools/olk_forensic.py PROFILE [--out DIR] [--tz HOURS] [--hfl-mode records|summary] [--skip-hfl]
   python -I tools/olk_forensic.py --rebuild DB [--tz HOURS]
   python -I tools/olk_forensic.py --report-only DB [--tz HOURS]

Options
-------

.. option:: PROFILE

   The copied profile folder, for example ``"Main Profile"``. Required unless
   :option:`--rebuild` or :option:`--report-only` is given.

.. option:: --out DIR

   Output folder. Default: ``olk_forensic_out``. Existing outputs inside it
   (``profile.db``, ``export/``, ``report/``, JSON) are replaced.

.. option:: --tz HOURS

   Show report times in UTC+HOURS, for example ``7``, ``-5`` or ``5.5``. Default ``0`` (UTC).
   Only the HTML report is shifted; the database and JSON always hold UTC.

.. option:: --hfl-mode {records,summary}

   ``records`` (default) stores **every** trace-log record in ``hfl_records``.
   ``summary`` stores only errors and warnings (levels 1–3), plus the full event catalog,
   hourly counts and object activity. Summary mode is much faster and the database much
   smaller; all statistics remain complete.

.. option:: --skip-hfl

   Do not decode the ``.hfl`` trace logs at all.

.. option:: --rebuild DB

   From an existing ``profile.db``: redo ``export/``, the JSON files and the report, without
   parsing the profile again. The profile path stored in the database is used to copy
   attachments, so the profile copy must still be at that path.

.. option:: --report-only DB

   Rebuild only ``report.html`` and ``report/`` from an existing ``profile.db``.

Why ``-I``
----------

``-I`` runs Python in isolated mode: it ignores ``PYTHON*`` environment variables and does not
add the current folder to the module search path, so a stray ``json.py`` or ``sqlite3.py``
next to the evidence cannot be imported by accident. The tool also sets
``sys.dont_write_bytecode`` so that no ``__pycache__`` folder is created.

Exit status
-----------

``0`` on success. ``2`` for a usage error (for example a missing ``PROFILE``). A message such
as ``error: ... is not a folder`` and a non-zero status if the profile path is wrong.
Individual files that cannot be decoded do **not** stop the run; they are marked in the
``files`` table (``parse_status``) and on the *Inventory* page.

Examples
--------

.. code-block:: bash

   # full run, report in UTC+7
   python3.12 -I tools/olk_forensic.py "Main Profile" --out case42 --tz 7

   # quick triage: trace-log errors and warnings only
   python3.12 -I tools/olk_forensic.py "Main Profile" --out triage --hfl-mode summary

   # everything except the trace logs
   python3.12 -I tools/olk_forensic.py "Main Profile" --out notrace --skip-hfl

   # report in New York time from an earlier run
   python3.12 -I tools/olk_forensic.py --report-only case42/profile.db --tz -5

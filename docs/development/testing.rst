Testing
=======

The unit tests are in ``tests/``. They use only the standard library (``unittest``) and build
small synthetic artifacts with ``tests/synth.py``, so they need no evidence and no network.

Running the tests
-----------------

.. code-block:: bash

   python3.12 -B -m unittest discover -s tests -v      # about 1 s
   python3.12 -B -m pytest tests -q                    # same tests, if pytest is installed

``-B`` prevents ``__pycache__`` folders. Do not use ``-I`` here: it ignores
``PYTHONDONTWRITEBYTECODE``.

Expected result: ``Ran 91 tests ... OK (skipped=2)``.

What is covered
---------------

.. list-table::
   :header-rows: 1
   :widths: 25 75

   * - Test class
     - Checks
   * - ``Helpers``, ``Classification``
     - Time conversions, hashing, strings, safe names, status set, type detection, categories,
       file-name patterns
   * - ``Lz4Block``, ``DecodeArgs``, ``HflHeaderAndChunks``
     - LZ4 literals and matches (overlapping, extended), malformed blocks, every argument type,
       error reporting, record iteration, header clock model, chunk tiling and gaps
   * - ``ParseHfl``
     - Full synthetic trace log in records and summary mode: times to the millisecond, events,
       signatures, object activity, hourly counts, timeline, gaps, evidence unchanged
   * - ``AccountBackup``
     - Every value type, truncated records
   * - ``OsaLogs``
     - Field extraction, duration, success statuses, failures on the timeline, malformed XML,
       unreadable files, pinned logs
   * - ``Olk15``, ``Plists``
     - Property types, names, dates, truncation; NSKeyedArchiver, cycles, nested plists, depth
       limit
   * - ``LegacySqlite``
     - Rows that exist only in the WAL are read, evidence unchanged, no ``-shm`` created;
       unreadable databases
   * - ``SmallBinaries``, ``ConfigFiles``, ``FilesArea``
     - Lock table (including an entry ending at end of file), counters, telemetry, replication
       state; connector configuration; attachment links, bodies, photos
   * - ``Database``, ``Inventory``
     - Schema and views, buffered inserts, acquisition warning
   * - ``CorrelationAndFindings``
     - Object coverage, missing files, trace/API overlap, findings exclude success statuses
   * - ``ExportContent``, ``ExportJson``
     - File names, collisions, escaping, manifest hashes, re-runs; JSON splitting and excluded
       columns
   * - ``HtmlReport``
     - Table cells, time-zone shift, page splitting, navigation, all links resolve
   * - ``EndToEnd``
     - Full run on a synthetic profile: evidence unchanged (hash, size, mtime), every file
       inventoried, decoded tables, three-clock session corroboration, outputs, report links,
       ``--report-only`` and ``--rebuild``
   * - ``Cli``
     - Help, usage errors, no bytecode written
   * - ``RealProfile`` (optional)
     - HxStore decoding and W1–W4 on a real profile

Tests against a real profile
----------------------------

.. code-block:: bash

   OLK_PROFILE="Main Profile" python3.12 -B -m unittest discover -s tests -k RealProfile -v

These tests only read the profile. They take about 30 seconds.

Building the documentation
--------------------------

.. code-block:: bash

   python3.12 -m venv .docenv
   .docenv/bin/pip install -r docs/requirements.txt
   .docenv/bin/sphinx-build -W -b html docs docs/_build/html
   open docs/_build/html/index.html

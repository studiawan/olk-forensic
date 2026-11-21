Related tools
=============

These scripts are in ``tools/``, next to ``olk_forensic.py``.

.. list-table::
   :header-rows: 1
   :widths: 25 75

   * - Tool
     - Purpose
   * - ``hfl_parse.py``
     - Stand-alone, in-depth decoder for one ``.hfl`` file. Options include ``--sqlite``,
       ``--jsonl``, ``--timeline``, ``--catalog``, ``--find-id`` and ``--hxstore-extract``.
       Run ``python3 tools/hfl_parse.py -h``.
   * - ``hfl_report.py``
     - HTML report for a database written by ``hfl_parse.py --sqlite``.
   * - ``hxstore_export.py``
     - Exports ``HxStore.hxd`` objects to JSON for ``hfl_parse.py --hxstore-extract``.
   * - ``hxstore-decode/``
     - Library and command-line tool for ``HxStore.hxd`` (MIT licence); its ``HXSTORE.md``
       documents the store format.

Troubleshooting
===============

.. list-table::
   :header-rows: 1
   :widths: 40 60

   * - Problem
     - Fix
   * - ``SyntaxError`` or ``TypeError ... slots`` when HxStore is parsed
     - Use Python 3.10 or newer (``python3 --version``).
   * - Findings say *HxStore.hxd not decoded*
     - Check that ``tools/hxstore-decode/src/hxdecode/`` exists next to ``tools/olk_forensic.py`` and that
       you use Python 3.10+. The warning text names the import error.
   * - The HxStore stage is slow
     - Install ``lz4`` in the Python you run the tool with (``pip install lz4``).
   * - Every file time in the inventory is the same
     - The profile was copied without preserving times. Re-acquire with ``ditto`` or
       ``cp -Rp`` (:doc:`getting-started/acquisition`).
   * - The output folder is very large
     - Use ``--hfl-mode summary``. Most of the size is the per-record trace-log table and its
       JSON Lines file.
   * - *Permission denied* on the live profile
     - Copy the profile first. Terminal may need Full Disk Access.
   * - ``--rebuild`` exports no attachments
     - The attachment copies are taken from the profile path stored in ``profile.db``
       (``SELECT value FROM meta WHERE key='profile_path'``). Restore the profile copy at that
       path.
   * - A file shows status ``error`` or ``unparsed``
     - The run continues; the reason is in ``files.notes`` and on the *Inventory* page. Please
       report the file's category and size (not its content) as an issue.
   * - The report shows times in the wrong zone
     - Regenerate it: ``python3 -I tools/olk_forensic.py --report-only out/profile.db --tz <hours>``.

Forensic soundness
==================

The tool is designed so that its results can be reproduced, verified and traced back to the
evidence. It follows four requirements.

R1 — Evidence is not modified
-----------------------------

* Every input file is opened read-only.
* SQLite databases are copied, with their ``-wal`` and ``-shm`` files, to a temporary folder
  before they are opened, because SQLite would otherwise write a ``-shm`` file or checkpoint the
  WAL next to the evidence. The temporary folder is deleted afterwards.
* No ``__pycache__`` folder is written (``sys.dont_write_bytecode``), and ``-I`` keeps Python
  from importing modules from the evidence folder.
* All output goes to the ``--out`` folder.

The end-to-end test compares the SHA-256, size and modification time of every input file
before and after a full run (:doc:`../development/testing`).

R2 — Every value has a provenance
---------------------------------

Every decoded row names the file it came from and, where applicable, its position: chunk
index and offset for trace records, page and file offset for store records, slot offset for
account values, the log ID for API fields, and the property ID for olk15 values. The
``files`` table records the MD5 and SHA-256 of every input, so a row can be tied to a hashed
file.

R3 — Decoding is checkable
--------------------------

Undocumented formats cannot be checked against a specification. The trace-log decoder therefore
checks structural properties that only a correct decoding satisfies (W1–W4, see
:doc:`validation`), and records gaps, decoding failures and size mismatches instead of hiding
them. Store records whose decompressed size differs from the declared size are kept with both
sizes.

R4 — Interpretation is separated from decoding
----------------------------------------------

Decoded values (bytes, integers, strings, times) are stored as found. Interpretations — event
labels, sender and subject heuristics, folder names, "possible remnant of a deleted message" —
are stored in separate columns or described as such in the report, so that the examiner can
weigh them.

Certainty of derived statements
-------------------------------

When writing up results, the following scale (after Casey, 2002) is useful for statements
derived from the tool's output:

.. list-table::
   :header-rows: 1
   :widths: 10 90

   * - Level
     - Basis
   * - C1
     - A single heuristic interpretation (for example an automatic event label)
   * - C2
     - A decoded value from one artifact (for example a time in one log)
   * - C3
     - Values from one artifact that are internally consistent (for example a well-formed
       trace log whose records agree)
   * - C4
     - Agreement of independent artifacts with independent clocks (for example a session start
       seen by the API logs, the trace log and the lock table within a fraction of a second)

Hashes and outputs
------------------

* ``files.md5`` and ``files.sha256``: every input file.
* ``store_records.payload_sha256``: every decompressed store record version.
* ``export/manifest.csv`` and ``export_files``: every exported file.
* ``hfl_files.sha256``, ``store_info.sha256``: the trace logs and the store.

Recommended workflow
--------------------

1. Acquire the profile with timestamps preserved (:doc:`../getting-started/acquisition`) and
   hash it.
2. Run the tool on the copy; keep the console output with the case notes.
3. Verify the export manifest.
4. Keep ``profile.db``: every report page and export can be regenerated from it with
   ``--rebuild``.
5. Confirm important findings in the raw artifact at the recorded offset.

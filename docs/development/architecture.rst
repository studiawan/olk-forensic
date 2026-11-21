Architecture
============

``olk_forensic.py`` is a single file that uses ``hfl_parse.py`` (trace-log primitives) and the
``hxdecode`` package from ``tools/hxstore-decode/src`` (store decoding). Everything else is the
Python standard library.

Processing stages
-----------------

.. code-block:: text

   profile copy (read only)
        │
   [1] inventory ── hashes, type detection, categories ──────────────┐
        │                                                            │
   [2] HxStore.hxd, AccountsBackup.bhxd                              │
   [3] trace logs (.hfl) ── uses store IDs to recognize objects      │
   [4] Osa API logs                                                  │  profile.db
   [5] legacy SQLite (temporary copy) + olk15 records                ├─ (DB class,
   [6] plists, configs, small binaries                               │   buffered
   [7] attachment / body / photo caches ── uses store references     │   inserts)
        │                                                            │
   [8] correlation + findings ───────────────────────────────────────┘
        │
   [9] export_content → export/      export_json → JSON      build_report → HTML

The store is decoded before the trace logs so that store record IDs can be used to recognize
object identifiers in trace-log arguments, and before the caches so that cached files can be
linked to the records that reference them.

Main functions
--------------

.. list-table::
   :header-rows: 1
   :widths: 30 70

   * - Function
     - Role
   * - ``run``
     - Orchestrates stages 1–9 for a profile
   * - ``inventory``
     - Walks the profile, hashes and classifies every file
   * - ``store_parse``
     - Decodes every HxStore record version, attachments and bodies
   * - ``parse_account_backup`` / ``decode_kv``
     - Account backup slots and key/value records
   * - ``parse_hfl``
     - Two-pass trace-log decoder (object ID discovery, then records)
   * - ``parse_osa``
     - API logs
   * - ``parse_legacy_sqlite``, ``parse_olk15``
     - Legacy data
   * - ``parse_plist``, ``parse_config``, ``parse_small``
     - Property lists, connector configuration, small binaries
   * - ``parse_files_area``
     - Attachment, body and photo caches
   * - ``correlate``, ``findings``
     - Cross-artifact links and findings
   * - ``export_content``, ``export_json``
     - File export with manifest; JSON
   * - ``build_report``, ``write_pages``
     - HTML report, split into a main page and section pages

Adding a decoder
----------------

1. Add a table to ``SCHEMA`` (and a view to ``VIEWS`` if useful). Include the source path and a
   position column so that every row has a provenance.
2. Write ``parse_<artifact>(f, db)`` that reads ``f["full"]``, adds rows with ``db.add`` and
   timestamps with ``db.tl(time_utc, source, artifact, kind, description, ref)``.
3. Call it from ``run`` and set ``status[path]`` so that the inventory shows the parser.
4. Add a report section in ``build_report`` as ``<h2 id="name">`` and an entry in
   ``SECTION_INFO``; ``write_pages`` turns it into ``report/name.html`` automatically.
5. Add a synthetic builder to ``tests/synth.py`` and tests to ``tests/test_olk_forensic.py``.
6. Regenerate the database reference of this documentation (the column lists are taken from
   ``SCHEMA``).

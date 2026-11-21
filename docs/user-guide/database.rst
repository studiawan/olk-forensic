Database reference
==================

.. This page is generated from the SCHEMA and VIEWS constants in olk_forensic.py.

``profile.db`` is an ordinary SQLite 3 database. All times are UTC text in the form
``YYYY-MM-DD HH:MM:SS.fff``. Unsigned 64-bit identifiers above 2\ :sup:`63` are stored as
negative signed integers (SQLite has no unsigned type).

Besides the tables below, each legacy SQLite table with rows is copied as
``legacy_<database>_<table>`` with its original columns.

Run and inventory
-----------------

``meta``
^^^^^^^^

Run information: tool version, profile path, start time, Python version, trace-log mode, run time, file-system time range.

.. code-block:: text

   key                      TEXT
   value                    TEXT

``files``
^^^^^^^^^

Inventory of every file in the profile, with hashes, detected type, the parser used and its status.

.. code-block:: text

   id                       INTEGER
   path                     TEXT
   category                 TEXT
   size                     INTEGER
   mtime_utc                TEXT
   birthtime_utc            TEXT
   mode                     TEXT
   md5                      TEXT
   sha256                   TEXT
   magic_hex                TEXT
   detected_type            TEXT
   parser                   TEXT
   parse_status             TEXT
   notes                    TEXT

``findings``
^^^^^^^^^^^^

Generated findings (severity ``warning``, ``notice`` or ``info``).

.. code-block:: text

   severity                 TEXT
   area                     TEXT
   finding                  TEXT
   detail                   TEXT

``correlations``
^^^^^^^^^^^^^^^^

Cross-artifact links and summaries (see :doc:`correlation`).

.. code-block:: text

   kind                     TEXT
   left_ref                 TEXT
   right_ref                TEXT
   status                   TEXT
   detail                   TEXT

``timeline``
^^^^^^^^^^^^

Unified UTC timeline of every timestamp found inside the artifacts. ``ref`` points to the record (for example ``osa_logs.id=17`` or ``chunk:0xoffset``).

.. code-block:: text

   time_utc                 TEXT
   source                   TEXT
   artifact                 TEXT
   kind                     TEXT
   description              TEXT
   ref                      TEXT

Trace logs
----------

``hfl_files``
^^^^^^^^^^^^^

One row per trace log: header fields, coverage, chunk and gap counts, record, error and warning counts.

.. code-block:: text

   file                     TEXT
   size                     INTEGER
   sha256                   TEXT
   office_build             TEXT
   created_utc              TEXT
   monotonic_zero_utc       TEXT
   first_utc                TEXT
   last_utc                 TEXT
   chunks                   INTEGER
   gaps                     INTEGER
   gap_bytes                INTEGER
   records                  INTEGER
   errors                   INTEGER
   warnings                 INTEGER
   threads                  INTEGER
   activities               INTEGER
   events                   INTEGER
   mode                     TEXT
   header_json              TEXT
   settings_json            TEXT

``hfl_records``
^^^^^^^^^^^^^^^

Trace records (all of them in ``records`` mode; levels 1–3 only in ``summary`` mode). ``chunk``/``off`` locate the record in the decompressed chunk; ``sig`` is the argument signature; ``summary`` the decoded arguments.

.. code-block:: text

   file                     TEXT
   chunk                    INTEGER
   off                      INTEGER
   time_utc                 TEXT
   stamp_ns                 INTEGER
   thread                   INTEGER
   activity                 TEXT
   ekey                     TEXT
   level                    INTEGER
   area                     INTEGER
   sig                      TEXT
   summary                  TEXT

``hfl_events``
^^^^^^^^^^^^^^

Event catalog per trace log: count, level distribution, time range, dominant signature, automatic label and an example.

.. code-block:: text

   file                     TEXT
   ekey                     TEXT
   label                    TEXT
   count                    INTEGER
   levels                   TEXT
   first_utc                TEXT
   last_utc                 TEXT
   signature                TEXT
   example                  TEXT

``hfl_hourly``
^^^^^^^^^^^^^^

Record counts per hour (UTC) and level.

.. code-block:: text

   file                     TEXT
   hour_utc                 TEXT
   level                    INTEGER
   n                        INTEGER

``hfl_object_activity``
^^^^^^^^^^^^^^^^^^^^^^^

Per object identifier mentioned in a trace log: mentions, first/last time and record, events and object types.

.. code-block:: text

   file                     TEXT
   object_id                INTEGER
   mentions                 INTEGER
   first_utc                TEXT
   last_utc                 TEXT
   events                   TEXT
   log_types                TEXT
   first_ref                TEXT
   last_ref                 TEXT

HxStore
-------

``store_info``
^^^^^^^^^^^^^^

One row per store: size, hash, page statistics, store identifiers, record and identifier counts.

.. code-block:: text

   store                    TEXT
   size                     INTEGER
   sha256                   TEXT
   pages_json               TEXT
   primary_store_id         TEXT
   secondary_store_id       TEXT
   records                  INTEGER
   distinct_ids             INTEGER
   note                     TEXT

``store_records``
^^^^^^^^^^^^^^^^^

One row per stored record **version**. ``payload`` is the decompressed payload, ``raw`` the stored bytes.

.. code-block:: text

   store                    TEXT
   record_id                INTEGER
   version                  INTEGER
   versions                 INTEGER
   page                     INTEGER
   file_offset              INTEGER
   size_compressed          INTEGER
   size_decompressed        INTEGER
   raw_format               TEXT
   format_name              TEXT
   object_type              INTEGER
   type_name                TEXT
   self_id                  INTEGER
   is_email                 INTEGER
   sender_email             TEXT
   sender_name              TEXT
   subject                  TEXT
   display_time_utc         TEXT
   timestamps               TEXT
   emails                   TEXT
   message_ids              TEXT
   folder                   TEXT
   n_strings                INTEGER
   payload_sha256           TEXT
   payload                  BLOB
   raw                      BLOB

``store_strings``
^^^^^^^^^^^^^^^^^

Every UTF-16 string of every record version, in order.

.. code-block:: text

   store                    TEXT
   record_id                INTEGER
   version                  INTEGER
   idx                      INTEGER
   text                     TEXT

``store_folders``
^^^^^^^^^^^^^^^^^

Folder names recovered from the store.

.. code-block:: text

   store                    TEXT
   record_id                INTEGER
   name                     TEXT

``store_attachments``
^^^^^^^^^^^^^^^^^^^^^

Attachment references found in store records, with the referenced cache path and whether that file exists.

.. code-block:: text

   store                    TEXT
   record_id                INTEGER
   versions                 TEXT
   display_name             TEXT
   profile_path             TEXT
   rel_path                 TEXT
   exists_on_disk           INTEGER
   size                     INTEGER
   sha256                   TEXT
   sender_email             TEXT

``store_bodies``
^^^^^^^^^^^^^^^^

Selected message body per e-mail record and its source (``inline``, ``efmdata``, ``sibling``, ``preview``).

.. code-block:: text

   store                    TEXT
   record_id                INTEGER
   source                   TEXT
   body_record_id           INTEGER
   efm_path                 TEXT
   text                     TEXT
   html                     TEXT

Account backup
--------------

``account_backup``
^^^^^^^^^^^^^^^^^^

Account settings from ``AccountsBackup.bhxd`` (section, property, type, value).

.. code-block:: text

   store                    TEXT
   record_hash              TEXT
   file_offset              INTEGER
   section                  TEXT
   prop                     TEXT
   type                     INTEGER
   type_name                TEXT
   value                    TEXT

Osa API logs
------------

``osa_logs``
^^^^^^^^^^^^

One row per Osa API log file with parsed header fields and the full XML.

.. code-block:: text

   id                       INTEGER
   file                     TEXT
   folder                   TEXT
   pinned                   INTEGER
   session_start_utc        TEXT
   seq                      INTEGER
   account                  TEXT
   channel                  TEXT
   command                  TEXT
   request_id               TEXT
   kind                     TEXT
   root                     TEXT
   time_utc                 TEXT
   send_time                TEXT
   receive_time             TEXT
   start_ts                 TEXT
   end_ts                   TEXT
   duration_ms              REAL
   status                   TEXT
   size                     INTEGER
   backend                  TEXT
   frontend                 TEXT
   server_build             TEXT
   tag                      TEXT
   app_state                TEXT
   app_version              TEXT
   client_version           TEXT
   device_os                TEXT
   device_type              TEXT
   device_id                TEXT
   socket_id                TEXT
   request_guid             TEXT
   client_session_id        TEXT
   user_agent               TEXT
   network_protocol         TEXT
   pii_values               INTEGER
   xml                      TEXT

``osa_fields``
^^^^^^^^^^^^^^

Every XML leaf of every API log as path/value (headers excluded).

.. code-block:: text

   log_id                   INTEGER
   path                     TEXT
   value                    TEXT

Legacy Outlook 2016
-------------------

``legacy_tables``
^^^^^^^^^^^^^^^^^

Tables found in legacy SQLite databases, with row count and the name of the copied table (``legacy_<db>_<table>``).

.. code-block:: text

   db                       TEXT
   tbl                      TEXT
   rows                     INTEGER
   copied_as                TEXT
   note                     TEXT

``wal_journals``
^^^^^^^^^^^^^^^^

Header summary of each SQLite write-ahead log found next to a database.

.. code-block:: text

   db                       TEXT
   wal_size                 INTEGER
   page_size                INTEGER
   frames                   INTEGER
   checkpoint_seq           INTEGER
   salt                     TEXT
   note                     TEXT

``olk15_records``
^^^^^^^^^^^^^^^^^

One row per legacy olk15 record file.

.. code-block:: text

   path                     TEXT
   kind                     TEXT
   record_type              TEXT
   uuid                     TEXT
   folder_no                INTEGER
   name                     TEXT
   modified_utc             TEXT
   n_props                  INTEGER
   size                     INTEGER

``olk15_props``
^^^^^^^^^^^^^^^

Every property of every olk15 record.

.. code-block:: text

   path                     TEXT
   prop_id                  TEXT
   prop_type                TEXT
   size                     INTEGER
   value                    TEXT

Other artifacts
---------------

``plist_values``
^^^^^^^^^^^^^^^^

Flattened property-list values (key path, type, value).

.. code-block:: text

   file                     TEXT
   keypath                  TEXT
   type                     TEXT
   value                    TEXT

``config_files``
^^^^^^^^^^^^^^^^

Outlook.com connector configuration files.

.. code-block:: text

   path                     TEXT
   format                   TEXT
   content                  TEXT

``attachment_files``
^^^^^^^^^^^^^^^^^^^^

Every cached attachment file with the store records that reference it.

.. code-block:: text

   path                     TEXT
   filename                 TEXT
   ref_no                   INTEGER
   ext                      TEXT
   size                     INTEGER
   sha256                   TEXT
   detected_type            TEXT
   store_record_ids         TEXT
   store_names              TEXT
   senders                  TEXT

``efm_files``
^^^^^^^^^^^^^

Every cached body file with title, text preview and owning store records.

.. code-block:: text

   path                     TEXT
   number                   INTEGER
   size                     INTEGER
   sha256                   TEXT
   format                   TEXT
   title                    TEXT
   text_preview             TEXT
   store_record_ids         TEXT

``photos``
^^^^^^^^^^

Contact photos and tenant logos with decoded timestamp and image size.

.. code-block:: text

   path                     TEXT
   kind                     TEXT
   guid                     TEXT
   time_utc                 TEXT
   width                    INTEGER
   height                   INTEGER
   size                     INTEGER
   sha256                   TEXT

``binary_artifacts``
^^^^^^^^^^^^^^^^^^^^

Small binaries and other files: parser name, decoded fields (JSON) and readable strings (JSON).

.. code-block:: text

   path                     TEXT
   parser                   TEXT
   fields                   TEXT
   strings                  TEXT

Export
------

``export_files``
^^^^^^^^^^^^^^^^

Manifest of ``export/`` (created by the export stage; same rows as ``manifest.csv``).

.. code-block:: text

   kind                     TEXT
   path                     TEXT
   record_id                INTEGER
   version                  INTEGER
   source                   TEXT
   size                     INTEGER
   sha256                   TEXT
   detail                   TEXT

Views
-----

``store_mail``
^^^^^^^^^^^^^^

View: one row per e-mail record (latest version).

.. code-block:: text

   store                    TEXT
   record_id                INTEGER
   latest_version           (computed)
   versions                 INTEGER
   sender_email             TEXT
   sender_name              TEXT
   subject                  TEXT
   display_time_utc         TEXT
   folder                   TEXT
   raw_format               TEXT

``hfl_store_objects``
^^^^^^^^^^^^^^^^^^^^^

View: trace-log object activity joined with the store (``in_store`` = 1 if the record exists).

.. code-block:: text

   file                     TEXT
   object_id                INTEGER
   mentions                 INTEGER
   first_utc                TEXT
   last_utc                 TEXT
   events                   TEXT
   type_name                TEXT
   subject                  TEXT
   sender_email             TEXT
   folder                   TEXT
   versions                 INTEGER
   in_store                 (computed)

``osa_commands``
^^^^^^^^^^^^^^^^

View: per channel and command, number of logs, number of non-success statuses and time range.

.. code-block:: text

   channel                  TEXT
   command                  TEXT
   n                        (computed)
   not_success              (computed)
   first_utc                (computed)
   last_utc                 (computed)

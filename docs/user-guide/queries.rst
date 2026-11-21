SQL cookbook
============

Open the database with ``sqlite3 olk_forensic_out/profile.db`` or a GUI such as
`DB Browser for SQLite <https://sqlitebrowser.org>`_. Record identifiers and dates below are
examples; replace them with your own.

Timeline
--------

.. code-block:: sql

   -- everything in one hour (UTC)
   SELECT time_utc, source, kind, description, ref FROM timeline
   WHERE time_utc BETWEEN '2025-11-10 22:00' AND '2025-11-10 23:00' ORDER BY time_utc;

   -- events per day and source
   SELECT substr(time_utc, 1, 10) AS day, source, count(*) FROM timeline GROUP BY 1, 2 ORDER BY 1;

   -- application starts and log rotations
   SELECT time_utc, source, kind, artifact FROM timeline
   WHERE kind IN ('api log session start', 'trace log created', 'store lock entry') ORDER BY time_utc;

E-mail
------

.. code-block:: sql

   -- e-mails with the start of their body text
   SELECT m.display_time_utc, m.sender_email, m.subject, b.source, substr(b.text, 1, 200)
   FROM store_mail m LEFT JOIN store_bodies b USING (record_id) ORDER BY 1 DESC;

   -- e-mails per folder
   SELECT folder, count(*) FROM store_mail GROUP BY folder ORDER BY 2 DESC;

   -- full-text search in every stored string, including older versions
   SELECT record_id, version, text FROM store_strings WHERE text LIKE '%invoice%';

Store versions
--------------

.. code-block:: sql

   -- objects with more than one stored version
   SELECT record_id, type_name, count(*) AS versions FROM store_records
   GROUP BY record_id HAVING count(*) > 1 ORDER BY versions DESC;

   -- all versions of one object
   SELECT record_id, version, file_offset, size_decompressed, subject, payload_sha256
   FROM store_records WHERE record_id = 1234567 ORDER BY version;

   -- write one version's payload to a file (sqlite3 shell)
   SELECT writefile('1234567_v2.bin', payload) FROM store_records WHERE record_id = 1234567 AND version = 2;

Trace logs
----------

.. code-block:: sql

   -- errors and warnings
   SELECT time_utc, ekey, level, summary FROM hfl_records WHERE level <= 3 ORDER BY time_utc;

   -- most frequent events
   SELECT ekey, label, count, signature FROM hfl_events ORDER BY count DESC LIMIT 30;

   -- what the trace log did with one store object
   SELECT * FROM hfl_store_objects WHERE object_id = 1234567;

   -- objects most often mentioned that are no longer in the store
   SELECT object_id, mentions, first_utc, last_utc FROM hfl_store_objects
   WHERE in_store = 0 ORDER BY mentions DESC LIMIT 20;

API logs
--------

.. code-block:: sql

   -- failed API exchanges
   SELECT time_utc, channel, command, status FROM osa_logs
   WHERE status IS NOT NULL
     AND status NOT IN ('Success','Ok','OK','200','201','202','204','304')
   ORDER BY time_utc;

   -- commands and failure counts
   SELECT * FROM osa_commands ORDER BY n DESC;

   -- client versions seen (detects an application update)
   SELECT app_version, min(time_utc), max(time_utc), count(*) FROM osa_logs
   WHERE app_version IS NOT NULL GROUP BY app_version ORDER BY 2;

   -- every field of one log
   SELECT path, value FROM osa_fields WHERE log_id = 1;

Attachments and caches
----------------------

.. code-block:: sql

   -- cached attachments that no record references
   SELECT path, size, sha256, detected_type FROM attachment_files WHERE store_record_ids IS NULL;

   -- references whose file is missing
   SELECT record_id, display_name, rel_path FROM store_attachments WHERE exists_on_disk = 0;

   -- cached bodies without an owner
   SELECT path, title, text_preview FROM efm_files WHERE store_record_ids IS NULL;

Account and legacy data
-----------------------

.. code-block:: sql

   SELECT section, prop, type_name, value FROM account_backup ORDER BY section, prop;
   SELECT keypath, value FROM plist_values WHERE file = 'ProfilePreferences.plist';
   SELECT * FROM legacy_tables;
   SELECT kind, name, modified_utc FROM olk15_records ORDER BY modified_utc;

Exports
-------

.. code-block:: sql

   SELECT kind, count(*), sum(size) FROM export_files GROUP BY kind;
   SELECT path, sha256 FROM export_files WHERE record_id = 1234567;

Python API
==========

``olk_forensic`` is a command-line tool, but its functions can be imported, for example to
decode a single artifact into a database. Import it with the project folder on
``sys.path``:

.. code-block:: python

   import sys
   sys.path.insert(0, "/path/to/hxcore")
   import olk_forensic as of

   db = of.DB("account.db")                     # creates the full schema
   n = of.parse_account_backup("Main Profile/AccountsBackup.bhxd", "AccountsBackup.bhxd", db)
   db.close()
   print(n, "values")

Parsers that take a file dictionary expect the keys produced by :func:`olk_forensic.inventory`:
``path`` (profile-relative), ``full`` (absolute path), ``size``, ``head`` (first 64 bytes),
``category``, ``type``, ``md5`` and ``sha256``.

.. note::

   These functions are internal interfaces of a forensic tool. They may change between
   versions; pin the version you use in casework.

Database
--------

.. autoclass:: olk_forensic.DB
   :members: add, flush, meta, tl, finding, corr, close

Inventory
---------

.. autofunction:: olk_forensic.inventory
.. autofunction:: olk_forensic.detect
.. autofunction:: olk_forensic.categorize
.. autofunction:: olk_forensic.hashes

Decoders
--------

.. autofunction:: olk_forensic.parse_hfl
.. autofunction:: olk_forensic.store_parse
.. autofunction:: olk_forensic.parse_account_backup
.. autofunction:: olk_forensic.decode_kv
.. autofunction:: olk_forensic.parse_osa
.. autofunction:: olk_forensic.parse_legacy_sqlite
.. autofunction:: olk_forensic.parse_olk15
.. autofunction:: olk_forensic.unarchive
.. autofunction:: olk_forensic.flatten
.. autofunction:: olk_forensic.parse_plist
.. autofunction:: olk_forensic.parse_files_area
.. autofunction:: olk_forensic.parse_small
.. autofunction:: olk_forensic.parse_config

Analysis and output
-------------------

.. autofunction:: olk_forensic.correlate
.. autofunction:: olk_forensic.findings
.. autofunction:: olk_forensic.export_content
.. autofunction:: olk_forensic.export_json
.. autofunction:: olk_forensic.build_report
.. autofunction:: olk_forensic.write_pages
.. autofunction:: olk_forensic.run

Time helpers
------------

.. autofunction:: olk_forensic.from_unix
.. autofunction:: olk_forensic.from_ticks
.. autofunction:: olk_forensic.from_cocoa
.. autofunction:: olk_forensic.iso

Trace-log primitives (``hfl_parse``)
------------------------------------

.. autofunction:: hfl_parse.parse_header
.. autofunction:: hfl_parse.iter_chunks
.. autofunction:: hfl_parse.chunk_header
.. autofunction:: hfl_parse.lz4_block
.. autofunction:: hfl_parse.iter_records
.. autofunction:: hfl_parse.decode_args
.. autofunction:: hfl_parse.arg_signature

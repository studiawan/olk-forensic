olk_forensic
============

**olk_forensic** is a forensic parser for profiles of the **new Outlook for Mac** (the
HxCore-based client). One run inventories every file in a copied profile folder, decodes
every known artifact, correlates them, and writes:

* a **multi-page HTML forensic report**, readable offline;
* an **SQLite database** and **JSON** with everything that was decoded;
* an **export folder** with one HTML file per e-mail body, one binary file per store record
  version, and attachment copies named by the store record that owns them, all listed in a
  SHA-256 manifest.

The tool only reads the evidence and never modifies it. It needs only the Python standard
library; the ``lz4`` package is optional and only makes the store decoding faster.

.. code-block:: bash

   python3.12 -I tools/olk_forensic.py "Main Profile" --out olk_forensic_out --tz 7
   open olk_forensic_out/report.html

What it decodes
---------------

.. list-table::
   :header-rows: 1
   :widths: 35 65

   * - Artifact
     - Content
   * - ``hxcore.hfl``, ``hxcore_previous_session.hfl``
     - HxCore binary trace logs: every record with UTC time, thread, event, level and typed
       arguments (format first documented by this project, see :doc:`formats/hfl`)
   * - ``HxStore.hxd``
     - HxCore object store: every stored record **version**, e-mail fields, folders,
       attachment references and message bodies
   * - ``AccountsBackup.bhxd``
     - Account settings backup (uncompressed key/value records)
   * - ``Osa/**/*.xmlgz``
     - Outlook Service API request/response logs
   * - ``Data/*.sqlite``, ``Data/**/*.olk15*``
     - Legacy Outlook 2016 database (with its write-ahead log) and record files
   * - Property lists, caches, lock table, counters, telemetry
     - Decoded fields, timestamps and readable strings

The artifacts are then correlated: trace-log object identifiers with store records,
attachment references with cached files, store records with cached bodies, and every internal
timestamp into one UTC timeline.

.. toctree::
   :maxdepth: 2
   :caption: Getting started

   getting-started/installation
   getting-started/acquisition
   getting-started/quickstart

.. toctree::
   :maxdepth: 2
   :caption: User guide

   user-guide/cli
   user-guide/artifacts
   user-guide/output
   user-guide/report
   user-guide/exports
   user-guide/correlation
   user-guide/database
   user-guide/queries

.. toctree::
   :maxdepth: 2
   :caption: Artifact formats

   formats/index
   formats/hfl
   formats/hxstore
   formats/accounts-backup
   formats/osa
   formats/olk15
   formats/caches
   formats/small-binaries

.. toctree::
   :maxdepth: 2
   :caption: Forensic use

   forensics/soundness
   forensics/validation
   forensics/limitations

.. toctree::
   :maxdepth: 2
   :caption: Development

   development/architecture
   development/testing
   development/api
   development/related-tools

.. toctree::
   :maxdepth: 1
   :caption: About

   troubleshooting
   faq
   citing
   changelog

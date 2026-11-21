Installation
============

Requirements
------------

.. list-table::
   :header-rows: 1
   :widths: 30 70

   * - Requirement
     - Why
   * - **Python 3.10 or newer**
     - The bundled ``hxstore-decode`` library uses Python 3.10 syntax. On macOS install it
       with ``brew install python@3.12`` or from python.org.
   * - ``tools/hfl_parse.py``
     - Decodes the ``.hfl`` trace logs. Must be in the same folder as ``olk_forensic.py``.
   * - ``tools/hxstore-decode/src/``
     - Library that decodes ``HxStore.hxd``. It is loaded from the folder; nothing is
       installed.
   * - ``lz4`` package (optional)
     - Faster decompression of ``HxStore.hxd``. Without it a pure-Python LZ4 decoder is
       used and the results are the same.

No other third-party package is needed. The tool runs on macOS, Linux and Windows; the
profile itself comes from macOS.

Folder layout
-------------

.. code-block:: text

   olk-forensic/
   ├── tools/
   │   ├── olk_forensic.py        <- the tool
   │   ├── hfl_parse.py           <- trace-log decoder (also usable on its own)
   │   ├── hfl_report.py, hxstore_export.py
   │   └── hxstore-decode/src/    <- HxStore library
   ├── tests/                     <- unit tests
   ├── docs/                      <- this documentation
   └── README.md

   Main Profile/                  <- your copy of the profile: keep it outside the repository

Setting up a virtual environment
--------------------------------

A virtual environment keeps the optional ``lz4`` package separate from the system Python:

.. code-block:: bash

   git clone <repository-url> olk-forensic
   cd olk-forensic
   python3.12 -m venv .venv            # or python3.10 / 3.11 / 3.13
   .venv/bin/pip install lz4           # optional
   .venv/bin/python -I tools/olk_forensic.py --help

Checking the installation
-------------------------

Run the unit tests. They use synthetic artifacts, so no evidence is needed:

.. code-block:: bash

   python3.12 -B -m unittest discover -s tests

The last line should be ``OK (skipped=2)``. The two skipped tests run only against a real
profile; see :doc:`../development/testing`.

If ``hxstore-decode`` cannot be loaded (for example on Python 3.9), the tool still runs:
``HxStore.hxd`` is skipped and a warning appears on the report's *Findings* page.

Validation
==========

Trace-log well-formedness
-------------------------

A trace log is decoded correctly only if all of the following hold. The tool and the test suite
check them; violations are recorded rather than ignored.

.. list-table::
   :header-rows: 1
   :widths: 8 92

   * - Check
     - Property
   * - W1
     - Every chunk decompresses to exactly the size declared in its header.
   * - W2
     - The records of a chunk tile its decompressed data exactly: each record length is at
       least the header size, and the last record ends at the end of the chunk.
   * - W3
     - Every record's arguments decode within the record: the declared number of typed
       arguments is read without an unknown type code and without running past the record.
   * - W4
     - Every event key is observed with a single argument signature.

Because the format has no checksum, W1–W4 are the strongest available evidence that the record
boundaries, the type grammar and the argument values are interpreted correctly; a wrong offset
or type length breaks W2 or W3 within a few records.

Results on the evaluation profile
---------------------------------

The tool was evaluated on a real profile of 22,122 files (298.9 MB):

.. list-table::
   :header-rows: 1
   :widths: 60 40

   * - Measure
     - Result
   * - Trace-log chunks satisfying W1 and W2
     - 5,782 of 5,782
   * - Trace records decoded / with argument errors (W3)
     - 4,294,222 / 0
   * - Typed arguments decoded
     - 19,085,573
   * - Event keys with a single signature (W4)
     - 704 of 704
   * - Gap bytes between chunks
     - 31,932
   * - HxStore record versions decoded
     - 1,453 (98.4 % of stored bytes recovered)
   * - Account backup values
     - 1,447
   * - Osa API logs
     - 21,648
   * - Exported files with matching manifest hash
     - all
   * - Report links resolving to an existing file
     - all
   * - Total run time
     - 208 s

Session corroboration
---------------------

For one application start, the Osa folder time, the first trace record and the store lock entry
agreed within 0.37 s, and the first API request followed 0.8 s later (see
:doc:`../user-guide/correlation`). Agreement of independent clocks is the highest certainty
level (C4) in :doc:`soundness`.

Reproducing the checks
----------------------

The optional tests run W1–W4 over every chunk of a real ``hxcore.hfl`` and decode the real
store, read-only:

.. code-block:: bash

   OLK_PROFILE="Main Profile" python3.12 -B -m unittest discover -s tests -k RealProfile -v

See :doc:`../development/testing` for the full test suite.

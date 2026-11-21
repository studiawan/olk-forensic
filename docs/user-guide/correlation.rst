Correlation and timeline
========================

After decoding, the tool relates the artifacts to each other. Every result is written to the
``correlations`` table and summarized on the *Correlation* page.

Trace-log objects and store records
-----------------------------------

The trace log mentions HxCore object identifiers in its arguments (as 64-bit integers or as
16-character little-endian hexadecimal strings). Store records carry the same identifiers, so
the two share one number space. For each trace log the tool reports how many logged objects
still exist in the store and which share of all mentions refers to them. Store records never
mentioned in a trace log are counted as well.

The view ``hfl_store_objects`` joins ``hfl_object_activity`` with the store, giving per object
the number of mentions, the first and last time, the events involved and, if present, the store
type, subject, sender, folder and number of stored versions.

Attachments
-----------

Store records reference cached attachments by profile-relative path
(``~/Files/S0/<n>/Attachments/<name>[<N>].<ext>``). The tool classifies every reference and every
cached file:

* **linked** — the reference and the file both exist;
* **file missing** — a record references a file that is not on disk;
* **on disk only** — a cached file that no current record references (possible remnant of a
  deleted message, an inline image of an older version, or a reference in an overwritten
  record).

Bodies
------

Store records reference cached bodies as ``EFMData/<n>.dat``. Each cached body is marked
**linked** (with the owning records) or **unreferenced**. Body selection for the export is
described in :doc:`exports`.

Trace logs and API logs
-----------------------

For each trace log the tool counts the Osa API logs whose time falls inside the trace log's
first-to-last record range, and how many distinct commands they contain.

Unified timeline
----------------

The ``timeline`` table merges every timestamp found **inside** the artifacts. File-system
times are not used, because a copy without ``-p`` replaces them.

.. list-table::
   :header-rows: 1
   :widths: 14 30 56

   * - Source
     - Kind
     - Clock
   * - ``hfl``
     - trace log created, first / last trace record, trace error
     - .NET ticks in the header plus monotonic record stamps (see :doc:`../formats/hfl`)
   * - ``store``
     - e-mail time
     - display time decoded from the record
   * - ``osa``
     - api log session start, api *channel*
     - hexadecimal Unix time in the folder name; ISO 8601 ``LogTime`` in the XML
   * - ``lock``
     - store lock entry
     - .NET ticks per lock-table entry
   * - ``olk15``
     - legacy record date
     - Cocoa (2001-01-01) double
   * - ``files``
     - photo timestamp (filename ticks)
     - .NET ticks in the photo file name
   * - ``telemetry``
     - telemetry snapshot
     - Unix seconds

Only events of interest from the API logs are put on the timeline: everything on the ``app``
channel, every non-success status, and the commands ``Initialize``, ``GetAttachment``,
``SendMessage``, ``SendMail``, ``DeleteItem`` and ``MoveItem``. All API logs remain in
``osa_logs``.

Corroborating a session start
-----------------------------

Because the clocks are independent, agreement between them corroborates an event. On the
evaluation profile, the start of one Outlook session was recorded by three sources within
0.37 s:

.. code-block:: text

   22:57:43.000  osa   api log session start   (folder name, whole seconds)
   22:57:43.335  hfl   first trace record      (trace-log clock)
   22:57:43.370  lock  store lock entry        (lock-table ticks)
   22:57:44.153  osa   first API request       (XML LogTime)

.. code-block:: sql

   SELECT time_utc, source, kind, description FROM timeline
   WHERE kind IN ('api log session start', 'trace log created', 'first trace record', 'store lock entry')
   ORDER BY time_utc;

.. note::

   An Osa log folder is created when the application starts **and** when the API log
   rotates during a running session. A folder start is therefore a session start only if
   another clock (trace log, lock table) agrees.

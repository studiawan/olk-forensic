Outlook Service API logs (``Osa/``)
===================================

The client logs its requests to, and responses from, the Outlook service as small
gzip-compressed XML files.

Folders
-------

.. code-block:: text

   Osa/OutlookServiceApiLogs_<YYYY-MM-DD-HH>_<XXXXXXXX>/   regular logs
   Osa/OsaPinnedLogs/                                      pinned (kept) logs

``XXXXXXXX`` is the folder's creation time as 8 hexadecimal digits of Unix seconds; it is stored
as ``osa_logs.session_start_utc`` and put on the timeline as *api log session start*. A folder
is created when the application starts and also when the log **rotates** during a running
session, so it is not by itself proof of an application start (see
:doc:`../user-guide/correlation`).

File names
----------

.. code-block:: text

   osa{YYYY-MM-DD-HH-MM-SS}_<seq>_<account>_<channel>.<command>[.<request id>].<kind>.xmlgz

.. list-table::
   :header-rows: 1
   :widths: 20 80

   * - Part
     - Meaning (column)
   * - ``{...}``
     - Local time of the log (used for pinned logs, which have no folder time)
   * - ``seq``
     - Sequence number in the folder (``seq``)
   * - ``account``
     - Account identifier (``account``)
   * - ``channel``
     - Channel, for example ``sync`` or ``app`` (``channel``)
   * - ``command``
     - API command, for example ``GetMessage`` or ``Initialize`` (``command``)
   * - ``request id``
     - Numeric request identifier, when present (``request_id``)
   * - ``kind``
     - ``request``, ``response`` and similar (``kind``)

Content
-------

Each file is one XML document (root ``Log``). The top-level elements below are copied into
columns of ``osa_logs``; values inside the XML take precedence over values from the file name.

.. code-block:: text

   AccountId  LogTime  SendTime  ReceiveTime  StartTimeStamp  EndTimeStamp  StatusCode  Size
   BackEndServer  FrontEndServer  ServerBuild  Tag  AppState  AppVersion  ClientVersion
   DeviceOS  DeviceType  DeviceId  SocketId  RequestGuid  ClientSessionId  NetworkProtocol
   CommandId  ChannelId  RequestId  Headers (User-Agent)

``duration_ms`` is ``EndTimeStamp − StartTimeStamp``. Every leaf element is also stored in
``osa_fields`` as an XML path and value, and the full document in ``osa_logs.xml``. Malformed
XML is still read with a regular-expression fallback (``root = '(malformed)'``).

Status codes
------------

The statuses ``Success``, ``Ok``, ``OK``, ``200``, ``201``, ``202``, ``204`` and ``304`` count
as success. Any other status is a failure: it is reported on the *Findings* page, counted in
the ``osa_commands`` view and put on the timeline.

Redaction
---------

The client replaces personal values (addresses, subjects, names) by ``pii:<hash>`` before
writing the log. ``osa_logs.pii_values`` counts them. Structure, timing, commands, servers and
status codes remain available.

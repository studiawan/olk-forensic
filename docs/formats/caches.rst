File caches (``Files/S0/``)
===========================

``Files/S0/<n>/`` holds files that the client has downloaded or generated.

Attachments
-----------

``Files/S0/<n>/Attachments/<name>[<N>].<ext>``

``<name>`` and ``<ext>`` are the attachment's file name; ``[<N>]`` is a reference number that
makes the cache name unique. Store records reference these files by their profile-relative
path (``~/Files/S0/...``). The ``attachment_files`` table lists every cached file with its
reference number, hash, detected type and the store records that reference it. Files no record
references are copied to ``export/attachments/unreferenced/``.

Message bodies
--------------

``Files/S0/<n>/EFMData/<number>.dat``

Each file is the HTML body of one message, stored as plain HTML or gzip-compressed HTML.
Store records reference it as ``EFMData/<number>.dat``. The ``efm_files`` table holds the
title, a text preview and the owning records.

Contact photos and tenant logos
-------------------------------

``Files/S0/<n>/Photos/{<GUID>}<ticks>.<ext>`` and ``Files/S0/<n>/AadLogos/...``

The photo file name contains a GUID and an 18-digit .NET-ticks value, which the tool converts
to UTC and puts on the timeline. The image size is read from the PNG header.

Other cache files
-----------------

Other files under ``Files/`` are hashed and reduced to readable strings (UTF-16 XML is decoded
as text) in ``binary_artifacts``.

Limitations
===========

Formats
-------

* **HxStore fields are heuristic.** Sender, subject, folder and display time come from the
  hxstore-decode heuristics. Folder names can be off by one or duplicated. Index pages and
  unallocated space inside the store are not carved.
* **Trace-log events have no names.** Labels are derived from constant arguments and log-site
  tags. Object identifiers with high flag bits are not matched to the store.
* **Account backup property names** are numeric HxCore identifiers whose meaning is not
  documented.
* **Legacy virtual tables**, such as ``Files`` in ``Outlook.sqlite``, need Outlook's own SQLite
  module and cannot be read.

Content
-------

* **API logs are redacted by the client.** Personal values are written as ``pii:<hash>``; only
  structure, timing, commands, servers and status codes can be recovered.
* **Bodies of preview-only messages** are incomplete: when no full body is cached, only the
  preview text is exported.
* **Remote content** referenced by HTML bodies is not fetched or preserved.

Time
----

* **Trace logs are ring buffers.** Older chunks are overwritten, so a log covers only the most
  recent part of a session, and the start of a session may be missing.
* **Osa folder times have one-second resolution**, and a folder can mark a log rotation rather
  than an application start.
* **File-system times** are not used on the timeline, because a copy without timestamp
  preservation replaces them; the inventory still records them.

Scope
-----

* Only the profile folder is examined. Unified logs, crash reports, keychain items and server
  data are out of scope.
* The tool was developed and evaluated on profiles of Outlook for Mac 16.11x; other versions may
  differ.
* Encrypted or damaged files are reported, not repaired.

Frequently asked questions
==========================

Does the tool work with the old Outlook 2016 for Mac?
   Partly. The legacy ``Data/`` folder (SQLite database and olk15 records) of a migrated
   profile is decoded. Pure Outlook 2016 profiles are better served by tools for that format.

Does it work for Outlook on Windows?
   No. Outlook on Windows uses PST/OST files; use libpff or similar.

Can it run on Windows or Linux?
   Yes. Copy the profile from the Mac and run the tool anywhere Python 3.10+ is available.

Does it recover deleted e-mails?
   It reports what remains: older record versions in the store, cached attachments and bodies
   that no live record references, trace-log activity for objects no longer in the store, and
   WAL rows of legacy databases. It does not carve unallocated space.

Why are the subjects and addresses in the API logs hashes?
   Outlook itself writes them as ``pii:<hash>`` values. The tool cannot reverse them.

Why is a trace log missing for some sessions?
   Only two trace logs are kept (current and previous session), and each is a ring buffer.

Can I use the results in court?
   The tool is designed for forensic soundness (:doc:`forensics/soundness`) and its decoding is
   checkable (:doc:`forensics/validation`), but as with any tool, important findings should be
   verified in the raw artifact and the tool should be validated in your own laboratory.

Does the tool send data anywhere?
   No. It makes no network connections, and the HTML report loads no external resources.

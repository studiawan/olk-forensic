Acquiring the profile
=====================

Always run the tool on a **copy** of the profile, never on the live folder.

Where the profile is
--------------------

On the examined Mac, the new Outlook keeps each profile in:

.. code-block:: text

   ~/Library/Group Containers/UBF8T346G9.Office/Outlook/Outlook 15 Profiles/<Profile Name>

The default profile is called ``Main Profile``. A typical profile contains:

.. code-block:: text

   AccountsBackup.bhxd         HxStore.hxd                 Osa/
   ActionsBackup/              HxStore.lock                OMCMigrationSourceFolder/
   clientConfigsForAM.dat      hxcore.hfl                  PreferencesSearchIndex/
   Data/                       hxcore_previous_session.hfl ProfilePreferences.plist
   ExternalCounters.ctr        LocalFiles/                 rss/
   Files/                      nls/                        SnapShot/
   FileSystemLoggingCache.log  Omc/                        TelemetryStorage/

Copying it
----------

1. **Quit Outlook** so that the files stop changing. On a live system, note the time.
2. Copy the folder **with timestamps preserved**:

   .. code-block:: bash

      ditto "$HOME/Library/Group Containers/UBF8T346G9.Office/Outlook/Outlook 15 Profiles/Main Profile" \
            "./Main Profile"
      # or
      cp -Rp "<source>" "./Main Profile"

3. Optionally hash the copy for your case notes. The tool also records the MD5 and SHA-256
   of every file in the ``files`` table and on the *Inventory* page.

.. warning::

   A plain ``cp -R`` or a Finder copy replaces every file's modification time with the time
   of the copy. The tool detects this (more than 50 files whose modification times all fall
   within one hour) and writes a warning to the *Findings* page. File-system times are never
   put on the timeline; only timestamps stored **inside** the artifacts are used.

Permissions
-----------

Reading ``~/Library/Group Containers`` may require *Full Disk Access* for Terminal
(System Settings → Privacy & Security → Full Disk Access).

From a disk image
-----------------

When working from a forensic image, mount it read-only and copy the profile folder out of
the mounted volume in the same way, or point the tool at the mounted path directly; the tool
opens every input read-only and copies SQLite databases to a temporary folder before opening
them, so nothing is written next to the evidence.

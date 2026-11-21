# olk_forensic: forensic parser for Outlook for Mac profiles

`olk_forensic.py` parses a whole **new Outlook for Mac** (HxCore) profile folder in one run and produces:

- a **multi-page HTML forensic report**
- an **SQLite database** and **JSON** with everything decoded
- an **export folder** with e-mail bodies, store record payloads and attachment copies

It reads the evidence and never modifies it.

---

## 1. Quick start

```bash
git clone <repository-url> olk-forensic && cd olk-forensic

# one-time setup: needs Python 3.10 or newer (check with: python3 --version)
python3.12 -m venv .venv          # or python3.10 / python3.11 / python3.13
.venv/bin/pip install lz4

# run it on a copied profile folder
.venv/bin/python -I tools/olk_forensic.py "Main Profile" --out olk_forensic_out --tz 7

# open the report
open olk_forensic_out/report.html
```

`--tz 7` shows times in UTC+7 (for example WIB). Use your own offset, or leave it out for UTC. Times stored in the database are always UTC.

A typical profile (about 22,000 files, 300 MB) takes about 3–4 minutes.

---

## 2. Requirements

| Requirement | Why |
|---|---|
| **Python 3.10+** | `hxstore-decode` uses Python 3.10 syntax. On macOS: `brew install python@3.12`, or use python.org. |
| `lz4` package (recommended) | Fast decompression of `HxStore.hxd`. Without it, a slower pure-Python decoder is used. |
| `tools/hfl_parse.py` | Decodes the `.hfl` trace logs. |
| `tools/hxstore-decode/` | Library that decodes `HxStore.hxd` (only `hxstore-decode/src` is used, nothing is installed). |

Expected layout:

```
olk-forensic/
├── tools/
│   ├── olk_forensic.py        <- this tool
│   ├── hfl_parse.py           <- trace-log decoder (also usable on its own)
│   ├── hfl_report.py, hxstore_export.py
│   └── hxstore-decode/src/    <- HxStore library (MIT, bundled)
├── tests/                     <- unit tests (synthetic artifacts, no evidence)
├── docs/                      <- Sphinx documentation (Read the Docs)
└── README.md
```

Keep the evidence (for example `Main Profile/`) and the output folders **outside** the repository, or rely on `.gitignore`, which excludes the usual names.

If `hxstore-decode` cannot be loaded (wrong Python version, missing folder), the run still finishes. `HxStore.hxd` is skipped and a warning is written to the Findings page.

---

## 3. Acquiring the profile

The live profile is in:

```
~/Library/Group Containers/UBF8T346G9.Office/Outlook/Outlook 15 Profiles/Main Profile
```

1. **Quit Outlook** so the files stop changing.
2. Copy the folder **with timestamps preserved**:
   ```bash
   ditto "$HOME/Library/Group Containers/UBF8T346G9.Office/Outlook/Outlook 15 Profiles/Main Profile" "./Main Profile"
   # or: cp -Rp "<source>" "./Main Profile"
   ```
   A plain `cp -R` or a Finder copy replaces every file's modification time with the copy time. The tool detects this and warns about it on the Findings page.
3. Optionally, hash the copy for your case notes. The tool also records MD5 and SHA-256 of every file.

Always run the tool on the **copy**, never on the live profile.

---

## 4. Command-line options

```
python -I tools/olk_forensic.py PROFILE [--out DIR] [--tz HOURS] [--hfl-mode records|summary] [--skip-hfl]
python -I tools/olk_forensic.py --rebuild DB [--tz HOURS]
python -I tools/olk_forensic.py --report-only DB [--tz HOURS]
```

| Option | Meaning |
|---|---|
| `PROFILE` | The copied profile folder (for example `"Main Profile"`). |
| `--out DIR` | Output folder (default `olk_forensic_out`). Existing outputs inside it are replaced. |
| `--tz HOURS` | Show report times in UTC+HOURS, for example `7`, `-5` or `5.5`. |
| `--hfl-mode records` | (default) Decode **every** trace-log record into `hfl_records`. |
| `--hfl-mode summary` | Keep only errors and warnings plus the event catalog. Smaller and faster. |
| `--skip-hfl` | Do not decode `.hfl` files at all. |
| `--rebuild DB` | Redo `export/`, JSON and the report from an existing `profile.db`, without parsing again (about 1 minute). |
| `--report-only DB` | Rebuild only the HTML report from an existing `profile.db`. |

`-I` (isolated mode) keeps Python from loading stray modules from the current folder. This is a good habit when working near evidence.

---

## 5. What gets parsed

| Artifact in the profile | What the tool extracts |
|---|---|
| `hxcore.hfl`, `hxcore_previous_session.hfl` | HxCore trace logs: every record with UTC time, thread, event, level and decoded arguments; event catalog; object IDs |
| `HxStore.hxd` | Every record **version**: type, format, sender, subject, display time, e-mail addresses, all text strings, folder, decompressed payload; attachment references; message bodies |
| `AccountsBackup.bhxd` | Account settings backup (key/value records, decoded by this tool) |
| `Osa/**/*.xmlgz` | Outlook Service API logs: command, request/response, times, duration, status, servers, client version, full XML and every XML field |
| `Data/*.sqlite` (+ `-wal`) | Legacy Outlook 2016 database and lock databases. Rows are copied into `legacy_*` tables, and WAL journals are summarized. Read from a temporary copy so the WAL is applied without touching the evidence. |
| `Data/**/*.olk15*` | Legacy record files (categories, folders, saved searches, signatures, contacts) with all properties |
| `ProfilePreferences.plist`, `clientConfigsForAM.dat` | Property lists, including NSKeyedArchiver and nested plists, flattened into key paths |
| `Files/S0/*/Attachments/` | Cached attachments: hash, type, and which store records reference each file |
| `Files/S0/*/EFMData/` | Cached message bodies, linked to store records |
| `Files/S0/*/Photos/`, `AadLogos/` | Contact photos (timestamp decoded from the file name) and tenant logos |
| `Omc/**` | Outlook.com connector configuration |
| `HxStore.lock`, `ExternalCounters.ctr`, `TelemetryStorage/*.bin`, `FileSystemLoggingCache.log`, `rss/*.rep`, `nls/`, `PreferencesSearchIndex` | Decoded fields where the format is known, plus readable strings |

Then the artifacts are **correlated**:

- trace-log object IDs ↔ HxStore record IDs
- store attachment references ↔ files in the attachment cache (missing files and unreferenced files)
- store records ↔ EFMData bodies
- trace-log time ranges ↔ Osa API activity
- every timestamp found **inside** the artifacts → one unified timeline

---

## 6. Output

```
olk_forensic_out/
├── report.html              main page: summary + menu of all sections
├── report/                  one HTML page per section
│   ├── findings.html        warnings and notable observations
│   ├── inventory.html       every file with MD5/SHA-256, type, parser
│   ├── account.html         preferences, account backup, connector config
│   ├── timeline.html        unified timeline with a per-day chart
│   ├── store.html           HxStore pages, object types, folders, versions
│   ├── mail.html            e-mail list (Body links open the exported body)
│   ├── attach.html          attachment references, cache files, bodies, photos
│   ├── hfl.html             trace logs: summary, top events, errors
│   ├── corr.html            cross-artifact correlation
│   ├── osa.html             API sessions, commands, status codes, app states
│   ├── legacy.html          Outlook 2016 SQLite and olk15 records
│   ├── other.html           lock file, counters, telemetry, caches
│   ├── exports.html         clickable list of every exported file
│   ├── limits.html          limitations
│   └── sql.html             query examples
├── export/
│   ├── bodies/<record_id>_<source>.html      one per e-mail body
│   ├── records/<record_id>_v<version>.bin    decompressed payload of each store record version
│   ├── attachments/<record_id>_<filename>    attachment copies, named by owning record
│   ├── attachments/unreferenced/             cached attachments no record references
│   └── manifest.csv                          every exported file with SHA-256
├── profile.db               SQLite database (all tables)
├── profile.json             all tables with ≤ 20,000 rows
└── json/<table>.jsonl       larger tables, one JSON object per line
```

The report is plain static HTML. It needs no server or internet connection, and the whole `olk_forensic_out` folder can be zipped and handed over.

**Body file names** say where the body came from:

| Suffix | Source |
|---|---|
| `_inline` | HTML stored inside the e-mail's own record |
| `_efmdata` | A cached body file in `Files/S0/*/EFMData/` |
| `_sibling` | Another store record with the same Message-ID |
| `_preview` | Only the short preview text survives (wrapped in a minimal page) |

**Attachment copies** keep the original file times. The `[1234]` cache suffix is removed from the name, and name clashes get `_2`, `_3` and so on. A file referenced by several records is copied once per record.

---

## 7. Main database tables

| Table / view | Content |
|---|---|
| `files` | Inventory of every file (path, size, times, MD5, SHA-256, detected type, parser) |
| `timeline` | Unified timeline (UTC) from all sources |
| `findings`, `correlations` | Generated findings and cross-artifact links |
| `hfl_files`, `hfl_records`, `hfl_events`, `hfl_hourly`, `hfl_object_activity` | Trace logs |
| `store_info`, `store_records`, `store_strings`, `store_folders`, `store_attachments`, `store_bodies` | HxStore (`store_records.payload` = decompressed bytes, `.raw` = compressed) |
| `store_mail` (view) | One row per e-mail |
| `hfl_store_objects` (view) | Trace-log object activity joined with the store |
| `account_backup` | AccountsBackup.bhxd settings |
| `osa_logs`, `osa_fields`, `osa_commands` (view) | Osa API logs |
| `legacy_tables`, `legacy_*`, `wal_journals`, `olk15_records`, `olk15_props` | Legacy Outlook 2016 data |
| `plist_values`, `config_files`, `attachment_files`, `efm_files`, `photos`, `binary_artifacts` | Other artifacts |
| `export_files` | Manifest of `export/` |

Example queries (`sqlite3 olk_forensic_out/profile.db`):

```sql
-- everything in one hour (UTC)
SELECT * FROM timeline WHERE time_utc BETWEEN '2026-11-12 01:00' AND '2026-11-12 02:00' ORDER BY time_utc;

-- e-mails with their body text
SELECT m.display_time_utc, m.sender_email, m.subject, b.source, substr(b.text,1,200)
FROM store_mail m LEFT JOIN store_bodies b USING(record_id) ORDER BY 1 DESC;

-- all versions of one store object
SELECT record_id, version, file_offset, subject, payload_sha256 FROM store_records WHERE record_id = 5227890;

-- what the trace log did with a store object
SELECT * FROM hfl_store_objects WHERE object_id = 5227890;

-- failed API calls
SELECT time_utc, channel, command, status FROM osa_logs
WHERE status NOT IN ('Success','Ok','200','304') ORDER BY time_utc;
```

A GUI such as [DB Browser for SQLite](https://sqlitebrowser.org) also works.

---

## 8. Limitations

- Field meaning in HxStore (sender, subject, folder, display time) comes from the `hxstore-decode` heuristics. Folder names can be off by one or duplicated. Index pages and unallocated space are not carved.
- Outlook redacts the content of Osa logs as `pii:<hash>`. Only structure, timing, commands, servers and status codes can be recovered.
- Trace-log events have no names in the file. Labels are derived from constant arguments. Object IDs with high flag bits are not matched to the store.
- AccountsBackup property names are numeric HxCore IDs whose meaning is undocumented.
- The legacy `Files` virtual table in `Outlook.sqlite` needs Outlook's own SQLite module and cannot be read.
- The `.hfl` files are ring buffers: older records are overwritten, so a log can start well after its creation time.

---

## 9. Troubleshooting

| Problem | Fix |
|---|---|
| `SyntaxError` / `TypeError ... slots` when HxStore is parsed | Use Python 3.10 or newer (`python3 --version`). |
| Findings say "HxStore.hxd not decoded" | Check that `tools/hxstore-decode/src/hxdecode/` exists next to `tools/olk_forensic.py`, and that you use Python 3.10+. |
| HxStore step is slow | `pip install lz4` in the Python you run the tool with. |
| Every file time in the inventory is the same | The profile was copied without preserving times. Re-acquire with `ditto` or `cp -Rp`. |
| The output is too large | Use `--hfl-mode summary`. Most of the size is the per-record trace-log table and its JSONL. |
| Permission denied on the live profile | Copy the profile first (section 3). On macOS, Terminal may need Full Disk Access. |

### Running the unit tests

The tests in `tests/` build small synthetic artifacts (trace log, account backup, Osa logs, olk15, plists, lock table, legacy SQLite with a WAL, cache files), so they need no evidence and no extra packages:

```bash
python3.12 -B -m unittest discover -s tests -v      # about 1 s, 89 tests
python3.12 -B -m pytest tests -q                    # same tests, if pytest is installed
```

Two optional tests check a real profile, read-only: HxStore decoding, and the trace-log well-formedness properties W1–W4 over every chunk of `hxcore.hfl`. They take about 30 s:

```bash
OLK_PROFILE="Main Profile" python3.12 -B -m unittest discover -s tests -k RealProfile -v
```

---

## 10. Related tools in `tools/`

| Tool | Purpose |
|---|---|
| `hfl_parse.py` | Stand-alone, in-depth decoder for one `.hfl` file. Options include `--sqlite`, `--jsonl`, `--timeline`, `--catalog`, `--find-id` and `--hxstore-extract`. Run `python3 tools/hfl_parse.py -h`. |
| `hfl_report.py` | HTML report for a database written by `hfl_parse.py --sqlite`. |
| `hxstore_export.py` | Exports `HxStore.hxd` objects to JSON for `hfl_parse.py --hxstore-extract`. |

---

## 11. Documentation

Full documentation (artifact formats, database reference, forensic soundness, API) is in `docs/` and is built by Read the Docs from `.readthedocs.yaml`. To build it locally:

```bash
python3.12 -m venv .docenv && .docenv/bin/pip install -r docs/requirements.txt
.docenv/bin/sphinx-build -W -b html docs docs/_build/html
```

## 12. License

`tools/hxstore-decode/` is third-party code under the MIT licence (see `tools/hxstore-decode/LICENSE`).

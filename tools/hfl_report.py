#!/usr/bin/env python3
"""
hfl_report.py - build a self-contained HTML report from the SQLite database written by
hfl_parse.py (v3).

    python3 -I hfl_report.py hxcore_decoded.db hxcore_report.html --tz 7
"""
import argparse
import datetime
import html
import json
import sqlite3
import sys

LEVEL_NAMES = {2: "Error", 4: "Info", 5: "Verbose"}


def esc(x):
    return html.escape("" if x is None else str(x))


def fmt_n(n):
    return "{:,}".format(n) if isinstance(n, int) else esc(n)


def shift(ts, tzh):
    if ts is None:
        return ""
    t = datetime.datetime.strptime(ts[:19], "%Y-%m-%d %H:%M:%S") + datetime.timedelta(hours=tzh)
    return t.strftime("%Y-%m-%d %H:%M:%S") + ts[19:23]


def table(headers, rows, cls=""):
    out = ['<div class="tw"><table class="%s"><thead><tr>' % cls]
    out += ["<th>%s</th>" % esc(h) for h in headers]
    out.append("</tr></thead><tbody>")
    for r in rows:
        out.append("<tr>" + "".join(
            '<td class="num">%s</td>' % fmt_n(c) if isinstance(c, int) else "<td>%s</td>" % (
                c[1] if isinstance(c, tuple) and c[0] == "html" else esc(c)) for c in r) + "</tr>")
    out.append("</tbody></table></div>")
    return "".join(out)


def bar_chart(points, tzlabel, err_by_hour):
    """points = [(label 'YYYY-MM-DD HH', count)]; inline SVG bar chart."""
    if not points:
        return ""
    w_bar, gap, h = 14, 3, 180
    mx = max(c for _, c in points)
    width = len(points) * (w_bar + gap) + 60
    s = ['<svg class="chart" viewBox="0 0 %d %d" role="img" aria-label="Records per hour">' % (width, h + 50)]
    for frac in (0, 0.5, 1):
        y = 10 + h - frac * h
        s.append('<line x1="50" x2="%d" y1="%.1f" y2="%.1f" class="grid"/>' % (width, y, y))
        s.append('<text x="44" y="%.1f" class="ax" text-anchor="end">%s</text>' % (y + 4, "{:,}".format(int(mx * frac))))
    for i, (lab, c) in enumerate(points):
        x = 54 + i * (w_bar + gap)
        bh = c / mx * h if mx else 0
        e = err_by_hour.get(lab, 0)
        s.append('<rect x="%d" y="%.1f" width="%d" height="%.1f" rx="2" class="bar%s"><title>%s:00 %s - %s records%s</title></rect>'
                 % (x, 10 + h - bh, w_bar, max(bh, 1), " err" if e else "", lab, tzlabel, "{:,}".format(c),
                    (", %d errors" % e) if e else ""))
        if lab.endswith(" 00") or i == 0:
            s.append('<text x="%d" y="%d" class="ax">%s</text>' % (x, h + 28, lab[5:10]))
        if int(lab[-2:]) % 6 == 0:
            s.append('<text x="%d" y="%d" class="ax small">%s</text>' % (x, h + 42, lab[-2:] + "h"))
    s.append("</svg>")
    return "".join(s)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("db")
    ap.add_argument("out")
    ap.add_argument("--tz", type=float, default=0.0, help="display offset from UTC in hours")
    a = ap.parse_args()
    tz = a.tz
    tzlabel = "UTC" if tz == 0 else "UTC%+g" % tz
    db = sqlite3.connect(a.db)
    q = lambda sql, *p: db.execute(sql, p).fetchall()
    meta = {k: v for k, v in q("SELECT key, value FROM meta")}
    hdr = json.loads(meta["header"])
    stats = json.loads(meta["stats"])
    gaps = json.loads(meta["gaps"])
    sys.stderr.write("querying...\n")

    n_rec = q("SELECT count(*) FROM records")[0][0]
    n_args = q("SELECT count(*) FROM args")[0][0]
    n_threads = q("SELECT count(DISTINCT thread) FROM records")[0][0]
    n_act = q("SELECT count(DISTINCT activity) FROM records WHERE activity IS NOT NULL")[0][0]
    n_events = q("SELECT count(*) FROM events")[0][0]
    levels = q("SELECT level, level_name, count(*) FROM records GROUP BY level ORDER BY level")
    n_err = sum(c for l, _, c in levels if l <= 2)
    areas = q("SELECT area, count(*), count(DISTINCT event), count(DISTINCT thread) FROM records GROUP BY area ORDER BY 2 DESC")
    mod = "%+d hours" % int(tz) if tz == int(tz) else "%+d minutes" % int(tz * 60)
    hours = q("SELECT strftime('%Y-%m-%d %H', time_utc, ?), count(*) FROM records GROUP BY 1 ORDER BY 1", mod)
    err_h = dict(q("SELECT strftime('%Y-%m-%d %H', time_utc, ?), count(*) FROM records WHERE level<=2 GROUP BY 1", mod))
    threads = q("SELECT thread, count(*), min(time_utc), max(time_utc), count(DISTINCT event_key) FROM records GROUP BY thread ORDER BY 2 DESC LIMIT 15")
    events = q("SELECT event_key, label, count, level, signature, threads, first_time, last_time, string_args, examples FROM events ORDER BY count DESC")
    errors = q("SELECT event_key, count(*), min(time_utc), max(time_utc), count(DISTINCT thread) FROM records WHERE level<=2 GROUP BY 1 ORDER BY 2 DESC")
    err_samples, err_ctx, err_minutes = {}, {}, {}
    for ek, *_ in errors:
        err_samples[ek] = q("SELECT time_utc, thread, summary, activity FROM records WHERE level<=2 AND event_key=? ORDER BY stamp_ns LIMIT 8", ek)
        fid, fst, fth = q("SELECT id, stamp_ns, thread FROM records WHERE level<=2 AND event_key=? ORDER BY stamp_ns LIMIT 1", ek)[0]
        err_ctx[ek] = q("""SELECT time_utc, thread, level_name, event_key, summary FROM records
                           WHERE thread=? AND stamp_ns BETWEEN ?-5000000000 AND ? ORDER BY stamp_ns DESC LIMIT 12""", fth, fst, fst)[::-1]
        err_minutes[ek] = q("SELECT count(DISTINCT substr(time_utc,1,16)) FROM records WHERE level<=2 AND event_key=?", ek)[0][0]
    sys.stderr.write("querying operations...\n")
    tasks = q("""SELECT a.value_text, count(*) FROM args a JOIN records r ON r.id=a.record_id
                 WHERE r.event_key='7.43' AND a.i=2 AND a.value_text NOT LIKE 'Completed:%'
                 GROUP BY 1 ORDER BY 2 DESC LIMIT 40""")
    triggers = q("""SELECT value_text, count(*) FROM args WHERE type IN ('str16','str8')
                    AND value_text LIKE 'TriggerEvent:%' GROUP BY 1 ORDER BY 2 DESC LIMIT 25""")
    sessions = q("""SELECT value_text, count(*) FROM args WHERE type IN ('str16','str8')
                    AND value_text LIKE 'ParkSession:%' GROUP BY 1 ORDER BY 2 DESC LIMIT 15""")
    sys.stderr.write("querying strings...\n")
    strings = q("""SELECT value_text, count(*), count(DISTINCT r.event_key) FROM args a JOIN records r ON r.id=a.record_id
                   WHERE a.type IN ('str16','str8') AND a.meaning IS NULL AND length(a.value_text) >= 4
                   GROUP BY 1 ORDER BY 2 DESC LIMIT 80""")
    urls = q("""SELECT value_text, count(*), min(r.time_utc), max(r.time_utc) FROM args a JOIN records r ON r.id=a.record_id
                WHERE a.type IN ('str16','str8') AND (value_text LIKE 'http%' OR value_text LIKE '%://%')
                GROUP BY 1 ORDER BY 2 DESC LIMIT 40""")
    n_pii = q("SELECT count(*), count(DISTINCT value_text) FROM args WHERE meaning LIKE 'redacted%'")[0]
    n_tags = q("SELECT count(*), count(DISTINCT value_text) FROM args WHERE meaning = 'log-site tag'")[0]
    sys.stderr.write("querying objects...\n")
    otypes = q("""SELECT object_type, count(*), count(DISTINCT object_id) FROM args
                  WHERE object_type IS NOT NULL AND object_id != 0 GROUP BY 1 ORDER BY 2 DESC LIMIT 20""")
    objs = q("""SELECT object_id, count(*), group_concat(DISTINCT object_type) FROM args
                WHERE object_id IS NOT NULL AND object_id > 0 GROUP BY object_id ORDER BY 2 DESC LIMIT 20""")
    n_objs = q("SELECT count(DISTINCT object_id) FROM args WHERE object_id > 0")[0][0]
    types = q("SELECT type, count(*) FROM args GROUP BY 1 ORDER BY 2 DESC")
    meanings = q("""SELECT CASE WHEN meaning LIKE 'object id%' THEN 'object id'
                               WHEN meaning LIKE 'hex blob%' THEN 'hex blob (serialized data)'
                               WHEN meaning LIKE 'HRESULT%' THEN 'HRESULT error code'
                               WHEN meaning LIKE '%UTC (%' THEN 'date/time'
                               WHEN meaning LIKE '%bytes%' THEN 'byte array'
                               ELSE meaning END, count(*)
                    FROM args WHERE meaning IS NOT NULL GROUP BY 1 ORDER BY 2 DESC""")
    hresults = q("SELECT meaning, count(*) FROM args WHERE meaning LIKE 'HRESULT%' GROUP BY 1 ORDER BY 2 DESC LIMIT 15")
    dates = q("""SELECT substr(meaning,1,10), count(*) FROM args WHERE meaning LIKE '%UTC (%'
                 GROUP BY 1 ORDER BY 2 DESC LIMIT 15""")
    chunks = q("SELECT count(*), sum(comp_len), sum(decoded_len), min(records), max(records), avg(records) FROM chunks")[0]
    has_corr = bool(q("SELECT name FROM sqlite_master WHERE name='object_activity'"))
    corr = {}
    if has_corr:
        sys.stderr.write("querying HxStore correlation...\n")
        hxm = json.loads(meta.get("hxstore", "{}"))
        corr["meta"] = hxm
        corr["top_stored"] = q("""SELECT object_id, store_type, store_label, log_mentions, first_seen_utc, last_seen_utc, top_events
                                  FROM object_activity WHERE in_store=1 AND log_mentions>0 ORDER BY log_mentions DESC LIMIT 30""")
        corr["emails"] = q("""SELECT object_id, sender_email, subject, mail_timestamp, log_mentions, first_seen_utc, last_seen_utc, top_events
                              FROM email_activity WHERE log_mentions>0 ORDER BY first_seen_utc LIMIT 200""")
        corr["folders"] = q("""SELECT o.object_id, s.folder, o.log_mentions, o.first_seen_utc, o.last_seen_utc, o.top_events
                               FROM object_activity o JOIN store_objects s ON s.record_id=o.object_id
                               WHERE s.folder IS NOT NULL ORDER BY o.log_mentions DESC""")
        corr["missing"] = q("""SELECT object_id, log_mentions, first_seen_utc, last_seen_utc, log_object_types, top_events
                               FROM object_activity WHERE in_store=0 ORDER BY log_mentions DESC LIMIT 40""")
        corr["missing_n"] = q("SELECT count(*), sum(log_mentions) FROM object_activity WHERE in_store=0")[0]
        corr["types"] = q("""SELECT coalesce(store_type,'(not in store)'), count(*), sum(log_mentions)
                             FROM object_activity WHERE log_mentions>0 GROUP BY 1 ORDER BY 3 DESC LIMIT 20""")
        corr["never"] = q("""SELECT type_name, count(*) FROM store_objects s
                             WHERE NOT EXISTS (SELECT 1 FROM object_activity o WHERE o.object_id=s.record_id AND o.log_mentions>0)
                             GROUP BY 1 ORDER BY 2 DESC""")
        corr["err_objs"] = q("""SELECT r.event_key, a.object_id, coalesce(a.store_label,'(not in store)'), count(*), min(r.time_utc), max(r.time_utc)
                                FROM records r JOIN args a ON a.record_id=r.id
                                WHERE r.level<=2 AND a.object_id>0 GROUP BY 1,2 ORDER BY 4 DESC LIMIT 20""")
    sys.stderr.write("writing html...\n")

    first, last = meta["first_record_utc"], meta["last_record_utc"]
    span_h = (datetime.datetime.strptime(last[:19], "%Y-%m-%d %H:%M:%S") -
              datetime.datetime.strptime(first[:19], "%Y-%m-%d %H:%M:%S")).total_seconds() / 3600

    H = []
    w = H.append
    w("""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>HxCore Trace Report</title>
<style>
:root{--bg:#f7f7f5;--panel:#fff;--ink:#1d1d1b;--mute:#6b6b66;--line:#e3e2dd;--accent:#2f6fdb;--accent2:#c7d9f7;--err:#c4372f;--code:#f0efeb}
@media (prefers-color-scheme:dark){:root:not([data-theme="light"]){--bg:#141413;--panel:#1d1d1b;--ink:#ecebe6;--mute:#9a9992;--line:#33322f;--accent:#6f9ef0;--accent2:#2b3f63;--err:#ec6a61;--code:#272724}}
:root[data-theme="dark"]{--bg:#141413;--panel:#1d1d1b;--ink:#ecebe6;--mute:#9a9992;--line:#33322f;--accent:#6f9ef0;--accent2:#2b3f63;--err:#ec6a61;--code:#272724}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--ink);font:15px/1.55 -apple-system,BlinkMacSystemFont,"Segoe UI",Helvetica,Arial,sans-serif}
main{max-width:1180px;margin:0 auto;padding:28px 16px 80px}
h1{font-size:28px;margin:0 0 4px}h2{font-size:20px;margin:42px 0 10px;padding-top:8px;border-top:1px solid var(--line)}
h3{font-size:16px;margin:22px 0 8px}
.sub{color:var(--mute);margin:0 0 18px}
nav{display:flex;flex-wrap:wrap;gap:6px 14px;margin:14px 0 6px;font-size:14px}
nav a{color:var(--accent);text-decoration:none}
.cards{display:grid;grid-template-columns:repeat(auto-fill,minmax(170px,1fr));gap:10px;margin:18px 0}
.card{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:12px 14px}
.card .v{font-size:22px;font-weight:650;font-variant-numeric:tabular-nums}
.card .k{color:var(--mute);font-size:13px}
.card.err .v{color:var(--err)}
.panel{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:14px 16px;margin:10px 0}
.tw{overflow-x:auto;margin:8px 0;border:1px solid var(--line);border-radius:8px;background:var(--panel)}
table{border-collapse:collapse;width:100%;font-size:13.5px}
th,td{padding:6px 10px;border-bottom:1px solid var(--line);text-align:left;vertical-align:top}
th{background:var(--code);font-weight:600;white-space:nowrap;position:sticky;top:0}
td.num{text-align:right;font-variant-numeric:tabular-nums;white-space:nowrap}
tr:last-child td{border-bottom:0}
code,.mono,td.m{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:12.5px}
code{background:var(--code);padding:1px 5px;border-radius:4px}
pre{background:var(--code);padding:12px 14px;border-radius:8px;overflow-x:auto;font-size:12.5px;line-height:1.45}
.chart{width:100%;height:auto;display:block}
.chart .bar{fill:var(--accent)}.chart .bar.err{fill:var(--err)}
.chart .grid{stroke:var(--line);stroke-width:1}.chart .ax{fill:var(--mute);font-size:10px}.chart .small{font-size:9px}
.legend{font-size:13px;color:var(--mute)}.sw{display:inline-block;width:10px;height:10px;border-radius:2px;margin:0 4px 0 10px;vertical-align:middle}
.two{display:grid;grid-template-columns:1fr 1fr;gap:14px}
@media (max-width:800px){.two{grid-template-columns:1fr}}
details{background:var(--panel);border:1px solid var(--line);border-radius:8px;margin:6px 0;padding:6px 12px}
details summary{cursor:pointer;font-weight:550}
details .ex{font-family:ui-monospace,Menlo,monospace;font-size:12px;color:var(--mute);word-break:break-all}
.tag{display:inline-block;font-size:11.5px;padding:0 6px;border-radius:9px;background:var(--accent2);margin-left:6px;font-weight:500}
.tag.e{background:var(--err);color:#fff}
input[type=search]{width:100%;max-width:420px;padding:8px 10px;border:1px solid var(--line);border-radius:8px;background:var(--panel);color:var(--ink);font-size:14px}
.note{color:var(--mute);font-size:13.5px}
.conf{font-size:12px;color:var(--mute)}
</style></head><body><main>
""")
    w("<h1>HxCore Trace Log Report</h1>")
    w('<p class="sub">Decoded from <code>%s</code> (%s bytes) with hfl_parse.py v%s. Times shown in %s unless marked UTC.</p>'
      % (esc(meta["source_file"]), fmt_n(int(meta["source_size"])), esc(meta["tool_version"]), tzlabel))
    w('<nav>' + "".join('<a href="#%s">%s</a>' % (i, t) for i, t in [
        ("summary", "Summary"), ("file", "File & header"), ("format", "Format"), ("timeline", "Activity over time"),
        ("levels", "Levels & areas"), ("threads", "Threads"), ("errors", "Errors"), ("ops", "Operations & sync"),
        ("strings", "Strings & URLs"), ("objects", "Objects"), ("values", "Value types"), ("events", "Top events"),
        ("catalog", "Full event catalog")] + ([("hxstore", "HxStore correlation")] if has_corr else []) + [("limits", "Limitations"), ("query", "Using the database")]) + "</nav>")

    # ---------------- summary
    w('<h2 id="summary">Summary</h2><div class="cards">')
    for k, v, c in [
        ("records decoded", fmt_n(n_rec), ""), ("arguments decoded", fmt_n(n_args), ""),
        ("payload decoded", "100%" if not stats.get("arg_errors") else "partial", ""),
        ("time span", "%.1f h" % span_h, ""), ("distinct events (area.event)", fmt_n(n_events), ""),
        ("threads", fmt_n(n_threads), ""), ("activities", fmt_n(n_act), ""),
        ("error-level records", fmt_n(n_err), "err"), ("distinct object IDs", fmt_n(n_objs), ""),
        ("LZ4 chunks", fmt_n(chunks[0]), "")]:
        w('<div class="card %s"><div class="v">%s</div><div class="k">%s</div></div>' % (c, v, esc(k)))
    w("</div>")
    w('<div class="panel"><p style="margin:0">The file is a binary <b>trace log</b> written by the HxCore sync engine of '
      'Outlook for Mac (Office build <code>%s</code>). It covers <b>%s</b> to <b>%s</b> %s (%s to %s UTC). '
      'Every one of the %s records in the %s compressed chunks was decompressed and every argument decoded; '
      'the only bytes that could not be read are %s orphan bytes (the remains of an overwritten chunk). '
      '%s records are at Error level, coming from %d distinct events.</p></div>'
      % (esc(hdr.get("office_build")), shift(first, tz)[:19], shift(last, tz)[:19], tzlabel, first[:19], last[:19],
         fmt_n(n_rec), fmt_n(chunks[0]), fmt_n(sum(g[1] for g in gaps)), fmt_n(n_err), len(errors)))

    # ---------------- file
    w('<h2 id="file">File &amp; header</h2><div class="two"><div>')
    w(table(["Field", "Value"], [
        ("File", meta["source_file"]), ("Size", "%s bytes" % fmt_n(int(meta["source_size"]))),
        ("SHA-256", ("html", "<span class='mono'>%s</span>" % esc(meta["source_sha256"]))),
        ("Office build", hdr.get("office_build")), ("Format version", hdr.get("version_0x04")),
        ("Header written (UTC)", hdr.get("created_utc")),
        ("Header written (%s)" % tzlabel, shift(hdr.get("created_utc"), tz)),
        ("Monotonic clock zero (≈ boot, UTC)", hdr.get("monotonic_zero_utc")),
        ("File ID (0x18)", ("html", "<span class='mono'>%s</span>" % esc(hdr.get("file_id_0x18")))),
        ("Unknown u32 at 0x38 / 0x44 / 0x48 / 0x4C", "%s / %s / %s / %s" % (hdr["u32_0x38"], hdr["u32_0x44"], hdr["u32_0x48"], hdr["u32_0x4c"])),
        ("Compressed data", "%s bytes in %s chunks" % (fmt_n(chunks[1]), fmt_n(chunks[0]))),
        ("Decompressed data", "%s bytes (ratio %.1f×)" % (fmt_n(chunks[2]), chunks[2] / chunks[1])),
        ("Records per chunk", "%d – %d (avg %.0f)" % (chunks[3], chunks[4], chunks[5])),
        ("Orphan bytes", ", ".join("%s bytes at offset %s" % (fmt_n(g[1]), fmt_n(g[0])) for g in gaps) or "none"),
    ]))
    w("</div><div>")
    w("<h3 style='margin-top:0'>Embedded settings</h3>")
    w(table(["Setting", "Value"], list(hdr.get("settings", {}).items())))
    tf = hdr.get("text_fields", [])
    if len(tf) >= 3:
        w("<p class='note'>Other text-block fields (meaning unknown, base64): <code>%s</code>, <code>%s</code></p>" % (esc(tf[1]), esc(tf[2])))
    w("</div></div>")

    # ---------------- format
    w('<h2 id="format">Decoded format</h2>')
    w('<p class="note">(C) = confirmed on every record of this file; (?) = inferred.</p><div class="two"><div>')
    w("<h3>Record (inside each decompressed chunk)</h3>")
    w(table(["Offset", "Type", "Field"], [
        ("+0x00", "16 B", "activity ID (GUID; zero = none) (C)"), ("+0x10", "u64", "timestamp, ns of monotonic clock (C)"),
        ("+0x18", "u32", "thread ID (C)"), ("+0x1C", "u32", "argument count (C)"), ("+0x20", "u16", "record length, padded to 8 (C)"),
        ("+0x22", "u16", "offset of first argument = 0x28 (C)"), ("+0x24", "u16", "event ID (local to area) (C)"),
        ("+0x26", "u8", "level: 2 Error, 4 Info, 5 Verbose (?)"), ("+0x27", "u8", "area / component (C: area.event fixes the signature)"),
        ("+0x28", "…", "typed arguments, then 0–7 padding bytes (stale memory)")], "m"))
    w("<h3>Chunk</h3>")
    w(table(["Offset", "Field"], [
        ("+0x00 u32", "total chunk length (C)"), ("+0x04 u32", "decoded size + 0x28 (C)"),
        ("+0x08 u32", "decoded size + size of the record that did not fit (?)"), ("+0x1C", "DE AD BE EF marker (C)"),
        ("+0x20 u32", "stream write offset (C/?)"), ("+0x28", "raw LZ4 block (C)")], "m"))
    w("</div><div><h3>Argument type codes</h3>")
    w(table(["Byte", "Type", "Encoding"], [
        ("01", "str8", "u32 byte count + UTF-8"), ("02", "str16", "u32 char count + UTF-16LE"), ("03", "i32", "4 bytes"),
        ("04", "u64", "8 bytes (often a pointer)"), ("05", "u32", "4 bytes"), ("06", "bool", "1 byte"), ("07", "f64", "8-byte double"),
        ("08", "guid", "16 bytes; first 8 zero ⇒ object ID"), ("0C", "bytes", "u32 count + bytes"), ("13", "u8", "1 byte"),
        ("15", "u16", "2 bytes (before a guid ⇒ object type)"), ("16", "i64", "8 bytes")], "m"))
    w("<h3>Time conversion</h3><p class='note'>UTC = header .NET ticks (0x08) − header monotonic stamp (0x10) + record stamp. "
      "The last record (%s UTC) matches the file's modification time.</p>" % esc(last[:19]))
    w("</div></div>")

    # ---------------- timeline
    w('<h2 id="timeline">Activity over time</h2>')
    w('<p class="legend">Records per hour (%s). <span class="sw" style="background:var(--accent)"></span>hour without errors'
      '<span class="sw" style="background:var(--err)"></span>hour containing Error-level records. Hover a bar for the numbers.</p>' % tzlabel)
    w('<div class="panel">%s</div>' % bar_chart(hours, tzlabel, err_h))
    busiest = sorted(hours, key=lambda x: -x[1])[:5]
    w("<p class='note'>Busiest hours: %s.</p>" % ", ".join("%s:00 (%s)" % (esc(h), fmt_n(c)) for h, c in busiest))

    # ---------------- levels / areas
    w('<h2 id="levels">Levels &amp; areas</h2><div class="two"><div>')
    w(table(["Level", "Name", "Records", "Share"], [(l, LEVEL_NAMES.get(l, n), c, "%.2f%%" % (100 * c / n_rec)) for l, n, c in levels]))
    w("</div><div>")
    w(table(["Area", "Records", "Distinct events", "Threads"], areas))
    w("</div></div><p class='note'>An <b>area</b> is a component/provider; event IDs are numbered separately within each area, "
      "so events are referred to as <code>area.event</code>.</p>")

    # ---------------- threads
    w('<h2 id="threads">Threads</h2><p class="note">%s distinct thread IDs. Thread 3 is the main engine thread; '
      'most other IDs are short-lived worker threads.</p>' % fmt_n(n_threads))
    w(table(["Thread", "Records", "First (%s)" % tzlabel, "Last (%s)" % tzlabel, "Distinct events"],
            [(str(t), c, shift(f, tz), shift(l, tz), e) for t, c, f, l, e in threads]))

    # ---------------- errors
    w('<h2 id="errors">Errors</h2>')
    w(table(["Event", "Records", "First (%s)" % tzlabel, "Last (%s)" % tzlabel, "Threads"],
            [(e, c, shift(f, tz), shift(l, tz), t) for e, c, f, l, t in errors]))
    for ek, *_ in errors:
        w("<h3>Event %s</h3><p class='note'>Occurs in %d distinct minutes. First records:</p>" % (esc(ek), err_minutes[ek]))
        w(table(["Time (%s)" % tzlabel, "Thread", "Decoded arguments", "Activity"],
                [(shift(t, tz), str(th), ("html", "<span class='mono'>%s</span>" % esc(s or "(no arguments)")), a or "") for t, th, s, a in err_samples[ek]]))
        w("<details><summary>Context: records on the same thread just before the first occurrence</summary>")
        w(table(["Time (%s)" % tzlabel, "Thread", "Level", "Event", "Decoded arguments"],
                [(shift(t, tz), str(th), lv, e2, ("html", "<span class='mono'>%s</span>" % esc((sm or "")[:200]))) for t, th, lv, e2, sm in err_ctx[ek]]))
        w("</details>")
    w("<p class='note'>Event 4.1011 carries a log-site tag (<code>be2xk</code>) and the object it failed on; events with no "
      "arguments only record that the error happened.</p>")

    # ---------------- operations
    w('<h2 id="ops">Operations &amp; sync</h2><div class="two"><div>')
    w("<h3>Engine tasks run (event 7.43, excluding “Completed:”)</h3>")
    w(table(["Task name", "Runs"], tasks))
    w("</div><div><h3>Sync triggers</h3>")
    w(table(["Trigger", "Mentions"], triggers))
    w("<h3>Sync sessions parked</h3>")
    w(table(["Session", "Mentions"], sessions))
    w("</div></div>")

    # ---------------- strings
    w('<h2 id="strings">Strings &amp; URLs</h2>')
    w("<p class='note'>%s values were redacted by Outlook as <code>pii:&lt;hash&gt;</code> (%s distinct hashes). "
      "%s log-site tags were recorded (%s distinct). The table below lists plain text arguments (not tags, IDs, PII or hex).</p>"
      % (fmt_n(n_pii[0]), fmt_n(n_pii[1]), fmt_n(n_tags[0]), fmt_n(n_tags[1])))
    w('<div class="two"><div>')
    w(table(["Text", "Count", "Events"], strings[:80]))
    w("</div><div><h3 style='margin-top:0'>URLs</h3>")
    w(table(["URL", "Count", "First (%s)" % tzlabel, "Last (%s)" % tzlabel], [(u, c, shift(f, tz), shift(l, tz)) for u, c, f, l in urls]))
    w("</div></div>")

    # ---------------- objects
    w('<h2 id="objects">Objects</h2>')
    w("<p class='note'>Store objects are referenced by 64-bit IDs, either as a 16-byte ID with a zero upper half (with the "
      "object's type number as a u16 before it) or as hex text. %s distinct object IDs were seen. The type numbers are "
      "internal to HxCore and have no names in the file.</p>" % fmt_n(n_objs))
    w('<div class="two"><div><h3>Object types</h3>')
    w(table(["Type", "Mentions", "Distinct objects"], otypes))
    w("</div><div><h3>Most referenced objects</h3>")
    w(table(["Object ID", "Hex", "Mentions", "Types seen"], [(str(o), "#0x%X" % o, c, t or "") for o, c, t in objs]))
    w("</div></div>")

    # ---------------- values
    w('<h2 id="values">Value types &amp; interpretations</h2><div class="two"><div>')
    w(table(["Argument type", "Count"], types))
    w("</div><div>")
    w(table(["Interpretation", "Count"], meanings))
    if hresults:
        w("<h3>HRESULT codes</h3>")
        w(table(["Code", "Count"], hresults))
    if dates:
        w("<h3>Dates found inside arguments (by day)</h3>")
        w(table(["Date (UTC)", "Count"], dates))
    w("</div></div>")

    # ---------------- top events
    w('<h2 id="events">Top 30 events</h2>')
    rows = []
    for (ek, lab, cnt, lvl, sig, thr, f, l, strs, ex) in events[:30]:
        exs = json.loads(ex)
        rows.append((ek, lab or "", cnt, lvl, ("html", "<span class='mono'>%s</span>" % esc(sig)),
                     ("html", "<span class='mono'>%s</span>" % esc((exs[0] if exs else "")[:140]))))
    w(table(["Event", "Auto label", "Count", "Levels", "Signature", "Example"], rows))
    w("<p class='note'>Signature letters: s str8, S str16, i i32, I u32, q i64, Q u64, H u16, B u8, ? bool, d f64, "
      "G guid/object, b bytes. A label is given only when an event always carries the same text or log tag.</p>")

    # ---------------- catalog
    w('<h2 id="catalog">Full event catalog (%d events)</h2>' % len(events))
    w('<input type="search" id="q" placeholder="Filter by event, label, string or example…" aria-label="Filter catalog">')
    w('<div id="cat">')
    for (ek, lab, cnt, lvl, sig, thr, f, l, strs, ex) in events:
        err = "ERROR" in (lvl or "")
        w('<details><summary>%s%s<span class="tag">%s</span>%s</summary>' % (
            esc(ek), (" – " + esc(lab)) if lab else "", fmt_n(cnt), '<span class="tag e">error</span>' if err else ""))
        w("<div class='note'>levels %s · threads %s · %s → %s UTC</div>" % (esc(lvl), esc(thr), esc(f), esc(l)))
        w("<div class='note'>signature <code>%s</code></div>" % esc(sig))
        for k, vals in json.loads(strs).items():
            w("<div class='note'>string arg[%s]: %s</div>" % (esc(k), esc(", ".join("%r ×%d" % (v, n) for v, n in vals))))
        for x in json.loads(ex):
            w("<div class='ex'>e.g. %s</div>" % esc(x[:400]))
        w("</details>")
    w("</div>")

    # ---------------- HxStore correlation
    if has_corr:
        cm = corr["meta"].get("correlation") or {}
        info = corr["meta"].get("info") or {}
        w('<h2 id="hxstore">Correlation with HxStore.hxd</h2>')
        w('<p class="note">The object IDs in the trace log are the record IDs of Outlook\'s database '
          '<code>HxStore.hxd</code>. The store was extracted with the hxstore-decode tool (hxdecode CLI + '
          'hxstore_export.py) and every logged object ID was looked up in it.</p>')
        w('<div class="cards">')
        for k, v, c in [
            ("log object IDs found in store", "%s / %s" % (fmt_n(cm.get("log_ids_in_store", 0)), fmt_n(cm.get("log_object_ids", 0))), ""),
            ("object mentions resolved", "%.0f%%" % (100.0 * cm.get("log_mentions_resolved", 0) / max(1, cm.get("log_mentions", 1))), ""),
            ("logged objects not in store", fmt_n(corr["missing_n"][0] or 0), "err"),
            ("e-mails with log activity", "%s / %s" % (fmt_n(cm.get("emails_with_log_activity", 0)), fmt_n(cm.get("emails_in_store", 0))), ""),
            ("folders with log activity", fmt_n(cm.get("folders_with_log_activity", 0)), ""),
            ("store objects never logged", "%s / %s" % (fmt_n(cm.get("store_ids_never_logged", 0)), fmt_n(cm.get("store_ids", 0))), "")]:
            w('<div class="card %s"><div class="v">%s</div><div class="k">%s</div></div>' % (c, v, esc(k)))
        w("</div>")
        w(table(["Store file", "Value"], [("File", info.get("source_file")), ("Size", "%s bytes" % fmt_n(info.get("size", 0))),
                                         ("SHA-256", ("html", "<span class='mono'>%s</span>" % esc(info.get("sha256")))),
                                         ("Record versions / distinct IDs", "%s / %s" % (fmt_n(info.get("records", 0)), fmt_n(info.get("distinct_record_ids", 0)))),
                                         ("Pages", json.dumps(info.get("pages"))), ("Extracted with", info.get("tool"))]))
        w("<h3>Objects behind the errors</h3>")
        w(table(["Error event", "Object", "What the store holds", "Records", "First (%s)" % tzlabel, "Last (%s)" % tzlabel],
                [(e, "#0x%X" % o, l, c, shift(f, tz), shift(la, tz)) for e, o, l, c, f, la in corr["err_objs"]]))
        w('<div class="two"><div><h3>Logged objects by store type</h3>')
        w(table(["Store type", "Objects", "Log mentions"], corr["types"]))
        w("</div><div><h3>Stored objects never touched in the log</h3>")
        w(table(["Store type", "Objects"], corr["never"]))
        w("</div></div>")
        w("<h3>Folders</h3><p class='note'>Folder names come from the hxstore-decode heuristic and may be off by one entry for some folders.</p>")
        w(table(["Folder ID", "Folder", "Log mentions", "First (%s)" % tzlabel, "Last (%s)" % tzlabel, "Top events"],
                [("#0x%X" % o, f, n, shift(a1, tz), shift(a2, tz), ev) for o, f, n, a1, a2, ev in corr["folders"]]))
        w("<h3>Most active stored objects</h3>")
        w(table(["Object", "Store type", "What the store holds", "Log mentions", "First (%s)" % tzlabel, "Last (%s)" % tzlabel, "Top events"],
                [("#0x%X" % o, t, l, n, shift(a1, tz), shift(a2, tz), ev) for o, t, l, n, a1, a2, ev in corr["top_stored"]]))
        w("<h3>E-mails the engine touched during the logged period (%d)</h3>" % len(corr["emails"]))
        w("<p class='note'>Mail time is the timestamp hxdecode extracted from the stored record; first/last seen are the times the "
          "object ID appears in the trace log.</p>")
        w(table(["Object", "Sender", "Subject", "Mail time (UTC)", "Log mentions", "First seen (%s)" % tzlabel, "Last seen (%s)" % tzlabel, "Top events"],
                [("#0x%X" % o, se or "", (su or "")[:90], (mt or "")[:19], n, shift(a1, tz), shift(a2, tz), ev)
                 for o, se, su, mt, n, a1, a2, ev in corr["emails"]]))
        w("<h3>Objects touched in the log but absent from the store (top 40 of %s)</h3>" % fmt_n(corr["missing_n"][0] or 0))
        w("<p class='note'>These IDs were handled by the engine during the logged period but no record with that ID exists in this copy "
          "of HxStore.hxd. They may have been <b>deleted</b> afterwards, been transient objects that were never persisted, or "
          "be numbers that only look like object IDs. The u16 types seen in the log hint at what they were.</p>")
        w(table(["Object", "Log mentions", "First (%s)" % tzlabel, "Last (%s)" % tzlabel, "Types in log", "Top events"],
                [("#0x%X" % o, n, shift(a1, tz), shift(a2, tz), lt, ev) for o, n, a1, a2, lt, ev in corr["missing"]]))
        w("<p class='note'>SQL: <code>SELECT * FROM object_timeline WHERE object_id = 0x4F6D19 ORDER BY time_utc;</code> · "
          "<code>SELECT * FROM email_activity;</code> · <code>SELECT * FROM deleted_or_missing_objects;</code></p>")

    # ---------------- limitations
    w('<h2 id="limits">Limitations</h2><div class="panel"><ul style="margin:0;padding-left:20px">'
      "<li><b>Event names are not in the file.</b> Only numeric IDs are logged; labels here are taken from constant text arguments. "
      "Use <code>--event-names names.json</code> with hfl_parse.py to add your own names.</li>"
      "<li><b>Argument names are not in the file.</b> Integer arguments are shown by position only.</li>"
      "<li><b>Hex blobs</b> (serialized object state) are shown as bytes with embedded object IDs and text; their inner layout is unknown.</li>"
      "<li><b>Level names</b> follow the ETW convention (2 Error, 4 Info, 5 Verbose); this is inferred.</li>"
      "<li><b>Personal data</b> was replaced by Outlook with <code>pii:</code> hashes before logging and cannot be recovered.</li>"
      "<li><b>%s orphan bytes</b> belong to a chunk whose start was overwritten (the log is a ring buffer) and cannot be decompressed.</li>"
      "<li>The <b>time conversion</b> assumes no reboot during the logged period; all stamps lie after the header stamp, consistent with that.</li>"
      "</ul></div>" % fmt_n(sum(g[1] for g in gaps)))

    # ---------------- query
    w('<h2 id="query">Using the database</h2>')
    w("<p class='note'>Tables: <code>records</code> (one row per event, with <code>summary</code> and JSON <code>args</code>), "
      "<code>args</code> (one row per argument, with <code>meaning</code>, <code>object_id</code>, <code>object_type</code>), "
      "<code>events</code> (the catalog), <code>chunks</code>, <code>gaps</code>, <code>meta</code>, and the view "
      "<code>record_view</code>. Times in the database are UTC.</p>")
    w("<pre>-- readable timeline of errors\nSELECT time_utc, thread, event_key, summary FROM record_view WHERE level_name='ERROR' ORDER BY time_utc;\n\n"
      "-- everything about one object\nSELECT r.time_utc, r.event_key, r.summary FROM args a JOIN records r ON r.id=a.record_id\n"
      " WHERE a.object_id = 0x4F7225 ORDER BY r.stamp_ns;\n\n"
      "-- all records of one activity, in order\nSELECT time_utc, thread, event_key, summary FROM records WHERE activity='&lt;guid&gt;' ORDER BY stamp_ns;\n\n"
      "-- local time (UTC%+g)\nSELECT datetime(time_utc, '%s'), summary FROM records LIMIT 10;</pre>" % (tz, mod))
    w("""<script>
(function(){var q=document.getElementById('q'),items=[].slice.call(document.querySelectorAll('#cat details'));
q.addEventListener('input',function(){var t=q.value.toLowerCase();items.forEach(function(d){
d.style.display=!t||d.textContent.toLowerCase().indexOf(t)>=0?'':'none';});});})();
</script>""")
    w("<p class='note' style='margin-top:40px'>Generated %s by hfl_report.py from %s.</p></main></body></html>"
      % (datetime.datetime.now().strftime("%Y-%m-%d %H:%M"), esc(a.db)))
    with open(a.out, "w", encoding="utf-8") as fh:
        fh.write("".join(H))
    sys.stderr.write("wrote %s\n" % a.out)


if __name__ == "__main__":
    main()

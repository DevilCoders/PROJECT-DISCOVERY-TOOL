"""Local JSON, Markdown and offline interactive HTML report generation."""
from __future__ import annotations

import heapq
import html
import io
import json
import re
import secrets
from importlib.resources import files as resource_files
from itertools import islice
from pathlib import Path
from typing import Any, TextIO

from .models import REPORT_SCHEMA_VERSION, ScanResult

# The offline HTML report embeds bounded slices so browsers can open reports of very
# large projects; the JSON report always carries the complete data set.
HTML_MAX_EMBEDDED = {
    "findings": 50_000,
    "files": 100_000,
    "directories": 50_000,
    "symlinks": 50_000,
    "special_entries": 50_000,
    "errors": 10_000,
}
_TEMPLATE_PLACEHOLDER = re.compile(r"__(ROOT|GENERATED|REPORT_JS|CSP_NONCE)__")


def _script_json(value: Any) -> str:
    """Serialize report data safely for an inline script block."""
    return (
        json.dumps(value, ensure_ascii=False, separators=(",", ":"))
        .replace("&", "\\u0026")
        .replace("<", "\\u003c")
        .replace(">", "\\u003e")
        .replace("\u2028", "\\u2028")
        .replace("\u2029", "\\u2029")
    )


def _html_template(result: ScanResult, *, nonce: str, data_marker: str) -> str:
    """Return the report shell with a unique data marker where the payload belongs.

    Placeholders are substituted in a single pass, so user-controlled text such as a
    project path containing "__DATA__" is never re-scanned as a template directive.
    """
    report_js = resource_files("project_discovery").joinpath("web/report.js").read_text(encoding="utf-8")
    if report_js.count("__DATA__") != 1:
        raise RuntimeError("report.js must contain exactly one __DATA__ placeholder")
    values = {
        "ROOT": html.escape(result.root),
        "GENERATED": html.escape(result.finished_at),
        "REPORT_JS": report_js.replace("__DATA__", data_marker),
        "CSP_NONCE": nonce,
    }
    template = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; script-src 'nonce-__CSP_NONCE__'; style-src 'unsafe-inline'; img-src data:; base-uri 'none'; form-action 'none'">
<meta name="referrer" content="no-referrer">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="color-scheme" content="dark">
<title>PDT // Project Intelligence Report</title>
<style>
:root {
 --bg:#070b14;--surface:#0d1423;--panel:#111d30;--panel2:#17263d;--line:#253b59;
 --text:#e8f0fb;--muted:#91a4bd;--cyan:#67e8f9;--green:#86efac;--amber:#fbbf24;
 --red:#fb7185;--shadow:0 18px 55px #0007;
}
*{box-sizing:border-box}html{scroll-behavior:smooth;scroll-padding-top:90px}
body{margin:0;background:radial-gradient(ellipse at 15% 0%,#15304b 0,transparent 35%),var(--bg);
 color:var(--text);font:14px/1.55 Inter,ui-sans-serif,system-ui,-apple-system,Segoe UI,sans-serif}
a{color:var(--cyan);text-decoration:none}a:hover{text-decoration:underline}
.topbar{position:sticky;top:0;z-index:5;display:flex;align-items:center;justify-content:space-between;
 padding:14px clamp(16px,4vw,54px);background:#080e19ef;border-bottom:1px solid var(--line);backdrop-filter:blur(14px)}
.brand{display:flex;align-items:center;gap:12px;font-weight:850;letter-spacing:.12em}
.brand-mark{width:34px;height:34px;display:grid;place-items:center;border:1px solid #2c8199;
 border-radius:10px;color:var(--cyan);background:#0e2a3a;font-size:19px}
.top-meta{color:var(--muted);font:11px ui-monospace,monospace;letter-spacing:.12em}
.shell{max-width:1660px;margin:auto;padding:30px clamp(16px,3vw,42px) 90px}
.hero{position:relative;overflow:hidden;padding:clamp(24px,4vw,44px);border:1px solid #284360;
 border-radius:22px;background:linear-gradient(120deg,#10243b,#0d1729 62%,#142b40);box-shadow:var(--shadow)}
.eyebrow{color:var(--cyan);font:800 11px ui-monospace,monospace;letter-spacing:.2em;text-transform:uppercase}
h1{margin:10px 0 14px;font-size:clamp(28px,4.5vw,48px);letter-spacing:-.04em;line-height:1.05}
.root{max-width:100%;overflow-wrap:anywhere;color:#bfd0e4;font:12px ui-monospace,monospace}
.completed{margin-top:7px;color:var(--muted);font:11px ui-monospace,monospace}
.stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(142px,1fr));gap:12px;margin-top:26px}
.stat{min-width:0;padding:15px 17px;border:1px solid #2a4564;border-radius:13px;background:#0a1728aa}
.stat span{display:block;color:var(--muted);font-size:11px;text-transform:uppercase;letter-spacing:.08em}
.stat strong{display:block;margin-top:5px;font-size:27px;line-height:1.2;overflow-wrap:anywhere}
.stat.cyan strong{color:var(--cyan)}.stat.green strong{color:var(--green)}.stat.amber strong{color:var(--amber)}
.main-grid{display:grid;grid-template-columns:230px minmax(0,1fr);gap:22px;margin-top:22px;align-items:start}
.sidebar{position:sticky;top:82px;padding:18px;border:1px solid var(--line);border-radius:16px;background:var(--surface)}
.sidebar h3{margin:0 0 12px;color:var(--muted);font:800 10px ui-monospace,monospace;letter-spacing:.16em;text-transform:uppercase}
.sidebar a{display:block;padding:8px 9px;margin:2px 0;border-radius:8px;color:#b4c5d9;font-size:12px}
.sidebar a:hover{background:var(--panel2);color:var(--cyan);text-decoration:none}
.content{min-width:0}.section{margin-bottom:20px;padding:22px;border:1px solid var(--line);border-radius:16px;background:linear-gradient(160deg,#111c2d,#0c1421)}
.section-head{display:flex;align-items:center;justify-content:space-between;gap:12px;margin-bottom:16px}
h2{margin:0;font-size:19px;letter-spacing:-.02em}h3{margin:0 0 12px;font-size:14px}
.kicker{color:var(--muted);font:10px ui-monospace,monospace;letter-spacing:.12em;text-transform:uppercase}
.muted{color:var(--muted)}.mono{font-family:ui-monospace,SFMono-Regular,monospace;overflow-wrap:anywhere}
.profile-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(250px,1fr));gap:16px}
.profile-card{padding:16px;border:1px solid var(--line);border-radius:12px;background:#0a1220}
.profile-card h3{color:#c9d8e9}
.bar-row{display:grid;grid-template-columns:minmax(110px,1fr) 3fr auto;gap:9px;align-items:center;margin:9px 0;font-size:11px}
.bar-label{overflow-wrap:anywhere;color:#b5c5d9}.bar-track{height:7px;border-radius:8px;background:#23354c;overflow:hidden}
.bar-fill{height:100%;background:linear-gradient(90deg,#1e7490,var(--cyan));border-radius:8px}
.bar-count{color:var(--muted);font:11px ui-monospace,monospace}
.controls{display:flex;flex-wrap:wrap;gap:9px;margin:14px 0}
input,select{min-width:130px;border:1px solid #2b405c;border-radius:9px;padding:10px 12px;background:#08111e;color:var(--text);outline:none}
input:focus,select:focus,button:focus-visible{outline:2px solid var(--cyan);outline-offset:2px}
input[type=search]{flex:1;min-width:220px}
button{cursor:pointer;border:1px solid #34506e;border-radius:9px;padding:9px 12px;background:#162940;color:#d7e8f7}
button:hover{border-color:var(--cyan);color:var(--cyan)}button.primary{background:#0c3a4b;border-color:#26748b;color:#a5f3fc}
button:disabled{opacity:.45;cursor:not-allowed}
.finding-list{display:grid;gap:9px}
.finding{border:1px solid var(--line);border-radius:12px;background:#0b1524;overflow:hidden}
.finding details{padding:0 14px}
.finding summary{display:flex;align-items:center;gap:9px;min-height:52px;cursor:pointer;list-style:none}
.finding summary::-webkit-details-marker{display:none}
.finding summary:before{content:"›";color:var(--cyan);font-size:20px;transition:transform .15s}
.finding details[open] summary:before{transform:rotate(90deg)}
.finding-title{flex:1;min-width:110px;font-weight:700;overflow-wrap:anywhere}
.badge{flex:none;padding:3px 8px;border-radius:20px;background:#26384f;color:#d7e4f2;font:800 9px ui-monospace,monospace;letter-spacing:.06em}
.badge.confirmed{color:var(--green)}.badge.inferred{color:var(--amber)}.badge.unknown{color:#fda4af}
.badge.sev-critical,.badge.sev-high{background:#571d2d;color:#fecdd3}
.badge.sev-medium{background:#493718;color:#fde68a}.badge.sev-low{color:var(--cyan)}
.finding-body{padding:0 0 15px 25px;color:#c6d5e5}.finding-body p{margin:8px 0 12px}
.evidence{padding:12px;border:1px solid #20334b;border-radius:9px;background:#07101d}
.evidence ul{margin:7px 0 0;padding-left:20px}.evidence li{margin:4px 0}
.evidence code{color:#9bdcf1;font:11px ui-monospace,monospace;overflow-wrap:anywhere}
.vulnerable-code{margin:12px 0;border:1px solid #713044;border-radius:10px;background:#180d16;overflow:hidden}
.vulnerable-code>strong{display:block;padding:9px 12px;background:#351321;color:#fda4af;font:800 10px ui-monospace,monospace;letter-spacing:.12em}
.vulnerable-line{display:flex;gap:12px;padding:8px 12px;border-top:1px solid #492034;border-left:4px solid #fb7185;background:#24101b}
.vulnerable-line .line-number{flex:none;color:#fb7185;font:700 11px ui-monospace,monospace}
.vulnerable-line code{color:#fecdd3;font:12px/1.5 ui-monospace,monospace;white-space:pre-wrap;overflow-wrap:anywhere}
.impact-block,.recommendation-block{margin:10px 0;padding:11px 13px;border:1px solid var(--line);border-radius:9px;background:#0a1422}
.impact-block strong{color:#fda4af}.recommendation-block strong{color:var(--green)}
.impact-block p,.recommendation-block p{margin:5px 0 0}
.empty{padding:28px;text-align:center;color:var(--muted);border:1px dashed var(--line);border-radius:12px}
.table-wrap{max-width:100%;overflow:auto;border:1px solid var(--line);border-radius:10px}
table{width:100%;border-collapse:collapse;min-width:640px;font-size:11px}
th,td{padding:10px 12px;border-bottom:1px solid #20334b;text-align:left;vertical-align:top}
th{position:sticky;top:0;background:#17263b;color:#b8cde2;font:800 10px ui-monospace,monospace;text-transform:uppercase}
td{color:#c7d5e5}td.path{max-width:520px;overflow-wrap:anywhere;font-family:ui-monospace,monospace}
.pagination{display:flex;align-items:center;justify-content:space-between;gap:10px;margin-top:12px;color:var(--muted);font-size:11px}
.raw-json{max-height:520px;overflow:auto;padding:14px;background:#060b13;border:1px solid var(--line);border-radius:10px;
 white-space:pre-wrap;overflow-wrap:anywhere;color:#9db5cf;font:11px/1.5 ui-monospace,monospace}
.footer{padding:28px 0;color:#667b94;text-align:center;font:10px ui-monospace,monospace;letter-spacing:.12em}
.truncation{margin-top:18px;padding:12px 14px;border:1px solid #6b5420;border-radius:10px;background:#2a210c;color:#fde68a;font-size:12px}
.hidden{display:none!important}
@media(max-width:900px){.main-grid{grid-template-columns:1fr}.sidebar{position:static;display:flex;flex-wrap:wrap;gap:4px}.sidebar h3{width:100%}}
@media(max-width:600px){.top-meta{display:none}.finding summary{flex-wrap:wrap;padding:10px 0}.finding-title{flex-basis:100%;order:3}.section{padding:15px}}
</style>
</head>
<body>
<div class="topbar">
 <div class="brand"><span class="brand-mark">⌁</span><span>PDT <span style="color:var(--cyan)">/</span> INTELLIGENCE</span></div>
 <div class="top-meta">LOCAL REPORT // STATIC EVIDENCE // OFFLINE</div>
</div>
<div class="shell">
 <header class="hero">
  <div class="eyebrow">Project discovery / analysis complete</div>
  <h1>Project Intelligence Report</h1>
  <div class="root">__ROOT__</div><div class="completed">COMPLETED // __GENERATED__</div>
  <div class="stats">
   <div class="stat cyan"><span>Files</span><strong id="stat-files">0</strong></div>
   <div class="stat"><span>Directories</span><strong id="stat-dirs">0</strong></div>
   <div class="stat"><span>Symlinks</span><strong id="stat-links">0</strong></div>
   <div class="stat"><span>Special entries</span><strong id="stat-special">0</strong></div>
   <div class="stat green"><span>Findings</span><strong id="stat-findings">0</strong></div>
   <div class="stat amber"><span>Hidden entries</span><strong id="stat-hidden">0</strong></div>
   <div class="stat"><span>Scan errors</span><strong id="stat-errors">0</strong></div>
  </div>
  <div id="truncation-notice" class="truncation hidden" role="status"></div>
 </header>
 <div class="main-grid">
  <aside class="sidebar" aria-label="Report navigation">
   <h3>Navigation</h3>
   <a href="#overview">01 // Overview</a><a href="#inventory">02 // Inventory</a>
   <a href="#vulnerabilities">03 // Vulnerabilities</a><a href="#vcs">04 // VCS / Providers</a>
   <a href="#directories">05 // Directories</a><a href="#symlinks">06 // Symlinks</a>
   <a href="#special">07 // Special entries</a><a href="#files">08 // File browser</a>
   <a href="#findings">09 // Findings</a><a href="#diagnostics">10 // Diagnostics</a>
  </aside>
  <main class="content">
   <section class="section" id="overview">
    <div class="section-head"><h2>Scan overview</h2><span class="kicker">01 / SUMMARY</span></div>
    <div class="profile-grid">
     <div class="profile-card"><h3>File type distribution</h3><div id="file-types"></div></div>
     <div class="profile-card"><h3>File size distribution</h3><div id="size-buckets"></div></div>
     <div class="profile-card"><h3>Development dependency trees</h3><div id="development-dirs"></div></div>
     <div class="profile-card"><h3>Host & native engine</h3><div id="host-os" class="mono muted"></div></div>
     <div class="profile-card"><h3>Vulnerability intelligence</h3><div id="vuln-summary" class="mono muted"></div></div>
     <div class="profile-card"><h3>Source control & delivery</h3><div id="vcs-summary" class="mono muted"></div></div>
    </div>
   </section>
   <section class="section" id="inventory">
    <div class="section-head"><h2>Filesystem inventory</h2><span class="kicker">02 / ENTRY PROFILE</span></div>
    <div id="inventory-summary" class="muted"></div>
    <p class="muted">The JSON report contains full inventory metadata. Large tables are rendered in bounded pages.</p>
   </section>
   <section class="section" id="vulnerabilities">
    <div class="section-head"><h2>Local vulnerability intelligence</h2><span class="kicker">03 / OFFLINE ADVISORY MATCHING</span></div>
    <div class="controls"><span id="vuln-db-state" class="badge">LOCAL DB STATUS</span><span id="vuln-db-updated" class="muted"></span></div>
    <div id="vulnerability-findings" class="finding-list"></div>
    <div id="no-vulnerabilities" class="empty hidden">No local advisory matches were produced. This does not prove dependencies are vulnerability-free.</div>
   </section>
   <section class="section" id="vcs">
    <div class="section-head"><h2>VCS, hosting & delivery providers</h2><span class="kicker">04 / SOURCE PROVENANCE</span></div>
    <div id="vcs-findings" class="finding-list"></div>
    <div id="no-vcs" class="empty hidden">No local VCS, source-hosting or delivery-provider metadata was detected.</div>
   </section>
   <section class="section" id="directories">
    <div class="section-head"><h2>Directory intelligence</h2><span class="kicker">05 / STRUCTURE</span></div>
    <div class="table-wrap"><table><thead><tr><th>Directory</th><th>Depth</th><th>Files</th><th>Aggregate size</th><th>Marker / state</th></tr></thead><tbody id="directory-rows"></tbody></table></div>
   </section>
   <section class="section" id="symlinks">
    <div class="section-head"><h2>Symbolic links</h2><span class="kicker">06 / NO-FOLLOW INVENTORY</span></div>
    <div class="table-wrap"><table><thead><tr><th>Link path</th><th>Target</th><th>Lexical scope</th><th>Verification</th><th>Permissions</th><th>Hidden</th></tr></thead><tbody id="symlink-rows"></tbody></table></div>
    <div class="pagination" id="symlink-pagination"><span id="symlink-page-info">0 links</span><button id="symlink-more" class="primary" type="button">Load next page</button></div>
    <div id="no-symlinks" class="empty hidden">No symbolic links were detected.</div>
   </section>
   <section class="section" id="special">
    <div class="section-head"><h2>Special filesystem entries</h2><span class="kicker">07 / FIFO SOCKET DEVICE</span></div>
    <div class="table-wrap"><table><thead><tr><th>Path</th><th>Type</th><th>Permissions</th><th>Hidden</th><th>Size</th></tr></thead><tbody id="special-rows"></tbody></table></div>
    <div class="pagination" id="special-pagination"><span id="special-page-info">0 entries</span><button id="special-more" class="primary" type="button">Load next page</button></div>
    <div id="no-special" class="empty hidden">No FIFO, socket, device or other special entries were detected.</div>
   </section>
   <section class="section" id="files">
    <div class="section-head"><h2>File browser</h2><span class="kicker">08 / SEARCHABLE INVENTORY</span></div>
    <div class="controls"><input id="file-search" type="search" placeholder="Search paths, languages and file types" aria-label="Search file inventory">
     <select id="file-kind"><option value="">All file types</option></select><button id="file-reset" type="button">Reset</button></div>
    <div class="table-wrap"><table><thead><tr><th>Path</th><th>Size</th><th>Type</th><th>Language</th><th>Flags</th></tr></thead><tbody id="file-rows"></tbody></table></div>
    <div class="pagination"><span id="file-page-info">0 entries</span><button id="file-more" class="primary" type="button">Load next page</button></div>
   </section>
   <section class="section" id="findings">
    <div class="section-head"><h2>Analysis findings</h2><span class="kicker">09 / EVIDENCE</span></div>
    <div class="controls">
     <input id="search" type="search" placeholder="Search findings, evidence and paths" aria-label="Search findings">
     <select id="category"><option value="">All categories</option></select>
     <select id="confidence"><option value="">All confidence</option><option>CONFIRMED</option><option>INFERRED</option><option>UNKNOWN</option></select>
     <select id="severity"><option value="">All severities</option><option>CRITICAL</option><option>HIGH</option><option>MEDIUM</option><option>LOW</option><option>INFO</option></select>
     <button id="reset" type="button">Reset filters</button>
    </div>
    <div class="controls"><button id="open-all" type="button">Open all filtered</button>
     <button id="close-all" type="button">Close all</button>
     <button id="load-more" class="primary" type="button">Load next page</button></div>
    <div class="pagination"><span id="finding-count">0 findings</span><span id="page-count">Page 0</span></div>
    <div id="finding-list" class="finding-list"></div>
    <div id="no-findings" class="empty hidden">No findings match the current filters.</div>
   </section>
   <section class="section" id="diagnostics">
    <div class="section-head"><h2>Diagnostics and raw metrics</h2><span class="kicker">10 / TRACE</span></div>
    <details><summary>Show scan metrics JSON</summary><pre id="raw-metrics" class="raw-json"></pre></details>
    <details><summary>Show scanner/analyzer errors</summary><pre id="raw-errors" class="raw-json"></pre></details>
    <details><summary>Active analyzers</summary><pre id="raw-analyzers" class="raw-json"></pre></details>
   </section>
  </main>
 </div>
 <div class="footer">PDT // LOCAL-FIRST // OFFLINE // READ-ONLY // CONFIDENCE-AWARE</div>
</div>
<script nonce="__CSP_NONCE__">
__REPORT_JS__
</script>
</body>
</html>"""
    return _TEMPLATE_PLACEHOLDER.sub(lambda match: values[match.group(1)], template)


def _write_json_value(stream: TextIO, value: Any, *, script_safe: bool = False) -> None:
    if script_safe:
        stream.write(_script_json(value))
    else:
        stream.write(json.dumps(value, ensure_ascii=False, separators=(",", ":")))


def _write_json_array(
    stream: TextIO,
    values,
    serializer,
    *,
    script_safe: bool = False,
) -> None:
    stream.write("[")
    first = True
    for item in values:
        if not first:
            stream.write(",")
        first = False
        _write_json_value(stream, serializer(item), script_safe=script_safe)
    stream.write("]")


def _write_html_payload(stream: TextIO, result: ScanResult) -> None:
    """Embed bounded, severity-ordered slices plus true totals for the offline client."""
    totals = {
        "findings": len(result.findings),
        "files": len(result.files),
        "directories": len(result.directories),
        "symlinks": len(result.symlinks),
        "special_entries": len(result.special_entries),
        "errors": len(result.errors),
    }

    def bounded(name: str, values):
        return islice(values, HTML_MAX_EMBEDDED[name])

    stream.write('{"schema_version":' + json.dumps(REPORT_SCHEMA_VERSION) + ',"totals":')
    _write_json_value(stream, totals, script_safe=True)
    stream.write(',"embedded_limits":')
    _write_json_value(stream, HTML_MAX_EMBEDDED, script_safe=True)
    stream.write(',"findings":')
    _write_json_array(
        stream, bounded("findings", result.findings), lambda item: item.to_dict(), script_safe=True,
    )
    stream.write(',"files":')
    _write_json_array(
        stream,
        bounded("files", result.files),
        lambda item: {
            "path": item.path,
            "size_bytes": item.size_bytes,
            "extension": item.extension,
            "language": item.language,
            "file_type": item.file_type,
            "size_bucket": item.size_bucket,
            "is_hidden": item.is_hidden,
            "permissions": item.permissions,
            "content_skipped_reason": item.content_skipped_reason,
            "error": item.error,
        },
        script_safe=True,
    )
    stream.write(',"directories":')
    _write_json_array(
        stream, bounded("directories", result.directories), lambda item: item.to_dict(),
        script_safe=True,
    )
    stream.write(',"symlinks":')
    _write_json_array(
        stream, bounded("symlinks", result.symlinks), lambda item: item.to_dict(), script_safe=True,
    )
    stream.write(',"special_entries":')
    _write_json_array(
        stream, bounded("special_entries", result.special_entries), lambda item: item.to_dict(),
        script_safe=True,
    )
    stream.write(',"metrics":')
    _write_json_value(stream, result.metrics, script_safe=True)
    stream.write(',"errors":')
    _write_json_array(stream, bounded("errors", result.errors), lambda item: item, script_safe=True)
    stream.write(',"analyzers":')
    _write_json_value(stream, result.analyzer_names, script_safe=True)
    stream.write("}")


def _write_json_report(stream: TextIO, result: ScanResult) -> None:
    stream.write('{"schema_version":' + json.dumps(REPORT_SCHEMA_VERSION) + ',"root":')
    _write_json_value(stream, result.root)
    stream.write(',"started_at":')
    _write_json_value(stream, result.started_at)
    stream.write(',"finished_at":')
    _write_json_value(stream, result.finished_at)
    stream.write(',"files":')
    _write_json_array(stream, result.files, lambda item: item.to_dict())
    stream.write(',"directories":')
    _write_json_array(stream, result.directories, lambda item: item.to_dict())
    stream.write(',"symlinks":')
    _write_json_array(stream, result.symlinks, lambda item: item.to_dict())
    stream.write(',"special_entries":')
    _write_json_array(stream, result.special_entries, lambda item: item.to_dict())
    stream.write(',"findings":')
    _write_json_array(stream, result.findings, lambda item: item.to_dict())
    stream.write(',"metrics":')
    _write_json_value(stream, result.metrics)
    stream.write(',"errors":')
    _write_json_array(stream, result.errors, lambda item: item)
    stream.write(',"analyzers":')
    _write_json_value(stream, result.analyzer_names)
    stream.write("}\n")


def _write_html_report(stream: TextIO, result: ScanResult) -> None:
    # A per-report random marker cannot be forged by paths or other report text.
    data_marker = f"__PDT_DATA_{secrets.token_hex(16)}__"
    template = _html_template(result, nonce=secrets.token_urlsafe(18), data_marker=data_marker)
    before, separator, after = template.partition(data_marker)
    if not separator or data_marker in after:
        raise RuntimeError("HTML report template is missing the report data placeholder")
    stream.write(before)
    _write_html_payload(stream, result)
    stream.write(after)


def _html_report(result: ScanResult) -> str:
    buffer = io.StringIO()
    _write_html_report(buffer, result)
    return buffer.getvalue()


# Underscores only form emphasis at word boundaries (e.g. "__init__.py" renders bold), so
# intraword underscores such as "snake_case" stay readable in the raw Markdown.
_MD_INLINE_SPECIAL = re.compile(r"[\\`*\[\]|~]|(?<![A-Za-z0-9])_|_(?![A-Za-z0-9])")


def _md(value: object) -> str:
    """Neutralize untrusted inline text (paths, titles, evidence) for Markdown output.

    Raw HTML and autolinks are disabled by entity-escaping <, > and &; Markdown control
    characters are backslash-escaped; newlines (legal in POSIX file names) are flattened
    so a value cannot start new Markdown blocks.
    """
    text = " ".join(str(value).splitlines())
    return _MD_INLINE_SPECIAL.sub(
        lambda match: "\\" + match.group(0), html.escape(text, quote=False),
    )


def _md_code(value: str) -> str:
    """Render text as a CommonMark code span; backslash escapes do not work inside spans."""
    text = " ".join(value.splitlines()) or " "
    fence = "`" * (max((len(run) for run in re.findall(r"`+", text)), default=0) + 1)
    pad = " " if text[0] == "`" or text[-1] == "`" else ""
    return f"{fence}{pad}{text}{pad}{fence}"


def _write_markdown_report(stream: TextIO, result: ScanResult) -> None:
    """Write Markdown incrementally without duplicating the complete report in RAM."""
    def line(value: str = "") -> None:
        stream.write(value + "\n")

    metrics = result.metrics
    native = metrics.get("native_backend", {})
    execution = metrics.get("execution", {})
    for value in (
        "# Project Discovery Report",
        "",
        f"- Root: {_md(result.root)}",
        f"- Schema version: {REPORT_SCHEMA_VERSION}",
        f"- Completed: {result.finished_at}",
        f"- Files: {len(result.files):,}",
        f"- Directories: {max(0, len(result.directories) - 1):,}",
        f"- Symbolic links: {len(result.symlinks):,}",
        f"- Special filesystem entries: {len(result.special_entries):,}",
        f"- Explicitly pruned directories: {metrics.get('pruned_directory_count', 0):,}",
        f"- Findings: {len(result.findings):,}",
        f"- Total file size: {metrics.get('total_bytes', 0):,} bytes",
        f"- Hidden entries: {metrics.get('hidden_entry_count', 0):,}",
        f"- Development/cache trees: {metrics.get('development_directory_count', 0):,}",
        f"- Analysis workers: {execution.get('worker_count', 'not reported')}",
        f"- Analysis queue limit: {execution.get('max_pending_tasks', 'not reported')} pending batches",
        f"- Native CPU backend: {native.get('backend', 'not reported')}",
        f"- GPU status: {native.get('gpu_status', 'not reported')}",
        f"- GPU device: {_md(native.get('gpu_name') or 'not detected')}",
        f"- GPU byte-count dispatches: {native.get('gpu_dispatches', 0):,}",
        f"- GPU CPU fallbacks: {native.get('gpu_fallbacks', 0):,}",
        "",
        "## File Type Distribution",
        "",
    ):
        line(value)
    for name, count in sorted(metrics.get("file_types", {}).items()):
        line(f"- {_md(name)}: {count:,}")
    line()
    line("## File Size Distribution")
    line()
    for name, count in sorted(metrics.get("size_buckets", {}).items()):
        line(f"- {_md(name)}: {count:,}")
    line()
    line("## Development Dependency and Cache Directories")
    line()
    for name, count in sorted(metrics.get("development_directories", {}).items()):
        line(f"- {_md(name)}: {count:,}")
    line()
    line("## Largest Directories")
    line()
    largest = heapq.nlargest(
        100,
        (item for item in result.directories if item.path != "."),
        key=lambda item: (item.total_bytes, item.path.casefold(), item.path),
    )
    for item in largest:
        marker = f" [{_md(item.development_marker)}]" if item.development_marker else ""
        pruned = " [pruned]" if item.pruned else ""
        line(
            f"- {_md(item.path)} — {item.total_bytes:,} bytes, "
            f"{item.file_count:,} files, depth {item.depth}{marker}{pruned}"
        )
    line()
    line("## Symbolic Links")
    line()
    if not result.symlinks:
        line("No symbolic links were detected.")
    else:
        for item in result.symlinks:
            line(
                f"- {_md(item.path)} -> {_md(item.target)} "
                f"(scope: {_md(item.target_scope)}, hidden: {item.is_hidden})"
            )
    line()
    line("## Special Filesystem Entries")
    line()
    if not result.special_entries:
        line("No special filesystem entries were detected.")
    else:
        for item in result.special_entries:
            mode = "unknown" if item.permissions is None else oct(item.permissions)
            line(
                f"- {_md(item.path)} — {_md(item.entry_type)}, permissions {mode}, "
                f"hidden: {item.is_hidden}, size: {item.size_bytes:,} bytes"
            )
    vuln_meta = metrics.get("vulnerability_intelligence", {})
    vulnerability_count = sum(
        1 for item in result.findings if item.category == "vulnerabilities"
    )
    line()
    line("## Local Vulnerability Intelligence")
    line()
    if not vuln_meta.get("enabled"):
        line("No local advisory database was configured. This is not a vulnerability-free result.")
    else:
        line(f"- Local advisories available: {vuln_meta.get('advisory_count', 0):,}")
        line(f"- Local advisory snapshot imported: {_md(vuln_meta.get('last_imported_at', 'unknown'))}")
        line(f"- Matched findings: {vulnerability_count:,}")
    for item in result.findings:
        if item.category != "vulnerabilities":
            continue
        line(f"- [{item.severity}][{item.confidence}] {_md(item.title)}")
        line(f"  - {_md(item.detail)}")
        line("  - Evidence: " + "; ".join(_md(value) for value in item.evidence))
    line()
    line("## Findings")
    line()
    if not result.findings:
        line("No findings were produced.")
    for item in result.findings:
        line(f"### [{item.severity}][{item.confidence}] {_md(item.title)}")
        line()
        line(_md(item.detail))
        line()
        if item.impact:
            line(f"**Potential attacker impact:** {_md(item.impact)}")
            line()
        if item.recommendation:
            line(f"**Recommended remediation:** {_md(item.recommendation)}")
            line()
        line("Evidence:")
        for value in item.evidence:
            line(f"- {_md(value)}")
        if item.code_evidence:
            line()
            line("**Vulnerable source lines (redacted):**")
            line()
            for code in item.code_evidence:
                line(f"- 🔴 Line {code.line_number}: {_md_code(code.code)}")
        line()
    line("## Diagnostics")
    line()
    if result.errors:
        for error in result.errors:
            line(f"- {_md(error)}")
    else:
        line("No scanner/analyzer errors recorded.")


def _markdown_report(result: ScanResult) -> str:
    """Compatibility helper for callers/tests that explicitly need a string."""
    buffer = io.StringIO()
    _write_markdown_report(buffer, result)
    return buffer.getvalue().rstrip() + "\n"


def write_reports(result: ScanResult, output: Path, formats: set[str]) -> list[Path]:
    output.mkdir(parents=True, exist_ok=True)
    written: list[Path] = []
    if "json" in formats:
        path = output / "discovery-report.json"
        with path.open("w", encoding="utf-8", errors="backslashreplace", newline="\n") as stream:
            _write_json_report(stream, result)
        written.append(path)
    if "markdown" in formats:
        path = output / "discovery-report.md"
        with path.open("w", encoding="utf-8", errors="backslashreplace", newline="\n") as stream:
            _write_markdown_report(stream, result)
        written.append(path)
    if "html" in formats:
        path = output / "discovery-report.html"
        with path.open("w", encoding="utf-8", errors="backslashreplace", newline="\n") as stream:
            _write_html_report(stream, result)
        written.append(path)
    return written

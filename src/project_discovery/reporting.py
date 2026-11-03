"""Local JSON, Markdown and offline interactive HTML report generation."""
from __future__ import annotations

import html
import json
from pathlib import Path
from typing import Any

from .models import ScanResult


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


def _report_data(result: ScanResult) -> dict[str, Any]:
    return {
        "findings": [item.to_dict() for item in result.findings],
        "files": [
            {
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
            }
            for item in result.files
        ],
        "directories": [item.to_dict() for item in result.directories],
        "symlinks": [item.to_dict() for item in result.symlinks],
        "special_entries": [item.to_dict() for item in result.special_entries],
        "metrics": result.metrics,
        "errors": result.errors,
        "analyzers": result.analyzer_names,
    }


def _html_report(result: ScanResult) -> str:
    data = _script_json(_report_data(result))
    root = html.escape(result.root)
    generated = html.escape(result.finished_at)
    template = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
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
 </header>
 <div class="main-grid">
  <aside class="sidebar" aria-label="Report navigation">
   <h3>Navigation</h3>
   <a href="#overview">01 // Overview</a><a href="#inventory">02 // Inventory</a>
   <a href="#directories">03 // Directories</a><a href="#symlinks">04 // Symlinks</a>
   <a href="#special">05 // Special entries</a><a href="#files">06 // File browser</a>
   <a href="#findings">07 // Findings</a><a href="#diagnostics">08 // Diagnostics</a>
  </aside>
  <main class="content">
   <section class="section" id="overview">
    <div class="section-head"><h2>Scan overview</h2><span class="kicker">01 / SUMMARY</span></div>
    <div class="profile-grid">
     <div class="profile-card"><h3>File type distribution</h3><div id="file-types"></div></div>
     <div class="profile-card"><h3>File size distribution</h3><div id="size-buckets"></div></div>
     <div class="profile-card"><h3>Development dependency trees</h3><div id="development-dirs"></div></div>
     <div class="profile-card"><h3>Host environment</h3><div id="host-os" class="mono muted"></div></div>
    </div>
   </section>
   <section class="section" id="inventory">
    <div class="section-head"><h2>Filesystem inventory</h2><span class="kicker">02 / ENTRY PROFILE</span></div>
    <div id="inventory-summary" class="muted"></div>
    <p class="muted">The JSON report contains full inventory metadata. Large tables are rendered in bounded pages.</p>
   </section>
   <section class="section" id="directories">
    <div class="section-head"><h2>Directory intelligence</h2><span class="kicker">03 / STRUCTURE</span></div>
    <div class="table-wrap"><table><thead><tr><th>Directory</th><th>Depth</th><th>Files</th><th>Aggregate size</th><th>Marker / state</th></tr></thead><tbody id="directory-rows"></tbody></table></div>
   </section>
   <section class="section" id="symlinks">
    <div class="section-head"><h2>Symbolic links</h2><span class="kicker">04 / NO-FOLLOW INVENTORY</span></div>
    <div class="table-wrap"><table><thead><tr><th>Link path</th><th>Target</th><th>Scope</th><th>Hidden</th></tr></thead><tbody id="symlink-rows"></tbody></table></div>
    <div id="no-symlinks" class="empty hidden">No symbolic links were detected.</div>
   </section>
   <section class="section" id="special">
    <div class="section-head"><h2>Special filesystem entries</h2><span class="kicker">05 / FIFO SOCKET DEVICE</span></div>
    <div class="table-wrap"><table><thead><tr><th>Path</th><th>Type</th><th>Permissions</th><th>Hidden</th><th>Size</th></tr></thead><tbody id="special-rows"></tbody></table></div>
    <div id="no-special" class="empty hidden">No FIFO, socket, device or other special entries were detected.</div>
   </section>
   <section class="section" id="files">
    <div class="section-head"><h2>File browser</h2><span class="kicker">05 / SEARCHABLE INVENTORY</span></div>
    <div class="controls"><input id="file-search" type="search" placeholder="Search paths, languages and file types" aria-label="Search file inventory">
     <select id="file-kind"><option value="">All file types</option></select><button id="file-reset" type="button">Reset</button></div>
    <div class="table-wrap"><table><thead><tr><th>Path</th><th>Size</th><th>Type</th><th>Language</th><th>Flags</th></tr></thead><tbody id="file-rows"></tbody></table></div>
    <div class="pagination"><span id="file-page-info">0 entries</span><button id="file-more" class="primary" type="button">Load next page</button></div>
   </section>
   <section class="section" id="findings">
    <div class="section-head"><h2>Analysis findings</h2><span class="kicker">06 / EVIDENCE</span></div>
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
    <div class="section-head"><h2>Diagnostics and raw metrics</h2><span class="kicker">07 / TRACE</span></div>
    <details><summary>Show scan metrics JSON</summary><pre id="raw-metrics" class="raw-json"></pre></details>
    <details><summary>Show scanner/analyzer errors</summary><pre id="raw-errors" class="raw-json"></pre></details>
    <details><summary>Active analyzers</summary><pre id="raw-analyzers" class="raw-json"></pre></details>
   </section>
  </main>
 </div>
 <div class="footer">PDT // LOCAL-FIRST // OFFLINE // READ-ONLY // CONFIDENCE-AWARE</div>
</div>
<script>
"use strict";
const REPORT = __DATA__;
const $ = function(id){return document.getElementById(id);};
const number = function(value){return Number(value || 0).toLocaleString();};
const formatBytes = function(value){
 const n=Number(value||0);if(n<1024)return n+" B";
 const units=["KiB","MiB","GiB","TiB"];let v=n/1024,i=0;
 while(v>=1024&&i<units.length-1){v/=1024;i++;}
 return v.toFixed(1)+" "+units[i];
};
function fillBars(targetId,values){
 const target=$(targetId);target.replaceChildren();
 const entries=Object.entries(values||{}).sort(function(a,b){return b[1]-a[1];});
 const max=Math.max(1,...entries.map(function(item){return Number(item[1]);}));
 if(!entries.length){target.textContent="No entries";target.className="muted";return;}
 for(const entry of entries.slice(0,16)){
  const label=entry[0],value=entry[1],row=document.createElement("div");row.className="bar-row";
  const name=document.createElement("span");name.className="bar-label";name.textContent=label;
  const track=document.createElement("span");track.className="bar-track";
  const fill=document.createElement("span");fill.className="bar-fill";fill.style.width=(Number(value)/max*100).toFixed(1)+"%";
  track.append(fill);
  const count=document.createElement("span");count.className="bar-count";count.textContent=number(value);
  row.append(name,track,count);target.append(row);
 }
}
const metrics=REPORT.metrics||{};
$("stat-files").textContent=number(REPORT.files.length);
$("stat-dirs").textContent=number(Math.max(0,REPORT.directories.length-1));
$("stat-links").textContent=number(REPORT.symlinks.length);
$("stat-special").textContent=number((REPORT.special_entries||[]).length);
$("stat-findings").textContent=number(REPORT.findings.length);
$("stat-hidden").textContent=number(metrics.hidden_entry_count||0);
$("stat-errors").textContent=number((REPORT.errors||[]).length+(metrics.walk_errors||0));
fillBars("file-types",metrics.file_types);fillBars("size-buckets",metrics.size_buckets);
fillBars("development-dirs",metrics.development_directories);
$("host-os").textContent=JSON.stringify(metrics.host_os||{},null,2);
$("inventory-summary").textContent=number(REPORT.files.length)+" files • "+
 number(Math.max(0,REPORT.directories.length-1))+" directories • "+number(REPORT.symlinks.length)+
 " links • "+number((REPORT.special_entries||[]).length)+" special entries • "+formatBytes(metrics.total_bytes)+" • "+number(metrics.hidden_entry_count||0)+
 " hidden entries • "+number(metrics.development_directory_count||0)+" development/cache trees";
$("raw-metrics").textContent=JSON.stringify(metrics,null,2);
$("raw-errors").textContent=JSON.stringify(REPORT.errors||[],null,2);
$("raw-analyzers").textContent=JSON.stringify(REPORT.analyzers||[],null,2);

const directoryRows=$("directory-rows");
const sortedDirectories=REPORT.directories.filter(function(item){return item.path!==".";})
 .sort(function(a,b){return b.total_bytes-a.total_bytes;}).slice(0,250);
for(const item of sortedDirectories){
 const tr=document.createElement("tr");
 const marker=[item.development_marker,item.pruned?"pruned":null,item.is_hidden?"hidden":null].filter(Boolean).join(" / ")||"—";
 for(const pair of [[item.path,"path"],[item.depth,""],[number(item.file_count),""],[formatBytes(item.total_bytes),""],[marker,""]]){
  const td=document.createElement("td");td.textContent=String(pair[0]);td.className=pair[1];tr.append(td);
 }
 directoryRows.append(tr);
}
const symlinkRows=$("symlink-rows");
for(const item of REPORT.symlinks){
 const tr=document.createElement("tr");
 for(const pair of [[item.path,"path"],[item.target,"path"],[item.target_scope,""],[item.is_hidden?"yes":"no",""]]){
  const td=document.createElement("td");td.textContent=String(pair[0]);td.className=pair[1];tr.append(td);
 }
 symlinkRows.append(tr);
}
$("no-symlinks").classList.toggle("hidden",REPORT.symlinks.length!==0);

const specialRows=$("special-rows"),specialEntries=REPORT.special_entries||[];
for(const item of specialEntries){
 const tr=document.createElement("tr");
 const mode=item.permissions===null||item.permissions===undefined?"unknown":Number(item.permissions).toString(8);
 for(const pair of [[item.path,"path"],[item.entry_type,""],[mode,"mono"],[item.is_hidden?"yes":"no",""],[formatBytes(item.size_bytes||0),""]]){
  const td=document.createElement("td");td.textContent=String(pair[0]);td.className=pair[1];tr.append(td);
 }
 specialRows.append(tr);
}
$("no-special").classList.toggle("hidden",specialEntries.length!==0);

const files=REPORT.files.slice().sort(function(a,b){return a.path.localeCompare(b.path);});
const fileSearch=$("file-search"),fileKind=$("file-kind"),fileRows=$("file-rows"),fileMore=$("file-more");
const fileTypes=Array.from(new Set(files.map(function(item){return item.file_type||"unknown";}))).sort();
for(const type of fileTypes){const option=document.createElement("option");option.value=type;option.textContent=type;fileKind.append(option);}
const FILE_PAGE=100;let fileMatches=files,fileOffset=0;
function renderFiles(reset){
 if(reset){fileOffset=0;fileRows.replaceChildren();}
 const query=fileSearch.value.trim().toLowerCase();
 fileMatches=files.filter(function(item){
  return (!query||(item.path+" "+item.language+" "+item.file_type).toLowerCase().includes(query))&&
   (!fileKind.value||(item.file_type||"unknown")===fileKind.value);
 });
 const end=Math.min(fileOffset+FILE_PAGE,fileMatches.length);
 for(let i=fileOffset;i<end;i++){
  const item=fileMatches[i],tr=document.createElement("tr");
  const flags=[item.is_hidden?"hidden":null,item.content_skipped_reason?"content skipped":null,item.error?"error":null].filter(Boolean).join(" / ")||"—";
  for(const pair of [[item.path,"path"],[formatBytes(item.size_bytes),""],[item.file_type||"unknown",""],[item.language,""],[flags,""]]){
   const td=document.createElement("td");td.textContent=String(pair[0]);td.className=pair[1];tr.append(td);
  }
  fileRows.append(tr);
 }
 fileOffset=end;$("file-page-info").textContent="Showing "+number(fileOffset)+" of "+number(fileMatches.length)+" matching files";
 fileMore.disabled=fileOffset>=fileMatches.length;fileMore.textContent=fileMore.disabled?"End of inventory":"Load next page";
}
fileSearch.addEventListener("input",function(){renderFiles(true);});
fileKind.addEventListener("change",function(){renderFiles(true);});
fileMore.addEventListener("click",function(){renderFiles(false);});
$("file-reset").addEventListener("click",function(){fileSearch.value="";fileKind.value="";renderFiles(true);});
renderFiles(true);

const findings=REPORT.findings||[],categories=Array.from(new Set(findings.map(function(item){return item.category;}))).sort();
for(const value of categories){const option=document.createElement("option");option.value=value;option.textContent=value;$("category").append(option);}
const search=$("search"),category=$("category"),confidence=$("confidence"),severity=$("severity");
const list=$("finding-list"),loadMore=$("load-more"),FINDING_PAGE=100;
let matches=[],findingOffset=0,expandFuture=false;
function makeFinding(item){
 const article=document.createElement("article");article.className="finding";
 const details=document.createElement("details");details.open=expandFuture;
 const summary=document.createElement("summary");
 const conf=document.createElement("span");conf.className="badge "+String(item.confidence||"UNKNOWN").toLowerCase();conf.textContent=item.confidence||"UNKNOWN";
 const sev=document.createElement("span");sev.className="badge sev-"+String(item.severity||"INFO").toLowerCase();sev.textContent=item.severity||"INFO";
 const title=document.createElement("span");title.className="finding-title";title.textContent=item.title||"Untitled finding";
 summary.append(conf,sev,title);
 const body=document.createElement("div");body.className="finding-body";
 const description=document.createElement("p");description.textContent=item.detail||"";
 const evidence=document.createElement("div");evidence.className="evidence";
 const label=document.createElement("strong");label.textContent="Evidence";evidence.append(label);
 const ul=document.createElement("ul");
 for(const text of (item.evidence||[])){const li=document.createElement("li"),code=document.createElement("code");code.textContent=text;li.append(code);ul.append(li);}
 evidence.append(ul);
 const analyzer=document.createElement("div");analyzer.className="muted";analyzer.textContent="Analyzer: "+(item.analyzer||"core");
 body.append(description,evidence,analyzer);details.append(summary,body);article.append(details);return article;
}
function updateFindingFilter(reset){
 if(reset){findingOffset=0;list.replaceChildren();}
 const q=search.value.trim().toLowerCase();
 matches=findings.filter(function(item){
  return (!q||[item.title,item.detail,(item.evidence||[]).join(" ")].join(" ").toLowerCase().includes(q))&&
   (!category.value||item.category===category.value)&&
   (!confidence.value||item.confidence===confidence.value)&&
   (!severity.value||item.severity===severity.value);
 });
 $("finding-count").textContent=number(matches.length)+" matching findings";
 $("no-findings").classList.toggle("hidden",matches.length!==0);
 appendFindings();
}
function appendFindings(){
 const end=Math.min(findingOffset+FINDING_PAGE,matches.length);
 for(let i=findingOffset;i<end;i++)list.append(makeFinding(matches[i]));
 findingOffset=end;$("page-count").textContent="Rendered "+number(findingOffset)+" / "+number(matches.length);
 loadMore.disabled=findingOffset>=matches.length;loadMore.textContent=loadMore.disabled?"All filtered findings loaded":"Load next page";
}
search.addEventListener("input",function(){updateFindingFilter(true);});
category.addEventListener("change",function(){updateFindingFilter(true);});
confidence.addEventListener("change",function(){updateFindingFilter(true);});
severity.addEventListener("change",function(){updateFindingFilter(true);});
loadMore.addEventListener("click",appendFindings);
$("open-all").addEventListener("click",function(){expandFuture=true;for(const details of list.querySelectorAll("details"))details.open=true;});
$("close-all").addEventListener("click",function(){expandFuture=false;for(const details of list.querySelectorAll("details"))details.open=false;});
$("reset").addEventListener("click",function(){search.value="";category.value="";confidence.value="";severity.value="";expandFuture=false;updateFindingFilter(true);});
updateFindingFilter(true);
</script>
</body>
</html>"""
    return (
        template.replace("__ROOT__", root)
        .replace("__GENERATED__", generated)
        .replace("__DATA__", data)
    )


def _markdown_report(result: ScanResult) -> str:
    metrics = result.metrics
    lines = [
        "# Project Discovery Report",
        "",
        f"- Root: {result.root}",
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
        "",
        "## File Type Distribution",
        "",
    ]
    for name, count in sorted(metrics.get("file_types", {}).items()):
        lines.append(f"- {name}: {count:,}")
    lines.extend(["", "## File Size Distribution", ""])
    for name, count in sorted(metrics.get("size_buckets", {}).items()):
        lines.append(f"- {name}: {count:,}")
    lines.extend(["", "## Development Dependency and Cache Directories", ""])
    for name, count in sorted(metrics.get("development_directories", {}).items()):
        lines.append(f"- {name}: {count:,}")
    lines.extend(["", "## Largest Directories", ""])
    largest = sorted(
        (item for item in result.directories if item.path != "."),
        key=lambda item: item.total_bytes,
        reverse=True,
    )[:100]
    for item in largest:
        marker = f" [{item.development_marker}]" if item.development_marker else ""
        pruned = " [pruned]" if item.pruned else ""
        lines.append(
            f"- {item.path} — {item.total_bytes:,} bytes, "
            f"{item.file_count:,} files, depth {item.depth}{marker}{pruned}"
        )
    lines.extend(["", "## Symbolic Links", ""])
    if not result.symlinks:
        lines.append("No symbolic links were detected.")
    else:
        for item in result.symlinks:
            lines.append(
                f"- {item.path} -> {item.target} "
                f"(scope: {item.target_scope}, hidden: {item.is_hidden})"
            )
    lines.extend(["", "## Special Filesystem Entries", ""])
    if not result.special_entries:
        lines.append("No special filesystem entries were detected.")
    else:
        for item in result.special_entries:
            mode = "unknown" if item.permissions is None else oct(item.permissions)
            lines.append(
                f"- {item.path} — {item.entry_type}, permissions {mode}, "
                f"hidden: {item.is_hidden}, size: {item.size_bytes:,} bytes"
            )
    lines.extend(["", "## Findings", ""])
    if not result.findings:
        lines.append("No findings were produced.")
    for item in result.findings:
        lines.extend([
            f"### [{item.severity}][{item.confidence}] {item.title}",
            "",
            item.detail,
            "",
            "Evidence:",
        ])
        lines.extend(f"- {value}" for value in item.evidence)
        lines.append("")
    lines.extend(["## Diagnostics", ""])
    if result.errors:
        lines.extend(f"- {error}" for error in result.errors)
    else:
        lines.append("No scanner/analyzer errors recorded.")
    return "\n".join(lines).rstrip() + "\n"


def write_reports(result: ScanResult, output: Path, formats: set[str]) -> list[Path]:
    output.mkdir(parents=True, exist_ok=True)
    data = result.to_dict()
    written: list[Path] = []
    if "json" in formats:
        path = output / "discovery-report.json"
        path.write_text(
            json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
        )
        written.append(path)
    if "markdown" in formats:
        path = output / "discovery-report.md"
        path.write_text(_markdown_report(result), encoding="utf-8")
        written.append(path)
    if "html" in formats:
        path = output / "discovery-report.html"
        path.write_text(_html_report(result), encoding="utf-8")
        written.append(path)
    return written

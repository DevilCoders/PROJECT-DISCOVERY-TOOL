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
$("host-os").textContent=JSON.stringify({
 host:metrics.host_os||{},
 native_backend:metrics.native_backend||{backend:"not reported"}
},null,2);
const vulnMeta=metrics.vulnerability_intelligence||{enabled:false};
const vulnFindings=(REPORT.findings||[]).filter(item=>item.category==="vulnerabilities");
$("vuln-summary").textContent=vulnMeta.enabled
 ? number(vulnMeta.advisory_count||0)+" local advisories • "+number(vulnFindings.length)+" matched finding(s)"
 : "Offline advisory database not configured";
$("vuln-db-state").textContent=vulnMeta.enabled?"LOCAL DATABASE ACTIVE":"NO LOCAL DATABASE";
$("vuln-db-updated").textContent=vulnMeta.last_imported_at
 ? "Last local import: "+vulnMeta.last_imported_at
 : "No local advisory snapshot metadata";
const vulnTarget=$("vulnerability-findings");
for(const item of vulnFindings.slice(0,200)){
 const card=document.createElement("article");card.className="finding";
 const details=document.createElement("details"),summary=document.createElement("summary");
 const title=document.createElement("span");title.className="finding-title";title.textContent=item.title;
 const severity=document.createElement("span");severity.className="badge sev-"+String(item.severity||"info").toLowerCase();severity.textContent=item.severity||"INFO";
 const confidence=document.createElement("span");confidence.className="badge "+String(item.confidence||"unknown").toLowerCase();confidence.textContent=item.confidence||"UNKNOWN";
 summary.append(title,severity,confidence);details.append(summary);
 const body=document.createElement("div");body.className="finding-body";
 const paragraph=document.createElement("p");paragraph.textContent=item.detail||"";body.append(paragraph);
 if(Array.isArray(item.evidence)&&item.evidence.length){
  const evidence=document.createElement("div");evidence.className="evidence";
  const label=document.createElement("strong");label.textContent="Dependency/advisory evidence";evidence.append(label);
  const list=document.createElement("ul");
  for(const value of item.evidence.slice(0,30)){const li=document.createElement("li");const code=document.createElement("code");code.textContent=String(value);li.append(code);list.append(li);}
  evidence.append(list);body.append(evidence);
 }
 details.append(body);card.append(details);vulnTarget.append(card);
}
$("no-vulnerabilities").classList.toggle("hidden",vulnFindings.length!==0);
if(vulnFindings.length>200){
 const note=document.createElement("div");note.className="empty";
 note.textContent="Showing first 200 vulnerability matches here. The global findings view and JSON report contain the complete set.";
 vulnTarget.append(note);
}
const vcsCategories=new Set(["vcs","hosting_providers","ci_cd","cloud_services"]);
const vcsFindings=(REPORT.findings||[]).filter(item=>vcsCategories.has(item.category));
const providerNames=[...new Set(vcsFindings.map(item=>item.title.split(":")[0]))].sort();
$("vcs-summary").textContent=vcsFindings.length
 ? number(vcsFindings.length)+" evidence item(s) • "+providerNames.slice(0,8).join(" / ")
   +(providerNames.length>8?" / +"+(providerNames.length-8)+" more":"")
 : "No VCS/provider evidence";
const vcsTarget=$("vcs-findings");
for(const item of vcsFindings.slice(0,100)){
 const card=document.createElement("article");card.className="finding";
 const details=document.createElement("details"),summary=document.createElement("summary");
 const title=document.createElement("span");title.className="finding-title";title.textContent=item.title;
 const category=document.createElement("span");category.className="badge";category.textContent=item.category;
 const confidence=document.createElement("span");confidence.className="badge "+String(item.confidence||"unknown").toLowerCase();confidence.textContent=item.confidence||"UNKNOWN";
 summary.append(title,category,confidence);details.append(summary);
 const body=document.createElement("div");body.className="finding-body";
 const paragraph=document.createElement("p");paragraph.textContent=item.detail||"";body.append(paragraph);
 if(Array.isArray(item.evidence)&&item.evidence.length){
  const evidence=document.createElement("div");evidence.className="evidence";
  const label=document.createElement("strong");label.textContent="Evidence";evidence.append(label);
  const list=document.createElement("ul");
  for(const value of item.evidence.slice(0,30)){const li=document.createElement("li");const code=document.createElement("code");code.textContent=String(value);li.append(code);list.append(li);}
  evidence.append(list);body.append(evidence);
 }
 details.append(body);card.append(details);vcsTarget.append(card);
}
$("no-vcs").classList.toggle("hidden",vcsFindings.length!==0);
if(vcsFindings.length>100){
 const note=document.createElement("div");note.className="empty";
 note.textContent="Showing first 100 VCS/provider findings. Use the global findings view or JSON report for the complete set.";
 vcsTarget.append(note);
}
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
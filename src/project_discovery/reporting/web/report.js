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
// Large reports embed bounded slices; totals always describe the complete scan.
const totals=REPORT.totals||{};
const total=function(name){
 const value=totals[name];
 return value===undefined?(REPORT[name]||[]).length:Number(value);
};
$("stat-files").textContent=number(total("files"));
$("stat-dirs").textContent=number(Math.max(0,total("directories")-1));
$("stat-links").textContent=number(total("symlinks"));
$("stat-special").textContent=number(total("special_entries"));
$("stat-findings").textContent=number(total("findings"));
$("stat-hidden").textContent=number(metrics.hidden_entry_count||0);
$("stat-errors").textContent=number(total("errors")+(metrics.walk_errors||0));
const truncated=["findings","files","directories","symlinks","special_entries","errors"].filter(function(name){
 return (REPORT[name]||[]).length<total(name);
});
if(truncated.length){
 const notice=$("truncation-notice");
 notice.textContent="Large report: this page embeds a bounded subset (findings by severity, inventory by path: "+
  truncated.map(function(name){return number((REPORT[name]||[]).length)+" of "+number(total(name))+" "+name.replace("_"," ");}).join(", ")+
  "). The JSON report contains the complete data set.";
 notice.classList.remove("hidden");
}
fillBars("file-types",metrics.file_types);fillBars("size-buckets",metrics.size_buckets);
fillBars("development-dirs",metrics.development_directories);
$("host-os").textContent=JSON.stringify({
 host:metrics.host_os||{},
 native_backend:metrics.native_backend||{backend:"not reported"}
},null,2);
// Scan mode and source: one summary (REPORT.scan) drives every report format.
const scan=REPORT.scan||{mode:"local",source:"local",network_access:[],remote:null};
const sourceMetrics=(metrics.source&&typeof metrics.source==="object")?metrics.source:{};
const remoteMeta=(sourceMetrics.remote&&typeof sourceMetrics.remote==="object")?sourceMetrics.remote:null;
const remoteSummary=(scan.remote&&typeof scan.remote==="object")?scan.remote:null;
function keyValues(target,rows){
 target.replaceChildren();
 for(const pair of rows){
  if(pair[1]===undefined||pair[1]===null||pair[1]==="")continue;
  const row=document.createElement("div");row.className="kv-row";
  const key=document.createElement("span");key.className="kv-key";key.textContent=pair[0];
  const value=document.createElement("span");value.className="kv-value";value.textContent=String(pair[1]);
  row.append(key,value);target.append(row);
 }
}
const NETWORK_LABELS={"provider-api":"provider API","osv.dev":"OSV.dev","nvd":"NVD","ghsa":"GitHub Advisory Database"};
const networkUses=Array.isArray(scan.network_access)?scan.network_access:[];
const networkText=networkUses.length?networkUses.map(function(item){return NETWORK_LABELS[item]||String(item);}).join(", "):"none";
if(remoteSummary){
 $("source-line").textContent=String(remoteSummary.provider||"remote")+" / "+String(remoteSummary.vcs||"vcs")+" @ "+String(remoteSummary.revision||"unknown revision");
 $("transport-badge").classList.toggle("hidden",!remoteSummary.transport_insecure);
}else{
 $("source-line").textContent="Local directory";
}
$("inventory-badge").classList.toggle("hidden",(metrics.execution||{}).analysis_mode!=="inventory-only");
$("source-summary").textContent=remoteSummary
 ? "Remote // "+(remoteSummary.acquisition==="api"?"provider API, no download":"temporary download")+" // "+String(remoteSummary.url||"")
 : (scan.mode==="online"?"Local directory // online advisory lookup":"Local directory // no network access");
keyValues($("source-details"),remoteSummary?[
 ["Mode",scan.mode],["Network access",networkText],
 ["Acquisition",remoteSummary.acquisition==="api"?"provider API; nothing written to disk":"downloaded to a temporary directory; deleted after the scan"],
 ["URL",remoteSummary.url],["Provider",remoteSummary.provider],["VCS",remoteSummary.vcs],
 ["Repository",remoteSummary.repository],["Requested ref",remoteSummary.ref||"remote default branch"],
 ["Revision",remoteSummary.revision||"not reported"],["Branch",remoteSummary.branch],
 ["Transport",String(remoteSummary.transport||"unknown")+(remoteSummary.transport_insecure?" (NOT ENCRYPTED)":" (encrypted)")],
 ["Acquired",remoteSummary.acquired_at?String(remoteSummary.acquired_at)+(remoteSummary.acquisition_seconds!==undefined&&remoteSummary.acquisition_seconds!==null?" ("+remoteSummary.acquisition_seconds+" s)":""):null],
 ["History",remoteSummary.history_complete===false?"only the analyzed revision":null],
]:[["Mode",scan.mode],["Source","local directory"],["Network access",networkText]]);
const coverageItems=remoteMeta&&Array.isArray(remoteMeta.coverage)?remoteMeta.coverage:[];
const coverageList=$("source-coverage");coverageList.replaceChildren();
for(const item of coverageItems){
 const li=document.createElement("li");
 li.textContent=String(item.detail||"")+(item.incomplete?" (missing from the analyzed tree)":" (not fetched)");
 coverageList.append(li);
}
coverageList.classList.toggle("hidden",coverageItems.length===0);
const coverageDetails=new Set(coverageItems.map(function(item){return String(item.detail||"");}));
const sourceNotes=remoteMeta&&Array.isArray(remoteMeta.warnings)?remoteMeta.warnings.filter(function(note){return !coverageDetails.has(String(note));}):[];
$("source-notes").textContent=sourceNotes.length?"Notes: "+sourceNotes.map(String).join(" • "):"";

const vulnMeta=metrics.vulnerability_intelligence||{enabled:false};
const onlineMeta=(vulnMeta.online&&typeof vulnMeta.online==="object")?vulnMeta.online:null;
const allFindings=REPORT.findings||[];
// Complete per-category counts and dedicated samples; older payloads lack them.
const categoryTotals=(totals.categories&&typeof totals.categories==="object")?totals.categories:null;
const vulnFindings=Array.isArray(REPORT.vulnerability_findings)?REPORT.vulnerability_findings.slice(0,200):[];
let vulnFindingCount=categoryTotals?Number(categoryTotals.vulnerabilities||0):0;
if(!Array.isArray(REPORT.vulnerability_findings)){
 for(const item of allFindings){
  if(item.category==="vulnerabilities"){
   if(!categoryTotals)vulnFindingCount++;
   if(vulnFindings.length<200)vulnFindings.push(item);
  }
 }
}
$("vuln-summary").textContent=[
 vulnMeta.enabled?number(vulnMeta.advisory_count||0)+" local advisories":"No local advisory database",
 onlineMeta
  ? (onlineMeta.coverage==="skipped"?"online lookup skipped":"OSV.dev: "+number(onlineMeta.packages_queried||0)+" package(s) checked ("+String(onlineMeta.coverage||"unknown")+")")
  : "online lookup off",
 number(vulnFindingCount)+" vulnerability finding(s)",
].join(" • ");
$("vuln-db-state").textContent=!vulnMeta.enabled?"NO LOCAL DATABASE":vulnMeta.coverage==="skipped"?"LOCAL DATABASE SKIPPED":"LOCAL DATABASE ACTIVE";
const onlineState=$("vuln-online-state");
onlineState.textContent=onlineMeta?"ONLINE: "+String(onlineMeta.coverage||"unknown").toUpperCase():"ONLINE LOOKUP OFF";
onlineState.className="badge"+(onlineMeta?" "+String(onlineMeta.coverage||"unknown"):"");
const onlineCache=onlineMeta&&onlineMeta.cache?onlineMeta.cache:{};
const onlineRequests=onlineMeta&&onlineMeta.requests?onlineMeta.requests:{};
const requestHosts=Object.entries(onlineRequests.requests_by_host||{}).map(function(pair){return pair[0]+" "+number(pair[1]);}).join(", ");
keyValues($("vuln-provenance"),onlineMeta?(onlineMeta.coverage==="skipped"?[["Online lookup","skipped: "+String(onlineMeta.reason||"")]]:[
 ["Online source",String(onlineMeta.provider||"OSV.dev")+" ("+String(onlineMeta.endpoint||"")+")"],
 ["Enrichment",(onlineMeta.enrichment||[]).length?(onlineMeta.enrichment||[]).join(", "):"none"],
 ["Query time",String(onlineMeta.query_started_at||"?")+" → "+String(onlineMeta.query_finished_at||"?")+" ("+String(onlineMeta.query_seconds||0)+" s)"],
 ["Coverage",onlineMeta.coverage],
 ["Lockfiles",number(onlineMeta.lockfiles||0)+" read, "+number(onlineMeta.lockfiles_unreadable||0)+" unreadable"],
 ["Packages",number(onlineMeta.unique_packages||0)+" unique • "+number(onlineMeta.packages_queried||0)+" checked • "+number(onlineMeta.packages_failed||0)+" failed • "+number(onlineMeta.vulnerable_packages||0)+" with advisories"],
 ["Advisories",number(onlineMeta.advisories||0)],
 ["Cache",onlineCache.enabled?number(onlineCache.hits||0)+" hit(s) • "+number(onlineCache.misses||0)+" miss(es) • TTL "+String((onlineCache.ttl_seconds||0)/3600)+" h":"disabled"],
 ["Requests",number(onlineRequests.requests||0)+(requestHosts?" ("+requestHosts+")":"")+" • retries "+number(onlineRequests.retries||0)+" • failed "+number(onlineRequests.failed_requests||0)],
 ["Data sent",onlineMeta.data_sent],
]):[]);
const onlineIncomplete=Boolean(onlineMeta&&(onlineMeta.coverage==="partial"||onlineMeta.coverage==="unavailable"));
const coverageWarning=$("vuln-coverage-warning");
coverageWarning.textContent=onlineIncomplete
 ? "Online vulnerability lookup is "+String(onlineMeta.coverage)+": "+number(onlineMeta.packages_failed||0)+" package(s) could not be checked and "+number(onlineMeta.lockfiles_unreadable||0)+" lockfile(s) could not be read. This is not a vulnerability-free result; see the UNKNOWN findings."
 : "";
coverageWarning.classList.toggle("hidden",!onlineIncomplete);
$("vuln-db-updated").textContent=vulnMeta.last_imported_at
 ? "Last local import: "+vulnMeta.last_imported_at
   +(vulnMeta.last_source_name?" from "+String(vulnMeta.last_source_name):"")
   +(vulnMeta.stale?" — STALE: "+number(vulnMeta.snapshot_age_days||0)+" days old; advisories published since are missing":"")
 : "No local advisory snapshot metadata";
$("vuln-db-updated").className=vulnMeta.stale?"badge insecure":"muted";
const vulnTarget=$("vulnerability-findings");
for(const item of vulnFindings){
 const card=document.createElement("article");card.className="finding";
 const details=document.createElement("details"),summary=document.createElement("summary");
 const title=document.createElement("span");title.className="finding-title";title.textContent=item.title;
 const severity=document.createElement("span");severity.className="badge sev-"+String(item.severity||"info").toLowerCase();severity.textContent=item.severity||"INFO";
 const confidence=document.createElement("span");confidence.className="badge "+String(item.confidence||"unknown").toLowerCase();confidence.textContent=item.confidence||"UNKNOWN";
 const origin=document.createElement("span");origin.className="badge";
 origin.textContent=item.analyzer==="online-vulnerability-intelligence"?"OSV.DEV":item.analyzer==="local-vulnerability-intelligence"?"LOCAL DB":String(item.analyzer||"core");
 summary.append(title,severity,confidence,origin);details.append(summary);
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
$("no-vulnerabilities").classList.toggle("hidden",vulnFindingCount!==0);
if(vulnFindingCount>200){
 const note=document.createElement("div");note.className="empty";
 note.textContent="Showing first 200 vulnerability matches here. The global findings view and JSON report contain the complete set.";
 vulnTarget.append(note);
}
const vcsCategories=new Set(["vcs","hosting_providers","ci_cd","cloud_services"]);
const vcsFindings=[],providerNameSet=new Set();
let vcsFindingCount=categoryTotals?Array.from(vcsCategories).reduce(function(sum,name){return sum+Number(categoryTotals[name]||0);},0):0;
const vcsSource=Array.isArray(REPORT.vcs_findings)?REPORT.vcs_findings:allFindings;
for(const item of vcsSource){
 if(vcsCategories.has(item.category)){
  if(!categoryTotals)vcsFindingCount++;
  providerNameSet.add(item.title.split(":")[0]);
  if(vcsFindings.length<100)vcsFindings.push(item);
 }
}
const providerNames=Array.from(providerNameSet).sort();
$("vcs-summary").textContent=vcsFindingCount
 ? number(vcsFindingCount)+" evidence item(s) • "+providerNames.slice(0,8).join(" / ")
   +(providerNames.length>8?" / +"+(providerNames.length-8)+" more":"")
 : "No VCS/provider evidence";
const vcsTarget=$("vcs-findings");
for(const item of vcsFindings){
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
$("no-vcs").classList.toggle("hidden",vcsFindingCount!==0);
if(vcsFindingCount>100){
 const note=document.createElement("div");note.className="empty";
 note.textContent="Showing first 100 VCS/provider findings. Use the global findings view or JSON report for the complete set.";
 vcsTarget.append(note);
}
$("inventory-summary").textContent=number(total("files"))+" files • "+
 number(Math.max(0,total("directories")-1))+" directories • "+number(total("symlinks"))+
 " links • "+number(total("special_entries"))+" special entries • "+formatBytes(metrics.total_bytes)+
 (metrics.size_unknown_count?" (plus "+number(metrics.size_unknown_count)+" files of unknown size)":"")+" • "+number(metrics.hidden_entry_count||0)+
 " hidden entries • "+number(metrics.development_directory_count||0)+" development/cache trees";
$("raw-metrics").textContent=JSON.stringify(metrics,null,2);
$("raw-errors").textContent=JSON.stringify(REPORT.errors||[],null,2);
$("raw-analyzers").textContent=JSON.stringify(REPORT.analyzers||[],null,2);

const directoryRows=$("directory-rows"),topDirectories=[];
for(const item of REPORT.directories){
 if(item.path===".")continue;
 let low=0,high=topDirectories.length;
 while(low<high){
  const middle=(low+high)>>1;
  if(Number(topDirectories[middle].total_bytes)>=Number(item.total_bytes))low=middle+1;
  else high=middle;
 }
 if(low<250){topDirectories.splice(low,0,item);if(topDirectories.length>250)topDirectories.pop();}
}
for(const item of topDirectories){
 const tr=document.createElement("tr");
 const marker=[item.development_marker,item.pruned?"pruned":null,item.is_hidden?"hidden":null].filter(Boolean).join(" / ")||"—";
 for(const pair of [[item.path,"path"],[item.depth,""],[number(item.file_count),""],[formatBytes(item.total_bytes),""],[marker,""]]){
  const td=document.createElement("td");td.textContent=String(pair[0]);td.className=pair[1];tr.append(td);
 }
 directoryRows.append(tr);
}
const symlinks=REPORT.symlinks||[],symlinkRows=$("symlink-rows");
const symlinkMore=$("symlink-more"),SYMLINK_PAGE=100;let symlinkOffset=0;
function renderSymlinks(reset){
 if(reset){symlinkOffset=0;symlinkRows.replaceChildren();}
 const end=Math.min(symlinkOffset+SYMLINK_PAGE,symlinks.length);
 while(symlinkOffset<end){
  const item=symlinks[symlinkOffset++],tr=document.createElement("tr");
  const mode=item.permissions===null||item.permissions===undefined?"unknown":Number(item.permissions).toString(8);
  for(const pair of [[item.path,"path"],[item.target,"path"],[item.target_scope,""],[item.target_state||"unverified",""],[mode,"mono"],[item.is_hidden?"yes":"no",""]]){
   const td=document.createElement("td");td.textContent=String(pair[0]);td.className=pair[1];tr.append(td);
  }
  symlinkRows.append(tr);
 }
 $("symlink-page-info").textContent="Showing "+number(symlinkOffset)+" of "+number(symlinks.length)+" links";
 symlinkMore.disabled=symlinkOffset>=symlinks.length;
 symlinkMore.textContent=symlinkMore.disabled?"All links loaded":"Load next page";
}
symlinkMore.addEventListener("click",function(){renderSymlinks(false);});
$("symlink-pagination").classList.toggle("hidden",symlinks.length===0);
$("no-symlinks").classList.toggle("hidden",symlinks.length!==0);
renderSymlinks(true);

const specialEntries=REPORT.special_entries||[],specialRows=$("special-rows");
const specialMore=$("special-more"),SPECIAL_PAGE=100;let specialOffset=0;
function renderSpecialEntries(reset){
 if(reset){specialOffset=0;specialRows.replaceChildren();}
 const end=Math.min(specialOffset+SPECIAL_PAGE,specialEntries.length);
 while(specialOffset<end){
  const item=specialEntries[specialOffset++],tr=document.createElement("tr");
  const mode=item.permissions===null||item.permissions===undefined?"unknown":Number(item.permissions).toString(8);
  for(const pair of [[item.path,"path"],[item.entry_type,""],[mode,"mono"],[item.is_hidden?"yes":"no",""],[formatBytes(item.size_bytes||0),""]]){
   const td=document.createElement("td");td.textContent=String(pair[0]);td.className=pair[1];tr.append(td);
  }
  specialRows.append(tr);
 }
 $("special-page-info").textContent="Showing "+number(specialOffset)+" of "+number(specialEntries.length)+" entries";
 specialMore.disabled=specialOffset>=specialEntries.length;
 specialMore.textContent=specialMore.disabled?"All entries loaded":"Load next page";
}
specialMore.addEventListener("click",function(){renderSpecialEntries(false);});
$("special-pagination").classList.toggle("hidden",specialEntries.length===0);
$("no-special").classList.toggle("hidden",specialEntries.length!==0);
renderSpecialEntries(true);

const files=REPORT.files;
const fileSearch=$("file-search"),fileKind=$("file-kind"),fileRows=$("file-rows"),fileMore=$("file-more");
const fileTypeSet=new Set();
for(const item of files)fileTypeSet.add(item.file_type||"unknown");
for(const type of Array.from(fileTypeSet).sort()){const option=document.createElement("option");option.value=type;option.textContent=type;fileKind.append(option);}
const FILE_PAGE=100;let fileOffset=0,fileScanIndex=0,fileMatchCount=0;
function fileMatchesFilter(item,query,kind){
 return (!query||(item.path+" "+item.language+" "+item.file_type).toLowerCase().includes(query))&&
  (!kind||(item.file_type||"unknown")===kind);
}
function countMatchingFiles(query,kind){
 let count=0;for(const item of files)if(fileMatchesFilter(item,query,kind))count++;return count;
}
function renderFiles(reset){
 const query=fileSearch.value.trim().toLowerCase(),kind=fileKind.value;
 if(reset){fileOffset=0;fileScanIndex=0;fileRows.replaceChildren();fileMatchCount=countMatchingFiles(query,kind);}
 let rendered=0;
 while(fileScanIndex<files.length&&rendered<FILE_PAGE){
  const item=files[fileScanIndex++];
  if(!fileMatchesFilter(item,query,kind))continue;
  const tr=document.createElement("tr");
  const flags=[item.is_hidden?"hidden":null,item.content_skipped_reason?"content skipped":null,item.error?"error":null].filter(Boolean).join(" / ")||"—";
  for(const pair of [[item.path,"path"],[formatBytes(item.size_bytes),""],[item.file_type||"unknown",""],[item.language,""],[flags,""]]){
   const td=document.createElement("td");td.textContent=String(pair[0]);td.className=pair[1];tr.append(td);
  }
  fileRows.append(tr);rendered++;fileOffset++;
 }
 $("file-page-info").textContent="Showing "+number(fileOffset)+" of "+number(fileMatchCount)+" matching files";
 fileMore.disabled=fileScanIndex>=files.length;fileMore.textContent=fileMore.disabled?"End of inventory":"Load next page";
}
let fileSearchTimer=0;
fileSearch.addEventListener("input",function(){
 clearTimeout(fileSearchTimer);
 fileSearchTimer=setTimeout(function(){renderFiles(true);},120);
});
fileKind.addEventListener("change",function(){renderFiles(true);});
fileMore.addEventListener("click",function(){renderFiles(false);});
$("file-reset").addEventListener("click",function(){fileSearch.value="";fileKind.value="";renderFiles(true);});
renderFiles(true);

const findings=REPORT.findings||[],categorySet=new Set();
for(const item of findings)categorySet.add(item.category);
for(const value of Array.from(categorySet).sort()){const option=document.createElement("option");option.value=value;option.textContent=value;$("category").append(option);}
const search=$("search"),category=$("category"),confidence=$("confidence"),severity=$("severity");
const list=$("finding-list"),loadMore=$("load-more"),FINDING_PAGE=100;
let findingOffset=0,findingScanIndex=0,findingMatchCount=0,expandFuture=false;
let activeFindingFilter={query:"",category:"",confidence:"",severity:""};
function findingMatchesFilter(item,filter){
 const haystack=[item.title,item.detail,(item.evidence||[]).join(" ")].join(" ").toLowerCase();
 return (!filter.query||haystack.includes(filter.query))&&
  (!filter.category||item.category===filter.category)&&
  (!filter.confidence||item.confidence===filter.confidence)&&
  (!filter.severity||item.severity===filter.severity);
}
function countMatchingFindings(filter){
 let count=0;for(const item of findings)if(findingMatchesFilter(item,filter))count++;return count;
}
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
 if(item.impact){
  const impact=document.createElement("div");impact.className="impact-block";
  const impactLabel=document.createElement("strong");impactLabel.textContent="POTENTIAL ATTACKER IMPACT";
  const impactText=document.createElement("p");impactText.textContent=item.impact;
  impact.append(impactLabel,impactText);body.append(impact);
 }
 if(item.recommendation){
  const recommendation=document.createElement("div");recommendation.className="recommendation-block";
  const recommendationLabel=document.createElement("strong");recommendationLabel.textContent="RECOMMENDED REMEDIATION";
  const recommendationText=document.createElement("p");recommendationText.textContent=item.recommendation;
  recommendation.append(recommendationLabel,recommendationText);body.append(recommendation);
 }
 if(Array.isArray(item.code_evidence)&&item.code_evidence.length){
  const codeEvidence=document.createElement("div");codeEvidence.className="vulnerable-code";
  const codeLabel=document.createElement("strong");codeLabel.textContent="VULNERABLE SOURCE LINES // REDACTED";
  codeEvidence.append(codeLabel);
  for(const sourceLine of item.code_evidence.slice(0,20)){
   const line=document.createElement("div");line.className="vulnerable-line";
   const number=document.createElement("span");number.className="line-number";
   number.textContent="L"+String(sourceLine.line_number);
   const code=document.createElement("code");code.textContent=String(sourceLine.code||"");
   line.append(number,code);codeEvidence.append(line);
  }
  body.append(codeEvidence);
 }
 const evidence=document.createElement("div");evidence.className="evidence";
 const label=document.createElement("strong");label.textContent="Evidence";evidence.append(label);
 const ul=document.createElement("ul");
 for(const text of (item.evidence||[])){const li=document.createElement("li"),code=document.createElement("code");code.textContent=text;li.append(code);ul.append(li);}
 evidence.append(ul);
 const analyzer=document.createElement("div");analyzer.className="muted";analyzer.textContent="Analyzer: "+(item.analyzer||"core");
 body.append(description,evidence,analyzer);details.append(summary,body);article.append(details);return article;
}
function updateFindingFilter(reset){
 if(reset){
  activeFindingFilter={query:search.value.trim().toLowerCase(),category:category.value,confidence:confidence.value,severity:severity.value};
  findingOffset=0;findingScanIndex=0;list.replaceChildren();
  findingMatchCount=countMatchingFindings(activeFindingFilter);
 }
 $("finding-count").textContent=number(findingMatchCount)+" matching findings";
 $("no-findings").classList.toggle("hidden",findingMatchCount!==0);
 appendFindings();
}
function appendFindings(){
 let rendered=0;
 while(findingScanIndex<findings.length&&rendered<FINDING_PAGE){
  const item=findings[findingScanIndex++];
  if(!findingMatchesFilter(item,activeFindingFilter))continue;
  list.append(makeFinding(item));rendered++;findingOffset++;
 }
 $("page-count").textContent="Rendered "+number(findingOffset)+" / "+number(findingMatchCount);
 loadMore.disabled=findingScanIndex>=findings.length;loadMore.textContent=loadMore.disabled?"All filtered findings loaded":"Load next page";
}
let findingSearchTimer=0;
search.addEventListener("input",function(){
 clearTimeout(findingSearchTimer);
 findingSearchTimer=setTimeout(function(){updateFindingFilter(true);},120);
});
category.addEventListener("change",function(){updateFindingFilter(true);});
confidence.addEventListener("change",function(){updateFindingFilter(true);});
severity.addEventListener("change",function(){updateFindingFilter(true);});
loadMore.addEventListener("click",appendFindings);
$("open-all").addEventListener("click",function(){expandFuture=true;for(const details of list.querySelectorAll("details"))details.open=true;});
$("close-all").addEventListener("click",function(){expandFuture=false;for(const details of list.querySelectorAll("details"))details.open=false;});
$("reset").addEventListener("click",function(){search.value="";category.value="";confidence.value="";severity.value="";expandFuture=false;updateFindingFilter(true);});
updateFindingFilter(true);
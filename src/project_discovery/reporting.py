"""Local JSON, Markdown and standalone interactive HTML report generation."""
from __future__ import annotations

import html
import json
import re
from pathlib import Path

from .models import ScanResult


def _slug(value: str) -> str:
    normalized = re.sub(r"[^a-z0-9]+", "-", value.lower()).strip("-")
    return normalized or "other"


def _html_report(result: ScanResult) -> str:
    categories = sorted({finding.category for finding in result.findings})
    category_options = "".join(
        f'<option value="{html.escape(category, quote=True)}">{html.escape(category)}</option>'
        for category in categories
    )
    category_links = "".join(
        f'<a href="#category-{_slug(category)}">{html.escape(category)}</a>'
        for category in categories
    )
    cards_by_category: dict[str, list[str]] = {category: [] for category in categories}
    for index, finding in enumerate(result.findings):
        category = html.escape(finding.category, quote=True)
        confidence = html.escape(finding.confidence, quote=True)
        severity = html.escape(finding.severity, quote=True)
        title = html.escape(finding.title)
        detail = html.escape(finding.detail)
        evidence = "".join(
            f"<li><code>{html.escape(item)}</code></li>" for item in finding.evidence
        )
        analyzer = html.escape(finding.analyzer)
        cards_by_category[finding.category].append(
            f'<article class="finding" data-category="{category}" data-severity="{severity}" '
            f'data-confidence="{confidence}" data-search="{html.escape((finding.title + " " + finding.detail + " " + " ".join(finding.evidence)).lower(), quote=True)}">'
            f'<details {"open" if index < 3 else ""}><summary>'
            f'<span class="badge {confidence.lower()}">{confidence}</span>'
            f'<span class="badge severity-{severity.lower()}">{severity}</span>'
            f'<span class="finding-title">{title}</span></summary>'
            f'<p>{detail}</p><div class="evidence"><b>Evidence</b><ul>{evidence}</ul></div>'
            f'<small>Analyzer: {analyzer}</small></details></article>'
        )

    sections = "".join(
        f'<section id="category-{_slug(category)}"><h2>{html.escape(category)} '
        f'<span class="count">{len(cards_by_category[category])}</span></h2>'
        f'{"".join(cards_by_category[category])}</section>'
        for category in categories
    )
    metrics = html.escape(json.dumps(result.metrics, indent=2, ensure_ascii=False))
    root = html.escape(result.root)
    generated = html.escape(result.finished_at)
    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>PDT — Project Discovery Report</title>
<style>
:root{{--bg:#090e1b;--panel:#121b2e;--panel2:#18243a;--line:#293955;--text:#e6edf7;--muted:#94a3b8;--accent:#67e8f9;--green:#86efac;--yellow:#fde68a;--red:#fca5a5}}
*{{box-sizing:border-box}}html{{scroll-behavior:smooth}}body{{margin:0;background:var(--bg);color:var(--text);font:15px/1.55 system-ui,-apple-system,Segoe UI,sans-serif}}
a{{color:var(--accent);text-decoration:none}}a:hover{{text-decoration:underline}}
.shell{{max-width:1400px;margin:auto;padding:30px 24px 80px}}header,.panel,.finding{{background:var(--panel);border:1px solid var(--line);border-radius:14px}}
header{{padding:28px;margin-bottom:20px;background:linear-gradient(135deg,#14213a,#101827)}}
.eyebrow{{color:var(--accent);font-size:12px;font-weight:700;letter-spacing:.16em;text-transform:uppercase}}
h1{{font-size:clamp(28px,4vw,42px);line-height:1.1;margin:8px 0 14px}}h2{{font-size:22px;margin:32px 0 14px;text-transform:capitalize}}
.muted,small{{color:var(--muted)}}.root{{overflow-wrap:anywhere;font-family:ui-monospace,monospace}}
.stats{{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px;margin:20px 0}}
.stat{{background:var(--panel2);border:1px solid var(--line);padding:16px;border-radius:12px}}.stat strong{{display:block;font-size:26px}}
.layout{{display:grid;grid-template-columns:230px minmax(0,1fr);gap:22px;align-items:start}}
nav{{position:sticky;top:18px;padding:18px}}nav a{{display:block;padding:6px 0;color:var(--muted)}}
.panel{{padding:18px}}.controls{{display:flex;gap:10px;flex-wrap:wrap;margin-bottom:18px}}
input,select{{background:#0c1424;border:1px solid var(--line);border-radius:9px;color:var(--text);padding:11px 12px;font:inherit}}
input{{flex:1;min-width:220px}}select{{min-width:150px}}
.finding{{margin:10px 0;padding:0 16px}}summary{{cursor:pointer;display:flex;align-items:center;gap:12px;padding:14px 0;list-style:none}}summary::-webkit-details-marker{{display:none}}
.finding-title{{font-weight:650;overflow-wrap:anywhere}}.badge{{font-size:11px;font-weight:800;padding:3px 8px;border-radius:20px;background:#26364d;white-space:nowrap}}
.badge.confirmed{{color:var(--green)}}.badge.inferred{{color:var(--yellow)}}.badge.unknown{{color:var(--red)}}.badge.severity-critical{{background:#7f1d1d;color:#fecaca}}.badge.severity-high{{background:#7f1d1d;color:#fecaca}}.badge.severity-medium{{color:var(--yellow)}}.badge.severity-low{{color:var(--accent)}}.badge.severity-info{{color:var(--muted)}}
.evidence{{border-top:1px solid var(--line);padding-top:8px;margin-top:12px}}ul{{padding-left:22px}}code,pre{{font-family:ui-monospace,SFMono-Regular,monospace}}code{{overflow-wrap:anywhere;color:#bae6fd}}
.count{{font-size:12px;color:var(--muted);background:var(--panel2);padding:3px 8px;border-radius:20px}}
pre{{white-space:pre-wrap;overflow-wrap:anywhere;background:#070b14;padding:18px;border:1px solid var(--line);border-radius:12px;max-height:600px;overflow:auto}}
.empty{{padding:26px;text-align:center;color:var(--muted)}}.hidden{{display:none!important}}
@media(max-width:800px){{.layout{{grid-template-columns:1fr}}nav{{position:static}}}}
</style>
</head>
<body><div class="shell">
<header><div class="eyebrow">Local-first static analysis</div><h1>PROJECT DISCOVERY TOOL</h1>
<div class="muted">Project: <span class="root">{root}</span></div><div class="muted">Completed: {generated}</div>
<div class="stats">
<div class="stat"><span class="muted">Files</span><strong>{len(result.files):,}</strong></div>
<div class="stat"><span class="muted">Findings</span><strong>{len(result.findings):,}</strong></div>
<div class="stat"><span class="muted">Analyzers</span><strong>{len(result.analyzer_names):,}</strong></div>
<div class="stat"><span class="muted">Scan errors</span><strong>{len(result.errors):,}</strong></div>
</div></header>
<div class="layout"><nav class="panel"><b>Report navigation</b><a href="#findings">All findings</a>{category_links}<a href="#metrics">Raw metrics</a></nav>
<main class="panel"><h2 id="findings">Findings</h2>
<div class="controls"><input id="search" type="search" placeholder="Search findings, evidence, paths...">
<select id="category"><option value="">All categories</option>{category_options}</select>
<select id="confidence"><option value="">All confidence levels</option><option>CONFIRMED</option><option>INFERRED</option><option>UNKNOWN</option></select>
<select id="severity"><option value="">All severities</option><option>CRITICAL</option><option>HIGH</option><option>MEDIUM</option><option>LOW</option><option>INFO</option></select>
<button id="reset" type="button">Reset filters</button></div>
<div id="results">{sections}<div id="empty" class="empty hidden">No findings match the current filters.</div></div>
<h2 id="metrics">Scan metrics</h2><details><summary>Show raw metrics JSON</summary><pre>{metrics}</pre></details>
</main></div></div>
<script>
"use strict";
const search=document.getElementById("search");
const category=document.getElementById("category");
const confidence=document.getElementById("confidence");
const severity=document.getElementById("severity");
const cards=[...document.querySelectorAll(".finding")];
const sections=[...document.querySelectorAll("main section")];
const empty=document.getElementById("empty");
function applyFilters(){{
 const q=search.value.trim().toLowerCase();
 let visible=0;
 for(const card of cards){{
  const matchText=!q||card.dataset.search.includes(q);
  const matchCategory=!category.value||card.dataset.category===category.value;
  const matchConfidence=!confidence.value||card.dataset.confidence===confidence.value;
  const matchSeverity=!severity.value||card.dataset.severity===severity.value;
  const show=matchText&&matchCategory&&matchConfidence&&matchSeverity;
  card.classList.toggle("hidden",!show);
  if(show)visible++;
 }}
 for(const section of sections){{
  const hasVisible=[...section.querySelectorAll(".finding")].some(card=>!card.classList.contains("hidden"));
  section.classList.toggle("hidden",!hasVisible);
 }}
 empty.classList.toggle("hidden",visible!==0);
}}
search.addEventListener("input",applyFilters);
category.addEventListener("change",applyFilters);
confidence.addEventListener("change",applyFilters);
severity.addEventListener("change",applyFilters);
document.getElementById("reset").addEventListener("click",()=>{{
 search.value="";category.value="";confidence.value="";severity.value="";applyFilters();
}});
</script></body></html>"""


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
        lines = [
            "# Project Discovery Report", "",
            f"- Root: {result.root}",
            f"- Files: {len(result.files)}",
            f"- Findings: {len(result.findings)}", "",
            "## Findings", "",
        ]
        for item in result.findings:
            lines.extend([
                f"### [{item.severity}][{item.confidence}] {item.title}", "",
                item.detail, "",
                "Evidence: " + ", ".join(item.evidence), "",
            ])
        path.write_text("\n".join(lines), encoding="utf-8")
        written.append(path)
    if "html" in formats:
        path = output / "discovery-report.html"
        path.write_text(_html_report(result), encoding="utf-8")
        written.append(path)
    return written

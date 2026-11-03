"""Local JSON, Markdown and standalone HTML report generation."""
import html
import json
from pathlib import Path
from .models import ScanResult

def write_reports(result: ScanResult, output: Path, formats: set[str]) -> list[Path]:
    output.mkdir(parents=True,exist_ok=True)
    data = result.to_dict()
    written: list[Path] = []
    if "json" in formats:
        path = output / "discovery-report.json"
        path.write_text(json.dumps(data,indent=2,ensure_ascii=False)+"\n",encoding="utf-8")
        written.append(path)
    if "markdown" in formats:
        path = output / "discovery-report.md"
        lines = ["# Project Discovery Report","",f"- Root: {result.root}",
                 f"- Files: {len(result.files)}",f"- Findings: {len(result.findings)}","","## Findings",""]
        for item in result.findings:
            lines.extend([f"### [{item.confidence}] {item.title}","",item.detail,"",
                          "Evidence: "+", ".join(item.evidence),""])
        path.write_text("\n".join(lines),encoding="utf-8")
        written.append(path)
    if "html" in formats:
        cards = "".join("<article><b>"+html.escape(x.confidence)+"</b><h3>"+
            html.escape(x.title)+"</h3><p>"+html.escape(x.detail)+"</p><small>"+
            html.escape(", ".join(x.evidence))+"</small></article>" for x in result.findings)
        metrics = html.escape(json.dumps(result.metrics,indent=2))
        page = ("<!doctype html><html><head><meta charset='utf-8'><meta name='viewport' content='width=device-width'>"
          "<title>PDT Report</title><style>body{max-width:1100px;margin:40px auto;padding:0 20px;background:#0b1020;color:#e5e7eb;font:16px system-ui}"
          "article,header{background:#151d31;border:1px solid #293550;border-radius:12px;padding:18px;margin:14px 0}"
          "b{color:#86efac}small{color:#9ca3af}</style></head><body><h1>PROJECT-DISCOVERY-TOOL</h1><header>Root: "+
          html.escape(result.root)+" | Files: "+str(len(result.files))+" | Findings: "+
          str(len(result.findings))+"</header>"+cards+"<h2>Metrics</h2><pre>"+metrics+"</pre></body></html>")
        path = output / "discovery-report.html"
        path.write_text(page,encoding="utf-8")
        written.append(path)
    return written

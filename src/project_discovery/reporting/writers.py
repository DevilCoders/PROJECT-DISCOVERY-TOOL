"""Local JSON, Markdown and offline interactive HTML report generation."""
from __future__ import annotations

import heapq
import html
import io
import json
import re
import secrets
from collections import Counter
from importlib.resources import files as resource_files
from itertools import islice
from pathlib import Path
from typing import Any, TextIO
from urllib.parse import urlsplit, urlunsplit

from ..core.source_utils import neutralize_controls
from ..models import REPORT_SCHEMA_VERSION, ScanResult

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
# Each dedicated HTML view (vulnerabilities, VCS/providers) embeds up to this many findings.
_HTML_VIEW_SAMPLE = 200
_VCS_CATEGORIES = frozenset({"vcs", "hosting_providers", "ci_cd", "cloud_services"})
_TEMPLATE_PLACEHOLDER = re.compile(r"__(ROOT|GENERATED|REPORT_JS|CSP_NONCE|MODE_CLASS|MODE_LABEL|MODE_META)__")

# Remote-source fields repeated in the top-level "scan" summary of every report.
_REMOTE_SUMMARY_KEYS = (
    "acquisition", "url", "provider", "vcs", "repository", "ref", "revision", "branch",
    "transport", "transport_insecure", "acquired_at", "acquisition_seconds", "history_complete",
)


def online_gap_text(online: dict[str, Any]) -> str:
    """Why an online lookup is incomplete, from its actual gap counters."""
    parts = [
        f"{int(online.get(key) or 0):,} {label}"
        for key, label in (
            ("packages_failed", "package(s) could not be checked"),
            ("packages_not_queried", "package(s) beyond the query limit were not checked"),
            ("lockfiles_unreadable", "lockfile(s) could not be read"),
            ("lockfiles_content_skipped", "lockfile(s) were skipped by --skip"),
            ("advisory_details_unavailable", "advisory record(s) could not be loaded"),
        )
        if online.get(key)
    ]
    return "; ".join(parts) or "see the UNKNOWN findings for the cause"


def public_url(value: Any) -> str:
    """Return a URL without passwords, query strings or fragments (SSH user names kept)."""
    text = str(value or "")
    if "://" not in text:
        return text
    try:
        parts = urlsplit(text)
        host = parts.hostname or ""
        port = parts.port
    except ValueError:
        # Unparseable (a port out of range, a malformed IPv6 host): still never keep userinfo.
        text = re.sub(r"^([A-Za-z][A-Za-z0-9+.-]{0,31}+://)[^/@\s]{0,1024}+@", r"\1", text)
        return text.split("?", 1)[0].split("#", 1)[0]
    netloc = f"[{host}]" if ":" in host else host
    if port is not None:
        netloc += f":{port}"
    if parts.username and parts.scheme.lower() in {"ssh", "pserver", "git+ssh", "svn+ssh", "bzr+ssh"}:
        netloc = f"{parts.username}@{netloc}"
    return urlunsplit((parts.scheme, netloc, parts.path, "", ""))


def attribute_summary(counts: dict[str, int], limit: int = 8) -> str:
    """The most common entry attributes with their counts, such as "archive 1,204, readonly 3"."""
    ranked = sorted(counts.items(), key=lambda item: (-item[1], item[0]))
    text = ", ".join(f"{name} {count:,}" for name, count in ranked[:limit])
    if len(ranked) > limit:
        text += f", and {len(ranked) - limit} more"
    return text or "none recorded"


def _link_outcome(item) -> str:
    """A link's resolution, such as "resolved: file src/a.py" or "broken: gone does not exist"."""
    state = getattr(item, "target_state", None) or "unverified"
    if state == "resolved":
        return f"resolved: {item.resolved_type} {item.resolved_path}"
    detail = getattr(item, "target_detail", None)
    return f"{state}: {detail}" if detail else state


def development_summary(metrics: dict[str, Any]) -> str:
    """"412 (380 confirmed, 20 by name, 12 possible)": marked trees by marker confidence."""
    count = metrics.get("development_directory_count", 0)
    confidence = metrics.get("development_confidence") or {}
    parts = [
        f"{confidence[key]:,} {label}" for key, label in (
            ("confirmed", "confirmed"), ("name", "by name"), ("possible", "possible"),
        ) if confidence.get(key)
    ]
    return f"{count:,}" + (f" ({', '.join(parts)})" if parts else "")


def _limit_text(timeout: Any, memory: Any) -> str:
    time_text = f"{timeout:g} s" if timeout else "no time limit"
    memory_text = f"{memory:,} MiB" if memory else "no memory limit"
    return f"{time_text} and {memory_text}"


def size_text(value: Any) -> str:
    """A byte count for people: "1.5 MiB", "640 bytes"."""
    value = float(value or 0)
    for unit, scale in (("GiB", 1 << 30), ("MiB", 1 << 20), ("KiB", 1 << 10)):
        if value >= scale:
            scaled = f"{value / scale:,.1f}"
            return f"{scaled[:-2] if scaled.endswith('.0') else scaled} {unit}"
    return f"{value:,.0f} bytes"


def cap_text(name: str, value: Any) -> str:
    """One declared cap for people: "line_bytes 256 KiB", "findings 10,000"."""
    if name.endswith("_bytes"):
        return f"{name} {size_text(value)}"
    if name.endswith("_seconds"):
        return f"{name} {value:g}"
    return f"{name} {value:,}"


def _limit_value_text(kind: str, value: Any) -> str:
    if kind == "bytes":
        return size_text(value)
    if kind == "wall_time":
        return f"{value:g} s"
    return f"{value:,.0f} {kind}"


def budget_summary(budgets: dict[str, Any] | None) -> str:
    """"120 s and 2,048 MiB per analyzer and file; 1 domain override; 2 stopped (time 2)"."""
    budgets = budgets or {}
    if not budgets:
        return "not recorded"
    text = f"{_limit_text(budgets.get('timeout_seconds'), budgets.get('memory_mb'))} per analyzer and file"
    if budgets.get("memory_mb") and not budgets.get("memory_enforced"):
        text += " (memory is not measured on this platform)"
    overrides = budgets.get("domain_overrides") or {}
    if overrides:
        text += f"; {len(overrides)} domain override(s)"
    stops = budgets.get("stops") or {}
    stopped = stops.get("time", 0) + stops.get("memory", 0)
    text += (f"; {stopped:,} call(s) stopped (time {stops.get('time', 0):,}, memory {stops.get('memory', 0):,})"
             if stopped else "; no call stopped")
    reached = budgets.get("limits_reached") or {}
    if reached:
        text += f"; {sum(reached.values()):,} content limit(s) reached (" + ", ".join(
            f"{kind} {count:,}" for kind, count in reached.items()) + ")"
    return text


def _write_markdown_budgets(line, budgets: dict[str, Any]) -> None:
    line("## Analyzer Budgets")
    line()
    line(f"- Budget: {_md(budget_summary(budgets))}")
    for domain, values in (budgets.get("domain_overrides") or {}).items():
        line(f"- Domain {_md(domain)}: " + _md(_limit_text(
            values.get("timeout_seconds", budgets.get("timeout_seconds")),
            values.get("memory_mb", budgets.get("memory_mb")),
        )))
    for item in (budgets.get("stopped") or [])[:20]:
        unit = "s" if item["budget"] == "time" else "MiB"
        line(f"- Stopped: {_md(item['path'])}: {_md(item['analyzer'])}, {item['budget']} budget "
             f"{item['limit']:g} {unit}, at {item['used']:,.1f} {unit}")
    for item in (budgets.get("limited") or [])[:20]:
        used = "" if item.get("used") is None else f", at {_limit_value_text(item['limit'], item['used'])}"
        line(f"- Limit reached: {_md(item['path'])}: {_md(item['analyzer'])}, "
             f"{_limit_value_text(item['limit'], item['value'])} limit{used}")
    declared = budgets.get("analyzer_limits") or {}
    analyzers = budgets.get("analyzers") or {}
    if analyzers:
        line()
        line("Time per analyzer over all files (the ten slowest):")
        line()
        for name, entry in list(analyzers.items())[:10]:
            memory = (f", peak memory growth {entry['max_memory_mb']:,.1f} MiB"
                      if entry.get("max_memory_mb") is not None else "")
            limits = declared.get(name) or {}
            budget = (f" (budget {size_text(limits['file_bytes'])} per file, {limits['reads']})"
                      if limits.get("file_bytes") else "")
            reached = (f", {entry['limits_reached']:,} limit(s) reached"
                       if entry.get("limits_reached") else "")
            line(f"- {_md(name)}: {entry['seconds']:,.2f} s over {entry['calls']:,} file(s), longest "
                 f"{entry['max_seconds']:,.2f} s ({_md(entry['max_seconds_path'] or '-')}), read "
                 f"{size_text(entry.get('bytes_read'))}{budget}{reached}{memory}")
    if declared:
        line()
        line("Content limits the analyzers declare:")
        line()
        line("| Analyzer | Reads | Per-file budget | Other limits |")
        line("|---|---|---:|---|")
        for name, limits in declared.items():
            if limits is None:
                line(f"| {_md(name)} | not declared | - | - |")
                continue
            caps = ", ".join(cap_text(key, value) for key, value in (limits.get("caps") or {}).items())
            budget = size_text(limits["file_bytes"]) if limits.get("file_bytes") else "-"
            line(f"| {_md(name)} | {limits['reads']} | {budget} | {_md(caps) or '-'} |")
    line()


def tree_mode_summary(trees: dict[str, Any] | None) -> str:
    """What --development-trees did, such as "directory-only: 3 trees, 120,412 files not recorded"."""
    trees = trees or {}
    mode = trees.get("mode") or "deep"
    if mode == "deep":
        return "deep: inventoried and analyzed like any other directory"
    count = trees.get("trees", 0)
    if mode == "inventory":
        return f"inventory: {count:,} tree(s), {trees.get('files_not_read', 0):,} files recorded but not read"
    return (
        f"directory-only: {count:,} tree(s), {trees.get('files_not_recorded', 0):,} files "
        f"({trees.get('bytes_not_recorded', 0):,} bytes) and "
        f"{trees.get('links_and_special_entries_not_recorded', 0):,} links or special entries counted, not recorded"
    )


def _marker_label(item) -> str:
    """"node_modules: dependencies, confirmed by .package-lock.json" for a marked directory."""
    confidence = getattr(item, "marker_confidence", None)
    category = getattr(item, "marker_category", None)
    if not confidence:
        return item.development_marker
    how = {"confirmed": f"confirmed by {item.marker_evidence}", "name": "by name"}.get(confidence, "possible")
    return f"{item.development_marker}: {category}, {how}"


_TYPE_SOURCES = ("signature", "content", "name")
_MISMATCH_EXAMPLES = 20


def type_summary(metrics: dict[str, Any]) -> list[tuple[str, str]]:
    """(label, text) lines on how file types were determined, shared by the terminal and Markdown."""
    sources = metrics.get("type_sources") or {}
    if not sources:
        return []
    lines = [("File types determined by", ", ".join(
        f"{name} {sources.get(name, 0):,}" for name in _TYPE_SOURCES if name in sources or name != "name"
    ))]
    if metrics.get("mime_types"):
        lines.append(("MIME types", attribute_summary(metrics["mime_types"], limit=6)))
    mismatches = metrics.get("type_mismatches") or {}
    if mismatches.get("count"):
        lines.append(("Name/content mismatches", (
            f"{mismatches['count']:,} ({attribute_summary(mismatches.get('pairs') or {}, limit=4)})"
        )))
    if metrics.get("git_lfs_pointer_count"):
        lines.append(("Git LFS pointers", f"{metrics['git_lfs_pointer_count']:,} (content not in the tree)"))
    return lines


def _utc_date(mtime_ns: int) -> str:
    from datetime import datetime, timezone

    try:
        return datetime.fromtimestamp(mtime_ns / 1e9, tz=timezone.utc).strftime("%Y-%m-%d")
    except (OverflowError, OSError, ValueError):
        return f"{mtime_ns} ns"


def aggregate_summary(aggregates: dict[str, Any] | None) -> list[tuple[str, str]]:
    """(label, text) lines for metrics.inventory_aggregates, shared by the terminal and Markdown."""
    if not aggregates:
        return []
    if "error" in aggregates:
        return [("Inventory aggregates", str(aggregates["error"]))]
    lines = [("Empty directories", f"{aggregates.get('empty_directory_count', 0):,}")]
    fan_out = aggregates.get("fan_out") or {}
    if fan_out.get("max_path") is not None:
        lines.append((
            "Largest directory fan-out",
            f"{fan_out['max']:,} entries in {fan_out['max_path']} (mean {fan_out.get('mean', 0)})",
        ))
    links = aggregates.get("hard_links") or {}
    lines.append(("Hard-linked files", (
        f"{links.get('hard_linked_files', 0):,} in {links.get('groups', 0):,} group(s)"
        if links.get("supported") else "not determined: no file identities were recorded"
    )))
    for key, label in (("owners", "Owners (uid)"), ("groups", "Groups (gid)"), ("owner_sids", "Owners (SID)")):
        if aggregates.get(key):
            lines.append((label, attribute_summary(aggregates[key], limit=5)))
    timestamps = aggregates.get("file_timestamps") or {}
    if timestamps.get("oldest") and timestamps.get("newest"):
        text = (
            f"oldest {_utc_date(timestamps['oldest']['mtime_ns'])} ({timestamps['oldest']['path']}), "
            f"newest {_utc_date(timestamps['newest']['mtime_ns'])} ({timestamps['newest']['path']})"
        )
        unusual = [
            f"{timestamps[key]:,} {label}" for key, label in (
                ("future_count", "in the future"), ("before_1980_count", "before 1980"),
            ) if timestamps.get(key)
        ]
        lines.append(("File modification times", text + (f"; {', '.join(unusual)}" if unusual else "")))
    return lines


def security_metadata_summary(metrics: dict[str, Any]) -> str:
    """One line on the --security-metadata block of the scan metrics."""
    security = metrics.get("security_metadata") or {}
    if not security.get("enabled"):
        return "not recorded (pdt scan --security-metadata records owners and ACLs)"
    return (
        f"{security.get('entries', 0):,} entries read, {security.get('explicit_acl_entries', 0):,} "
        f"with ACL entries of their own, {security.get('errors', 0):,} unreadable"
    )


def scan_summary(metrics: dict[str, Any]) -> dict[str, Any]:
    """Describe how a scan obtained its data: local or online, and every network use.

    ``mode`` is "online" when PDT used the network for this scan (fetching the repository
    or querying advisory services) and "local" otherwise. The same summary feeds the JSON,
    Markdown and HTML reports so they cannot disagree.
    """
    source = metrics.get("source") if isinstance(metrics.get("source"), dict) else {}
    remote = source.get("remote") if isinstance(source.get("remote"), dict) else None
    vulnerabilities = metrics.get("vulnerability_intelligence")
    vulnerabilities = vulnerabilities if isinstance(vulnerabilities, dict) else {}
    online = vulnerabilities.get("online") if isinstance(vulnerabilities.get("online"), dict) else None
    network: list[str] = []
    remote_summary = None
    if remote is not None:
        acquisition = str(remote.get("acquisition") or "download")
        network.append("provider-api" if acquisition == "api" else f"{remote.get('vcs') or 'vcs'}-client")
        remote_summary = {key: remote.get(key) for key in _REMOTE_SUMMARY_KEYS}
        remote_summary["acquisition"] = acquisition
        remote_summary["url"] = public_url(remote.get("url"))
        remote_summary["coverage_gap_count"] = len(remote.get("coverage_gaps") or [])
    requests = online.get("requests") if online is not None and isinstance(online.get("requests"), dict) else {}
    if online is not None and online.get("coverage") != "skipped" and int(requests.get("requests") or 0) > 0:
        # Only services that were contacted: a lookup with no lockfile sends nothing.
        network.append("osv.dev")
        network.extend(sorted(str(item) for item in online.get("enrichment") or []))
    sources = vulnerabilities.get("sources")
    if not isinstance(sources, list):
        sources = ["local-database"] if vulnerabilities.get("enabled") else []
    return {
        "mode": "online" if network else "local",
        "source": "remote" if remote is not None else "local",
        "network_access": network,
        "remote": remote_summary,
        "vulnerability_sources": list(sources),
        "online_vulnerability_coverage": online.get("coverage") if online else None,
    }


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
    report_js = resource_files("project_discovery").joinpath("reporting/web/report.js").read_text(encoding="utf-8")
    if report_js.count("__DATA__") != 1:
        raise RuntimeError("report.js must contain exactly one __DATA__ placeholder")
    summary = scan_summary(result.metrics)
    online = summary["mode"] == "online"
    values = {
        "ROOT": html.escape(result.root),
        "GENERATED": html.escape(result.finished_at),
        "REPORT_JS": report_js.replace("__DATA__", data_marker),
        "CSP_NONCE": nonce,
        "MODE_CLASS": "online" if online else "local",
        "MODE_LABEL": "ONLINE SCAN" if online else "LOCAL SCAN",
        "MODE_META": (
            "ONLINE SCAN // OFFLINE REPORT // STATIC EVIDENCE" if online
            else "LOCAL SCAN // OFFLINE REPORT // STATIC EVIDENCE"
        ),
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
.mode-line{display:flex;flex-wrap:wrap;align-items:center;gap:10px;margin-top:12px}
.badge.mode-online{background:#0c3a4b;color:#a5f3fc;border:1px solid #26748b}.badge.mode-local{background:#173823;color:var(--green);border:1px solid #2f6b45}
.badge.insecure{background:#571d2d;color:#fecdd3}.badge.complete{color:var(--green)}.badge.partial,.badge.unavailable{background:#571d2d;color:#fecdd3}
.kv{display:grid;gap:0}.kv-row{display:grid;grid-template-columns:minmax(120px,220px) minmax(0,1fr);gap:12px;padding:7px 0;border-bottom:1px solid #20334b;font-size:12px}
.kv-key{color:var(--muted);font:700 10px ui-monospace,monospace;letter-spacing:.08em;text-transform:uppercase;padding-top:2px}
.kv-value{color:#d5e2f0;font-family:ui-monospace,monospace;overflow-wrap:anywhere}
.coverage-list{margin:10px 0 0;padding-left:20px;color:#c6d5e5}.coverage-list li{margin:4px 0}
.hidden{display:none!important}
@media(max-width:900px){.main-grid{grid-template-columns:1fr}.sidebar{position:static;display:flex;flex-wrap:wrap;gap:4px}.sidebar h3{width:100%}}
@media(max-width:600px){.top-meta{display:none}.finding summary{flex-wrap:wrap;padding:10px 0}.finding-title{flex-basis:100%;order:3}.section{padding:15px}}
</style>
</head>
<body>
<div class="topbar">
 <div class="brand"><span class="brand-mark">⌁</span><span>PDT <span style="color:var(--cyan)">/</span> INTELLIGENCE</span></div>
 <div class="top-meta">__MODE_META__</div>
</div>
<div class="shell">
 <header class="hero">
  <div class="eyebrow">Project discovery / analysis complete</div>
  <h1>Project Intelligence Report</h1>
  <div class="root">__ROOT__</div><div class="completed">COMPLETED // __GENERATED__</div>
  <div class="mode-line"><span id="scan-mode" class="badge mode-__MODE_CLASS__">__MODE_LABEL__</span><span id="source-line" class="muted mono"></span><span id="transport-badge" class="badge insecure hidden">NO TLS</span><span id="inventory-badge" class="badge insecure hidden">INVENTORY ONLY: CONTENTS NOT ANALYZED</span></div>
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
   <a href="#overview">01 // Overview</a><a href="#source">02 // Scan source</a>
   <a href="#inventory">03 // Inventory</a>
   <a href="#vulnerabilities">04 // Vulnerabilities</a><a href="#vcs">05 // VCS / Providers</a>
   <a href="#directories">06 // Directories</a><a href="#symlinks">07 // Symlinks</a>
   <a href="#special">08 // Special entries</a><a href="#files">09 // File browser</a>
   <a href="#findings">10 // Findings</a><a href="#diagnostics">11 // Diagnostics</a>
  </aside>
  <main class="content">
   <section class="section" id="overview">
    <div class="section-head"><h2>Scan overview</h2><span class="kicker">01 / SUMMARY</span></div>
    <div class="profile-grid">
     <div class="profile-card"><h3>Scan source</h3><div id="source-summary" class="mono muted"></div></div>
     <div class="profile-card"><h3>File type distribution</h3><div id="file-types"></div></div>
     <div class="profile-card"><h3>File size distribution</h3><div id="size-buckets"></div></div>
     <div class="profile-card"><h3>Development dependency trees</h3><div id="development-dirs"></div></div>
     <div class="profile-card"><h3>Development trees by category</h3><div id="development-categories"></div></div>
     <div class="profile-card"><h3>Entry attributes</h3><div id="entry-attributes"></div></div>
     <div class="profile-card"><h3>Directory fan-out</h3><div id="fan-out"></div></div>
     <div class="profile-card"><h3>MIME types</h3><div id="mime-types"></div></div>
     <div class="profile-card"><h3>Host & native engine</h3><div id="host-os" class="mono muted"></div></div>
     <div class="profile-card"><h3>Analyzer time (seconds)</h3><div id="analyzer-budgets" class="muted"></div><div id="analyzer-time"></div></div>
     <div class="profile-card"><h3>Analyzer reads (MiB)</h3><div id="analyzer-limits" class="muted"></div><div id="analyzer-bytes"></div><details><summary>Declared content limits</summary><div id="analyzer-declared" class="mono muted"></div></details></div>
     <div class="profile-card"><h3>Vulnerability intelligence</h3><div id="vuln-summary" class="mono muted"></div></div>
     <div class="profile-card"><h3>Source control & delivery</h3><div id="vcs-summary" class="mono muted"></div></div>
    </div>
   </section>
   <section class="section" id="source">
    <div class="section-head"><h2>Scan source</h2><span class="kicker">02 / MODE AND PROVENANCE</span></div>
    <div id="source-details" class="kv"></div>
    <ul id="source-coverage" class="coverage-list hidden"></ul>
    <div id="source-notes" class="muted"></div>
   </section>
   <section class="section" id="inventory">
    <div class="section-head"><h2>Filesystem inventory</h2><span class="kicker">03 / ENTRY PROFILE</span></div>
    <div id="inventory-summary" class="muted"></div>
    <p class="muted">The JSON report contains full inventory metadata. Large tables are rendered in bounded pages.</p>
   </section>
   <section class="section" id="vulnerabilities">
    <div class="section-head"><h2>Vulnerability intelligence</h2><span class="kicker">04 / ADVISORY MATCHING</span></div>
    <div class="controls"><span id="vuln-db-state" class="badge">LOCAL DB STATUS</span><span id="vuln-online-state" class="badge">ONLINE LOOKUP OFF</span><span id="vuln-db-updated" class="muted"></span></div>
    <div id="vuln-coverage-warning" class="truncation hidden" role="status"></div>
    <div id="vuln-provenance" class="kv"></div>
    <div id="vulnerability-findings" class="finding-list"></div>
    <div id="no-vulnerabilities" class="empty hidden">No advisory matches were produced. This does not prove dependencies are vulnerability-free.</div>
   </section>
   <section class="section" id="vcs">
    <div class="section-head"><h2>VCS, hosting & delivery providers</h2><span class="kicker">05 / SOURCE PROVENANCE</span></div>
    <div id="vcs-findings" class="finding-list"></div>
    <div id="no-vcs" class="empty hidden">No local VCS, source-hosting or delivery-provider metadata was detected.</div>
   </section>
   <section class="section" id="directories">
    <div class="section-head"><h2>Directory intelligence</h2><span class="kicker">06 / STRUCTURE</span></div>
    <div class="table-wrap"><table><thead><tr><th>Directory</th><th>Depth</th><th>Files</th><th>Aggregate size</th><th>Marker / state</th></tr></thead><tbody id="directory-rows"></tbody></table></div>
   </section>
   <section class="section" id="symlinks">
    <div class="section-head"><h2>Symbolic links</h2><span class="kicker">07 / NO-FOLLOW INVENTORY</span></div>
    <div class="table-wrap"><table><thead><tr><th>Link path</th><th>Target</th><th>Lexical scope</th><th>Verification</th><th>Permissions</th><th>Hidden</th></tr></thead><tbody id="symlink-rows"></tbody></table></div>
    <div class="pagination" id="symlink-pagination"><span id="symlink-page-info">0 links</span><button id="symlink-more" class="primary" type="button">Load next page</button></div>
    <div id="no-symlinks" class="empty hidden">No symbolic links were detected.</div>
   </section>
   <section class="section" id="special">
    <div class="section-head"><h2>Special filesystem entries</h2><span class="kicker">08 / FIFO SOCKET DEVICE</span></div>
    <div class="table-wrap"><table><thead><tr><th>Path</th><th>Type</th><th>Permissions</th><th>Hidden</th><th>Size</th></tr></thead><tbody id="special-rows"></tbody></table></div>
    <div class="pagination" id="special-pagination"><span id="special-page-info">0 entries</span><button id="special-more" class="primary" type="button">Load next page</button></div>
    <div id="no-special" class="empty hidden">No FIFO, socket, device or other special entries were detected.</div>
   </section>
   <section class="section" id="files">
    <div class="section-head"><h2>File browser</h2><span class="kicker">09 / SEARCHABLE INVENTORY</span></div>
    <div class="controls"><input id="file-search" type="search" placeholder="Search paths, languages and file types" aria-label="Search file inventory">
     <select id="file-kind"><option value="">All file types</option></select><button id="file-reset" type="button">Reset</button></div>
    <div class="table-wrap"><table><thead><tr><th>Path</th><th>Size</th><th>Type</th><th>Language</th><th>Flags</th></tr></thead><tbody id="file-rows"></tbody></table></div>
    <div class="pagination"><span id="file-page-info">0 entries</span><button id="file-more" class="primary" type="button">Load next page</button></div>
   </section>
   <section class="section" id="findings">
    <div class="section-head"><h2>Analysis findings</h2><span class="kicker">10 / EVIDENCE</span></div>
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
    <div class="section-head"><h2>Diagnostics and raw metrics</h2><span class="kicker">11 / TRACE</span></div>
    <details><summary>Show scan metrics JSON</summary><pre id="raw-metrics" class="raw-json"></pre></details>
    <details><summary>Show scanner/analyzer errors</summary><pre id="raw-errors" class="raw-json"></pre></details>
    <details><summary>Active analyzers</summary><pre id="raw-analyzers" class="raw-json"></pre></details>
   </section>
  </main>
 </div>
 <div class="footer">PDT // SELF-CONTAINED OFFLINE REPORT // READ-ONLY // CONFIDENCE-AWARE</div>
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
    """Embed bounded slices plus true totals for the offline client.

    Findings are severity-ordered, inventory records path-ordered. The vulnerability and
    VCS views get their own samples and complete per-category counts, so they stay right
    when the general findings slice is truncated.
    """
    categories: Counter[str] = Counter()
    vulnerabilities: list = []
    vcs: list = []
    for finding in result.findings:
        categories[finding.category] += 1
        if finding.category == "vulnerabilities" and len(vulnerabilities) < _HTML_VIEW_SAMPLE:
            vulnerabilities.append(finding)
        elif finding.category in _VCS_CATEGORIES and len(vcs) < _HTML_VIEW_SAMPLE:
            vcs.append(finding)
    totals = {
        "findings": len(result.findings),
        "categories": dict(sorted(categories.items())),
        "files": len(result.files),
        "directories": len(result.directories),
        "symlinks": len(result.symlinks),
        "special_entries": len(result.special_entries),
        "errors": len(result.errors),
    }

    def bounded(name: str, values):
        return islice(values, HTML_MAX_EMBEDDED[name])

    stream.write('{"schema_version":' + json.dumps(REPORT_SCHEMA_VERSION) + ',"scan":')
    _write_json_value(stream, scan_summary(result.metrics), script_safe=True)
    stream.write(',"totals":')
    _write_json_value(stream, totals, script_safe=True)
    stream.write(',"embedded_limits":')
    _write_json_value(stream, HTML_MAX_EMBEDDED, script_safe=True)
    for name, items in (("vulnerability_findings", vulnerabilities), ("vcs_findings", vcs)):
        stream.write(f',"{name}":')
        _write_json_array(stream, items, lambda item: item.to_dict(), script_safe=True)
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
            "type_source": item.type_source,
            "mime_type": item.mime_type,
            "name_type": item.name_type,
            "type_mismatch": item.type_mismatch,
            "size_bucket": item.size_bucket,
            "is_hidden": item.is_hidden,
            "permissions": item.permissions,
            "attributes": item.attributes,
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
    stream.write(',"scan":')
    _write_json_value(stream, scan_summary(result.metrics))
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
    text = neutralize_controls(" ".join(str(value).splitlines()))
    return _MD_INLINE_SPECIAL.sub(
        lambda match: "\\" + match.group(0), html.escape(text, quote=False),
    )


# The same neutralization for other Markdown writers (project comparisons).
md_inline = _md


def _md_code(value: str) -> str:
    """Render text as a CommonMark code span; backslash escapes do not work inside spans."""
    text = neutralize_controls(" ".join(value.splitlines())) or " "
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
    summary = scan_summary(metrics)
    for value in (
        "# Project Discovery Report",
        "",
        f"- Root: {_md(result.root)}",
        f"- Scan mode: {summary['mode']} ({_md(_network_label(summary))})",
        f"- Source: {_md(_source_label(summary))}",
        "- Analysis: " + (
            "inventory only; no file contents were read, so no content analyzer ran"
            if execution.get("analysis_mode") == "inventory-only" else "full"
        ) + ("; resumed from an earlier interrupted scan" if execution.get("resumed") else ""),
        f"- Schema version: {REPORT_SCHEMA_VERSION}",
        f"- Completed: {result.finished_at}",
        f"- Files: {len(result.files):,}",
        f"- Directories: {max(0, len(result.directories) - 1):,}",
        f"- Symbolic links: {len(result.symlinks):,}" + (
            f" ({_md(attribute_summary(metrics['symlink_states']))})" if metrics.get("symlink_states") else ""
        ),
        f"- Special filesystem entries: {len(result.special_entries):,}",
        f"- Explicitly pruned directories: {metrics.get('pruned_directory_count', 0):,}",
        f"- Findings: {len(result.findings):,}",
        f"- Total file size: {metrics.get('total_bytes', 0):,} bytes" + (
            f" (plus {metrics['size_unknown_count']:,} file(s) of unknown size)"
            if metrics.get("size_unknown_count") else ""
        ),
        f"- Hidden entries: {metrics.get('hidden_entry_count', 0):,}",
        f"- Entry attributes: {_md(attribute_summary(metrics.get('entry_attributes') or {}))}",
        f"- Security metadata: {_md(security_metadata_summary(metrics))}",
        *([f"- Windows reparse points: {_md(attribute_summary(metrics['reparse_tags']))}"]
          if metrics.get("reparse_tags") else []),
        f"- Development/cache trees: {development_summary(metrics)}",
        f"- Development trees: {tree_mode_summary(metrics.get('development_trees'))}",
        *(f"- {label}: {_md(text)}" for label, text in aggregate_summary(metrics.get("inventory_aggregates"))),
        f"- Analysis workers: {execution.get('worker_count', 'not reported')}",
        f"- Analysis queue limit: {execution.get('max_pending_tasks', 'not reported')} pending batches",
        f"- Native CPU backend: {native.get('backend', 'not reported')}",
        f"- GPU status: {native.get('gpu_status', 'not reported')}",
        f"- GPU device: {_md(native.get('gpu_name') or 'not detected')}",
        f"- GPU byte-count dispatches: {native.get('gpu_dispatches', 0):,}",
        f"- GPU CPU fallbacks: {native.get('gpu_fallbacks', 0):,}",
        "",
    ):
        line(value)
    _write_markdown_source(line, metrics, summary)
    if metrics.get("analysis_budgets") and execution.get("analysis_mode") != "inventory-only":
        _write_markdown_budgets(line, metrics["analysis_budgets"])
    line("## File Type Distribution")
    line()
    for name, count in sorted(metrics.get("file_types", {}).items()):
        line(f"- {_md(name)}: {count:,}")
    line()
    summary_lines = type_summary(metrics)
    for label, text in summary_lines:
        line(f"- {label}: {_md(text)}")
    if summary_lines:
        line()
    if (metrics.get("type_mismatches") or {}).get("count"):
        line(f"Files whose name and content disagree (first {_MISMATCH_EXAMPLES}):")
        line()
        shown = 0
        for item in result.files:
            if not getattr(item, "type_mismatch", False):
                continue
            detail = f" ({_md(item.type_detail)})" if item.type_detail else ""
            line(f"- {_md(item.path)}: the name suggests {_md(item.name_type)}, the content is {_md(item.file_type)}{detail}")
            shown += 1
            if shown >= _MISMATCH_EXAMPLES:
                break
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
    if metrics.get("development_categories"):
        line(f"- By category: {_md(attribute_summary(metrics['development_categories'], limit=9))}")
        line(f"- By confidence: {_md(attribute_summary(metrics.get('development_confidence') or {}, limit=3))}")
        line("- Possible markers are common names (build, vendor, dist) that nothing confirmed; "
             "presets never prune them.")
        line()
    if metrics.get("pruned_by_profile"):
        line(f"- Pruned by --exclude-profile: {_md(attribute_summary(metrics['pruned_by_profile'], limit=9))}")
        line()
    line("## Largest Directories")
    line()
    largest = heapq.nlargest(
        100,
        (item for item in result.directories if item.path != "."),
        key=lambda item: (item.total_bytes, item.path.casefold(), item.path),
    )
    for item in largest:
        marker = f" [{_md(_marker_label(item))}]" if item.development_marker else ""
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
            tag = f", {_md(item.reparse_tag)}" if item.reparse_tag else ""
            line(
                f"- {_md(item.path)} -> {_md(item.target)} "
                f"({_md(_link_outcome(item))}; scope: {_md(item.target_scope)}, hidden: {item.is_hidden}{tag})"
            )
    line()
    line("## Special Filesystem Entries")
    line()
    if not result.special_entries:
        line("No special filesystem entries were detected.")
    else:
        for item in result.special_entries:
            mode = "unknown" if item.permissions is None else oct(item.permissions)
            owner = "unknown" if item.uid is None else f"{item.uid}:{item.gid}"
            device = f", device {item.device_major}:{item.device_minor}" if item.device_major is not None else ""
            tag = f", reparse tag {_md(item.reparse_tag)}" if item.reparse_tag else ""
            line(
                f"- {_md(item.path)} — {_md(item.entry_type)}{device}{tag}, permissions {mode}, "
                f"owner {owner}, hidden: {item.is_hidden}, size: {item.size_bytes:,} bytes"
            )
    _write_markdown_vulnerabilities(line, result, metrics.get("vulnerability_intelligence") or {})
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


def _network_label(summary: dict[str, Any]) -> str:
    uses = summary.get("network_access") or []
    if not uses:
        return "no network access"
    names = {
        "provider-api": "provider API", "osv.dev": "OSV.dev", "nvd": "NVD", "ghsa": "GitHub Advisory Database",
    }
    return "network used: " + ", ".join(names.get(item, item) for item in uses)


def _source_label(summary: dict[str, Any]) -> str:
    remote = summary.get("remote")
    if not remote:
        return "local directory"
    how = (
        "read through the provider API, not downloaded" if remote.get("acquisition") == "api"
        else "downloaded to a temporary directory and deleted after the scan"
    )
    return f"remote repository {remote.get('url') or ''} ({how})"


def _write_markdown_source(line, metrics: dict[str, Any], summary: dict[str, Any]) -> None:
    line("## Scan Source")
    line()
    line(f"- Mode: {summary['mode']}")
    line(f"- Network access: {_md(_network_label(summary))}")
    remote_metrics = (metrics.get("source") or {}).get("remote")
    remote = summary.get("remote")
    if not remote or not isinstance(remote_metrics, dict):
        line("- Source: local directory (the report root above)")
        line()
        return
    line(f"- Source: remote repository ({'provider API' if remote.get('acquisition') == 'api' else 'temporary download'})")
    line(f"- URL: {_md(remote.get('url') or 'not reported')}")
    line(f"- Provider: {_md(remote.get('provider') or 'unknown')}")
    line(f"- VCS: {_md(remote.get('vcs') or 'unknown')}")
    line(f"- Repository: {_md(remote.get('repository') or 'unknown')}")
    line(f"- Requested ref: {_md(remote.get('ref') or 'remote default branch')}")
    line(f"- Revision analyzed: {_md(remote.get('revision') or 'not reported')}")
    if remote.get("branch"):
        line(f"- Branch: {_md(remote['branch'])}")
    transport = remote.get("transport") or "unknown"
    if remote.get("transport_insecure"):
        line(f"- Transport: {_md(transport)} — **not encrypted**" + (
            " (a loopback API)" if remote.get("acquisition") == "api"
            else " (accepted with --allow-insecure-transport)"))
    else:
        line(f"- Transport: {_md(transport)} (encrypted)")
    if remote.get("acquired_at"):
        seconds = remote.get("acquisition_seconds")
        timing = f" ({seconds:,} s)" if isinstance(seconds, (int, float)) else ""
        line(f"- Acquired: {_md(remote['acquired_at'])}{timing}")
    if remote.get("history_complete") is False:
        line("- History: only the analyzed revision (history not imported)")
    coverage = [item for item in remote_metrics.get("coverage") or [] if isinstance(item, dict)]
    if coverage:
        line("- Coverage:")
        for item in coverage:
            state = "missing from the analyzed tree" if item.get("incomplete") else "not fetched"
            line(f"  - {_md(item.get('detail', ''))} ({state})")
    else:
        line("- Coverage: every listed path was materialized")
    details = {str(item.get("detail")) for item in coverage}
    for note in remote_metrics.get("warnings") or []:
        if str(note) not in details:
            line(f"- Note: {_md(note)}")
    line()


def _write_markdown_vulnerabilities(line, result: ScanResult, meta: dict[str, Any]) -> None:
    findings = [item for item in result.findings if item.category == "vulnerabilities"]
    confirmed = sum(1 for item in findings if item.confidence == "CONFIRMED")
    online = meta.get("online") if isinstance(meta.get("online"), dict) else None
    sources = meta.get("sources") if isinstance(meta.get("sources"), list) else (
        ["local-database"] if meta.get("enabled") else []
    )
    labels = {"local-database": "local advisory database", "osv.dev": "OSV.dev (online)"}
    line("## Vulnerability Intelligence")
    line()
    if sources:
        line("- Sources: " + ", ".join(labels.get(str(item), _md(item)) for item in sources))
    else:
        line("- Sources: none configured (use --vuln-db or --vuln-online). This is not a vulnerability-free result.")
    line(f"- Advisory matches: {confirmed:,} confirmed, {len(findings) - confirmed:,} UNKNOWN (coverage or comparison gaps)")
    line()
    line("### Local Advisory Database")
    line()
    if not meta.get("enabled"):
        line("No local advisory database was configured. This is not a vulnerability-free result.")
    else:
        if meta.get("coverage") == "skipped":
            line(f"Skipped: {_md(meta.get('skip_reason', 'not run'))}. This is not a vulnerability-free result.")
            line()
        line(f"- Local advisories available: {meta.get('advisory_count', 0):,}")
        line(f"- Local advisory snapshot imported: {_md(meta.get('last_imported_at', 'unknown'))}")
        if meta.get("snapshot_age_days") is not None:
            line(f"- Snapshot age: {meta['snapshot_age_days']:,} day(s)")
        if meta.get("last_source_name") or meta.get("last_source_sha256"):
            line(f"- Snapshot source: {_md(meta.get('last_source_name', 'unknown'))}"
                 + (f" (SHA-256 {_md_code(str(meta['last_source_sha256']))})" if meta.get("last_source_sha256") else ""))
        ecosystems = meta.get("ecosystems") if isinstance(meta.get("ecosystems"), dict) else {}
        if ecosystems:
            line("- Ecosystems: " + ", ".join(f"{_md(name)} ({count:,})" for name, count in sorted(ecosystems.items())))
        if meta.get("stale"):
            line()
            line(f"> **Stale snapshot:** {meta['snapshot_age_days']:,} days old (older than "
                 f"{meta.get('stale_after_days', 30)}). Advisories published since its import are "
                 "missing; refresh it with `pdt vuln-db import`.")
    line()
    line("### Online Advisory Lookup")
    line()
    if online is None:
        line("Not used: no advisory service was contacted (enable with --vuln-online).")
    elif online.get("coverage") == "skipped":
        line(f"Skipped: {_md(online.get('reason', 'not run'))}")
    else:
        coverage = str(online.get("coverage", "unknown"))
        line(f"- Provider: {_md(online.get('provider', 'OSV.dev'))} ({_md(public_url(online.get('endpoint')))})")
        enrichment = online.get("enrichment") or []
        line(f"- Enrichment: {_md(', '.join(enrichment)) if enrichment else 'none'}")
        line(f"- Query time: {_md(online.get('query_started_at', 'unknown'))} to "
             f"{_md(online.get('query_finished_at', 'unknown'))} ({online.get('query_seconds', 0)} s)")
        line(f"- Coverage: {_md(coverage)}")
        if coverage in {"partial", "unavailable"}:
            line(
                f"- **Incomplete:** {_md(online_gap_text(online))}. "
                "This is not a vulnerability-free result; see the UNKNOWN findings."
            )
        line(f"- Lockfiles: {online.get('lockfiles', 0):,}; unique packages: {online.get('unique_packages', 0):,}; "
             f"checked: {online.get('packages_queried', 0):,}; with advisories: {online.get('vulnerable_packages', 0):,}")
        cache = online.get("cache") or {}
        if cache.get("enabled"):
            line(f"- Cache: {cache.get('hits', 0):,} hit(s), {cache.get('misses', 0):,} miss(es), "
                 f"TTL {cache.get('ttl_seconds', 0) / 3600:g} h")
        else:
            line("- Cache: disabled")
        requests = online.get("requests") or {}
        per_host = ", ".join(f"{_md(host)} {count:,}" for host, count in (requests.get("requests_by_host") or {}).items())
        line(f"- Requests: {requests.get('requests', 0):,}" + (f" ({per_host})" if per_host else "")
             + f"; retries {requests.get('retries', 0):,}; failed {requests.get('failed_requests', 0):,}")
        for failure in online.get("failures") or []:
            line(f"- Failure: {_md(failure.get('reason'))} ({failure.get('packages', 0):,} package(s))")
        line(f"- Data sent: {_md(online.get('data_sent', 'package coordinates'))}")
    if findings:
        # Local and online matches alike: not under the online lookup's heading.
        line()
        line("### Advisory matches")
        line()
    for item in findings:
        line(f"- [{item.severity}][{item.confidence}] {_md(item.title)} ({_md(item.analyzer)})")
        line(f"  - {_md(item.detail)}")
        line("  - Evidence: " + "; ".join(_md(value) for value in item.evidence))


def _markdown_report(result: ScanResult) -> str:
    """Compatibility helper for callers/tests that explicitly need a string."""
    buffer = io.StringIO()
    _write_markdown_report(buffer, result)
    return buffer.getvalue().rstrip() + "\n"


REMOTE_BATCH_SCHEMA_VERSION = "1.0"


def write_remote_batch_summary(
    output: Path,
    targets: list[dict[str, Any]],
    *,
    started_at: str,
    finished_at: str,
    exit_code: int,
) -> list[Path]:
    """Write batch-summary.json/.md for a `pdt scan --url FILE` run.

    One entry per requested repository: credential-free URL, provider, VCS, ref, revision,
    status (completed, findings, incomplete, failed, interrupted, not_started), exit code,
    report directory and the sanitized error, so a failed or skipped repository is visible.
    """
    from collections import Counter

    from .. import __version__

    output.mkdir(parents=True, exist_ok=True)
    totals = Counter(str(item.get("status")) for item in targets)
    payload = {
        "schema_version": REMOTE_BATCH_SCHEMA_VERSION,
        "kind": "pdt-remote-batch",
        "pdt_version": __version__,
        "started_at": started_at,
        "finished_at": finished_at,
        "exit_code": exit_code,
        "target_count": len(targets),
        "totals": dict(sorted(totals.items())),
        "targets": targets,
    }
    json_path = output / "batch-summary.json"
    with json_path.open("w", encoding="utf-8", errors="backslashreplace", newline="\n") as stream:
        json.dump(payload, stream, ensure_ascii=False, indent=2)
        stream.write("\n")
    markdown_path = output / "batch-summary.md"
    with markdown_path.open("w", encoding="utf-8", errors="backslashreplace", newline="\n") as stream:
        stream.write("# PDT Remote Batch Summary\n\n")
        stream.write(f"- Started: {_md(started_at)}\n- Finished: {_md(finished_at)}\n")
        stream.write(f"- Exit code: {exit_code}\n- Repositories: {len(targets):,}\n")
        for status, count in sorted(totals.items()):
            stream.write(f"- {_md(status)}: {count:,}\n")
        stream.write(
            "\n| # | Status | Provider | Repository | VCS | Ref | Revision | Report | Error | Cleanup error |\n"
            "|---|---|---|---|---|---|---|---|---|---|\n"
        )
        for item in targets:
            cells = [
                str(item.get("index", "")), str(item.get("status", "")),
                str(item.get("provider") or ""), str(item.get("url") or ""),
                str(item.get("vcs") or ""), str(item.get("ref") or ""),
                str(item.get("revision") or ""), str(item.get("report_directory") or ""),
                str(item.get("error") or ""), str(item.get("cleanup_error") or ""),
            ]
            stream.write("| " + " | ".join(_md(cell) for cell in cells) + " |\n")
    return [json_path, markdown_path]


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

"""Host and target operating-system indicator discovery."""
from __future__ import annotations

import re
from pathlib import Path

from ...core.limits import AnalyzerLimits, limit_reached
from ...catalog.languages import is_textual_path
from ...core.source_utils import describe_error, open_verified_text
from ...models import FileRecord, Finding
from ..base import Analyzer

_TARGET_MARKERS = {
    "Windows": re.compile(r"(?i)\b(?:windows|win32|win64|_WIN32|windows-latest|windowsservercore)\b"),
    "Linux": re.compile(r"(?i)\b(?:linux|ubuntu|debian|alpine|fedora|rhel|centos|systemd|apt-get|apk add|dnf install)\b"),
    "macOS": re.compile(r"(?i)\b(?:macos|mac os x|darwin|osx|macos-latest|xcodebuild|launchd)\b"),
    "iOS": re.compile(r"(?i)\b(?:ios|iphoneos|iphonesimulator|UIKit|SwiftUI)\b"),
    "Android": re.compile(r"(?i)\b(?:android|AndroidManifest\.xml|android-latest|adb)\b"),
    "FreeBSD": re.compile(r"(?i)\bfreebsd\b"),
    "OpenBSD": re.compile(r"(?i)\bopenbsd\b"),
    "NetBSD": re.compile(r"(?i)\bnetbsd\b"),
    "Embedded/RTOS": re.compile(r"(?i)\b(?:freertos|zephyr|threadx|rt-thread|bare.?metal|yocto|buildroot)\b"),
}
_MAX_LINE_CHARS = 256 * 1024
_MAX_OS_FILE_CHARS = 64 * 1024 * 1024
_MAX_OS_EVIDENCE_LINES = 20


class OperatingSystemAnalyzer(Analyzer):
    """Infer project target platforms from manifests and source markers."""

    name = "operating-system-intelligence"
    limits = AnalyzerLimits(
        None,
        "stream",
        {"chars": _MAX_OS_FILE_CHARS, "line_chars": _MAX_LINE_CHARS, "evidence_lines": _MAX_OS_EVIDENCE_LINES},
        outcome="UNKNOWN finding when the character budget is reached",
    )
    domains = ("operating_systems", "configuration", "embedded")
    languages = ("Polyglot source/configuration/build manifests",)

    def supports(self, record: FileRecord) -> bool:
        if record.error or record.content_skipped_reason:
            return False
        name = Path(record.path).name.lower()
        return (
            is_textual_path(record.path)
            or name in {
                "dockerfile", "containerfile", "cmakelists.txt", "makefile",
                "package.swift", "go.mod", "cargo.toml", "build.gradle",
                "build.gradle.kts", "info.plist", "androidmanifest.xml",
            }
        )

    def analyze(self, path: Path, record: FileRecord) -> list[Finding]:
        # A count and the first lines per platform; every line number of a large file
        # made memory grow about five times the file size.
        line_hits: dict[str, list[int]] = {}
        line_counts: dict[str, int] = {}
        characters = 0
        budget_reached = False
        try:
            with open_verified_text(
                path, encoding="utf-8", errors="replace",
                expected_identity=record.analysis_identity,
            ) as stream:
                line_number = 1
                while True:
                    line = stream.readline(_MAX_LINE_CHARS)
                    if not line:
                        break
                    characters += len(line)
                    if characters > _MAX_OS_FILE_CHARS:
                        budget_reached = True
                        break
                    current_line = line_number
                    for os_name, pattern in _TARGET_MARKERS.items():
                        if pattern.search(line):
                            hits = line_hits.setdefault(os_name, [])
                            if hits[-1:] != [current_line]:
                                line_counts[os_name] = line_counts.get(os_name, 0) + 1
                                if len(hits) < _MAX_OS_EVIDENCE_LINES:
                                    hits.append(current_line)
                    if line.endswith(("\n", "\r")):
                        line_number += 1
        except OSError as exc:
            return [Finding(
                "platform", f"Platform analysis unavailable: {record.path}",
                describe_error(exc), confidence="UNKNOWN", severity="LOW",
                evidence=[record.path], analyzer=self.name,
            )]
        findings = []
        if budget_reached:
            limit_reached("chars", _MAX_OS_FILE_CHARS, characters)
            findings.append(Finding(
                "platform", f"Platform analysis resource limit: {record.path}",
                f"Analysis stopped after {_MAX_OS_FILE_CHARS:,} characters. This is not a clean result "
                "for the rest of the file.",
                confidence="UNKNOWN", evidence=[record.path], analyzer=self.name, severity="LOW",
            ))
        if not line_hits:
            return findings
        names = sorted(line_hits)
        evidence = [
            f"{record.path}:{line} ({name} indicator)"
            for name, lines in sorted(line_hits.items())
            for line in lines
        ]
        findings.insert(0, Finding(
            "platform",
            f"Target operating-system indicators: {record.path}",
            "Observed platform markers: " + ", ".join(f"{name} ({line_counts[name]:,} lines)" for name in names)
            + ". These are target/build-context hints; they do not identify the current host OS.",
            confidence="INFERRED", evidence=evidence[:100], analyzer=self.name,
        ))
        return findings

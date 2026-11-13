"""Read-only VCS, source-hosting, CI and cloud-delivery discovery."""
from __future__ import annotations

import configparser
import re
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

from ...core.limits import AnalyzerLimits
from ...core.source_utils import describe_error, read_text_bounded
from ...models import FileRecord, Finding
from ..base import Analyzer

_VCS_ROOTS = {
    ".git": "Git", ".hg": "Mercurial", ".svn": "Subversion",
    ".bzr": "Bazaar", "_darcs": "Darcs", ".jj": "Jujutsu",
    ".pijul": "Pijul", "CVS": "CVS",
}
# Marker files at a working-copy root. Fossil's checkout database is _FOSSIL_ on Windows,
# .fslckout elsewhere and .fos in old releases; it is never opened.
_MARKER_FILES = {
    ".git": "Git", ".hg": "Mercurial", ".svn": "Subversion",
    "_FOSSIL_": "Fossil", ".fslckout": "Fossil", ".fos": "Fossil",
}
# Git files read anywhere inside a .git directory (also below modules/ and worktrees/).
_GIT_FILES = frozenset({"config", "config.worktree", "HEAD", "packed-refs", "shallow"})
# Files read inside the other control directories, by their path inside the directory.
# A "marker" is a file every repository of that VCS has: it gives the one repository
# finding of its control directory, whether or not optional files such as hgrc exist.
# The "remotes" files name remote locations.
_CONTROL_FILES = {
    ".hg": {"requires": "marker", "hgrc": "remotes"},
    ".svn": {"wc.db": "marker", "entries": "marker", "format": "marker"},
    ".bzr": {"branch-format": "marker", "branch/branch.conf": "remotes"},
    "_darcs": {"format": "marker", "prefs/repos": "remotes"},
    # .jj/repo is a directory in a repository's first workspace and a pointer file in
    # the others. A non-colocated repository keeps its Git remotes in store/git/config.
    ".jj": {"repo/store/type": "marker", "repo": "marker",
            "repo/store/git/config": "remotes", "repo/config.toml": "remotes"},
    ".pijul": {"pristine/db": "marker", "config": "remotes", "config.toml": "remotes"},
    "CVS": {"Root": "marker"},
}
_PROVIDER_RULES = (
    ("GitHub", re.compile(r"(^|\.)github\.com$", re.I)),
    ("GitLab", re.compile(r"(^|\.)gitlab\.com$", re.I)),
    ("Bitbucket", re.compile(r"(^|\.)bitbucket\.org$", re.I)),
    ("Azure Repos", re.compile(r"(^|\.)dev\.azure\.com$|(^|\.)visualstudio\.com$", re.I)),
    ("AWS CodeCommit", re.compile(r"(^|\.)git-codecommit\.[a-z0-9-]+\.amazonaws\.com$", re.I)),
    ("Google Cloud Source Repositories", re.compile(r"(^|\.)source\.developers\.google\.com$", re.I)),
    ("SourceHut", re.compile(r"(^|\.)git\.sr\.ht$", re.I)),
)
_CI_FILES = {
    ".gitlab-ci.yml": "GitLab CI",
    "bitbucket-pipelines.yml": "Bitbucket Pipelines",
    "azure-pipelines.yml": "Azure Pipelines",
    "jenkinsfile": "Jenkins",
    ".travis.yml": "Travis CI",
    ".drone.yml": "Drone CI",
    ".woodpecker.yml": "Woodpecker CI",
    "appveyor.yml": "AppVeyor",
    "buildspec.yml": "AWS CodeBuild",
    "appspec.yml": "AWS CodeDeploy",
}
_CI_PATHS = {
    ".github/workflows": "GitHub Actions",
    ".circleci": "CircleCI",
    ".buildkite": "Buildkite",
    ".teamcity": "TeamCity",
    ".azure/pipelines": "Azure Pipelines",
}
_CLOUD_MARKERS = {
    "cdk.json": "AWS CDK",
    "samconfig.toml": "AWS SAM",
    "serverless.yml": "Serverless Framework",
    "serverless.yaml": "Serverless Framework",
    "cloudbuild.yaml": "Google Cloud Build",
    "cloudbuild.yml": "Google Cloud Build",
    "firebase.json": "Firebase",
    "app.yaml": "Google App Engine",
    "wrangler.toml": "Cloudflare Workers",
    "fly.toml": "Fly.io",
    "render.yaml": "Render",
    "vercel.json": "Vercel",
    "netlify.toml": "Netlify",
}


def _vcs_root(relative: str) -> tuple[str, str, str] | None:
    """(control directory, VCS name, path inside the directory) of the first control
    directory on ``relative``; None when the path is not inside one."""
    parts = relative.split("/")
    for index, part in enumerate(parts[:-1]):
        if part in _VCS_ROOTS:
            return part, _VCS_ROOTS[part], "/".join(parts[index + 1:])
    return None


def _is_worktree_pointer(inner: str) -> bool:
    """``worktrees/<name>/gitdir`` inside a .git directory: a linked worktree."""
    parts = inner.split("/")
    return len(parts) == 3 and parts[0] == "worktrees" and parts[2] == "gitdir"


def _remote_host(raw: str) -> tuple[str | None, str | None]:
    """Return credential-free host and scrubbed locator."""
    value = raw.strip()
    if not value:
        return None, None
    if "://" not in value and re.match(r"^[^/@\s]+@[^:/\s]+:.+", value):
        host = value.split("@", 1)[1].split(":", 1)[0].lower()
        path = value.split(":", 1)[1]
        path = path.split("?", 1)[0].split("#", 1)[0]
        return host, f"ssh://{host}/{path.lstrip('/')}"
    if value.startswith("codecommit::"):
        match = re.match(r"codecommit::([a-z0-9-]+)://(.+)", value, re.I)
        if match:
            return "codecommit.amazonaws.com", f"codecommit://{match.group(1)}/{match.group(2)}"
    try:
        parsed = urlsplit(value)
        if not parsed.hostname:
            return None, None
        host = parsed.hostname.lower()
        netloc = host + (f":{parsed.port}" if parsed.port else "")
        locator = urlunsplit((parsed.scheme or "https", netloc, parsed.path.rstrip("/"), "", ""))
        return host, locator
    except ValueError:
        return None, None


def _hosting_provider(host: str | None) -> str:
    if not host:
        return "unknown"
    for provider, pattern in _PROVIDER_RULES:
        if pattern.search(host):
            return provider
    if "bitbucket" in host:
        return "Bitbucket Data Center/Server"
    if "gitlab" in host:
        return "GitLab self-managed"
    if "github" in host:
        return "GitHub Enterprise"
    if "azure" in host:
        return "Azure DevOps Server"
    if "codecommit" in host:
        return "AWS CodeCommit"
    if "gitea" in host:
        return "Gitea"
    if "forgejo" in host or host == "codeberg.org" or host.endswith(".codeberg.org"):
        return "Forgejo"
    if "gerrit" in host:
        return "Gerrit"
    return "Self-hosted or unclassified"


def _read_text(
    path: Path,
    expected_identity: tuple[int | None, int | None, int | None, int | None, int | None] | None = None,
) -> tuple[str | None, str | None]:
    try:
        return read_text_bounded(
            path, _MAX_VCS_FILE_BYTES, encoding="utf-8", errors="replace",
            expected_identity=expected_identity,
        ), None
    except OSError as exc:
        return None, describe_error(exc)


_MAX_VCS_FILE_BYTES = 2 * 1024 * 1024


class VCSHostingAnalyzer(Analyzer):
    """Discover local VCS metadata and hosting/CI providers without invoking clients."""

    name = "vcs-hosting-intelligence"
    limits = AnalyzerLimits(
        _MAX_VCS_FILE_BYTES,
        "whole",
        outcome="An unreadable or over-budget file contributes no signals; the limit reached is recorded",
    )
    domains = ("vcs", "hosting_providers", "ci_cd", "cloud_services")
    languages = tuple(dict.fromkeys([*_VCS_ROOTS.values(), *_MARKER_FILES.values()])) + (
        "Perforce", "Git LFS", "Git Submodules",
    )

    def supports(self, record: FileRecord) -> bool:
        if record.error:
            return False
        relative = record.path.replace("\\", "/")
        relative_lower = relative.casefold()
        file_name = relative.rsplit("/", 1)[-1]
        name = file_name.lower()
        control = _vcs_root(relative)
        if control is not None:
            # Only files that a handler reads: names without one cost a read and gave nothing.
            root_name, _, inner = control
            if root_name == ".git":
                return file_name in _GIT_FILES or _is_worktree_pointer(inner)
            return inner in _CONTROL_FILES[root_name]
        if file_name in _MARKER_FILES or file_name == "HEAD":
            return True  # HEAD: a bare repository is recognized from its siblings
        if name in _CI_FILES or name in {".gitmodules", ".gitattributes"} or relative_lower == ".p4config":
            return True
        if any(relative_lower.startswith(prefix + "/") for prefix in _CI_PATHS):
            return True
        if name in _CLOUD_MARKERS:
            return True
        return False

    def analyze(self, path: Path, record: FileRecord) -> list[Finding]:
        relative = record.path.replace("\\", "/")
        file_name = relative.rsplit("/", 1)[-1]
        name = file_name.lower()
        control = _vcs_root(relative)
        if control is not None:
            return self._vcs_metadata(path, record, *control)
        if file_name == "HEAD":
            return self._bare_repository(path, relative)
        if file_name in _MARKER_FILES:
            if file_name == ".git":
                content, error = _read_text(path, record.analysis_identity)
                if error:
                    return [self._unknown(record, error)]
                if content and content.strip().startswith("gitdir:"):
                    return [Finding(
                        "vcs", f"Git metadata pointer: {record.path}",
                        "The .git file points to a separate Git metadata directory, as used by "
                        "linked worktrees and submodules. The pointer target is not followed.",
                        confidence="CONFIRMED", evidence=[record.path, "gitdir pointer present"],
                        analyzer=self.name,
                    )]
            return [Finding(
                "vcs", f"{_MARKER_FILES[file_name]} metadata marker: {record.path}",
                "A version-control metadata marker file is present; it is not opened.",
                confidence="CONFIRMED", evidence=[record.path], analyzer=self.name,
            )]
        if file_name == ".gitmodules":  # at any depth: vendored and nested repositories have their own
            return self._gitmodules(path, record)
        if file_name == ".gitattributes":
            return self._gitattributes(path, record)
        if name == ".p4config":
            return [Finding(
                "vcs", f"Perforce client configuration marker: {record.path}",
                "A Perforce client configuration file is present; connection values are not copied.",
                confidence="CONFIRMED", evidence=[record.path], analyzer=self.name,
            )]
        provider = next((value for key, value in _CI_FILES.items() if name == key), None)
        if provider is None:
            provider = next(
                (value for prefix, value in _CI_PATHS.items()
                 if relative.startswith(prefix + "/")), None
            )
        if provider:
            return [Finding(
                "ci_cd", f"CI/CD provider: {provider}",
                "A provider-specific pipeline definition is present. Pipeline jobs are not "
                "executed and credential values are not extracted.",
                confidence="CONFIRMED", evidence=[record.path], analyzer=self.name,
            )]
        if name in _CLOUD_MARKERS:
            label = _CLOUD_MARKERS[name]
            return [Finding(
                "cloud_services", f"Cloud/deployment platform marker: {label}",
                "A provider-specific deployment/application configuration file is present. "
                "No cloud API or deployment endpoint is contacted.",
                confidence="CONFIRMED", evidence=[record.path], analyzer=self.name,
            )]
        return []

    def _unknown(self, record: FileRecord, detail: str) -> Finding:
        return Finding(
            "vcs", f"VCS metadata read error: {record.path}", detail,
            confidence="UNKNOWN", evidence=[record.path], analyzer=self.name,
        )

    def _bare_repository(self, path: Path, relative: str) -> list[Finding]:
        """A HEAD file outside any control directory, next to objects/ and config."""
        directory = path.parent
        if not ((directory / "objects").is_dir() and (directory / "config").is_file()):
            return []
        location = relative.rsplit("/", 1)[0] if "/" in relative else ""
        prefix = location + "/" if location else ""
        return [Finding(
            "vcs", "Git bare repository metadata" + (f": {location}" if location else ""),
            "A Git HEAD file, objects directory and config file are present"
            + (f" in {location}" if location else " at the scan root")
            + ". This is consistent with a bare Git repository.",
            confidence="CONFIRMED",
            evidence=[prefix + "HEAD", prefix + "objects/", prefix + "config"],
            analyzer=self.name,
        )]

    def _git_config(self, record: FileRecord, text: str, label: str) -> list[Finding]:
        parser = configparser.ConfigParser(
            interpolation=None, strict=False, allow_no_value=True, inline_comment_prefixes=("#", ";"),
        )
        try:
            parser.read_string(text)
        except configparser.Error as exc:
            return [self._unknown(record, f"Invalid Git config: {exc}")]
        remotes = []
        for section in parser.sections():
            if section.lower().startswith('remote "'):
                remote_name = section[8:-1] if section.endswith('"') else section
                raw = parser.get(section, "url", fallback="")
                host, locator = _remote_host(raw)
                remotes.append((remote_name, _hosting_provider(host), host, locator))
        findings = [
            Finding(
                "hosting_providers",
                f"Git remote provider: {provider}",
                f"Remote {remote_name!r} points to host {host or 'unresolved'}; "
                f"sanitized locator: {locator or 'not resolved'}. Authentication material "
                "and URL query/fragment values are removed.",
                confidence="CONFIRMED" if host else "UNKNOWN",
                evidence=[record.path, f"remote section: {remote_name}"],
                analyzer=self.name,
            )
            for remote_name, provider, host, locator in remotes
        ]
        branches = sum(
            section.lower().startswith('branch "') for section in parser.sections()
        )
        findings.append(Finding(
            "vcs", f"{label}: {record.path}",
            f"Detected {len(remotes)} remote(s) and {branches} local branch configuration "
            "section(s). A config file alone does not prove a complete clone.",
            confidence="CONFIRMED", evidence=[record.path], analyzer=self.name,
        ))
        return findings

    def _control_marker(
        self, path: Path, record: FileRecord, root_name: str, vcs_name: str, inner: str,
    ) -> list[Finding]:
        """The one repository finding of a control directory, from its marker file."""
        relative = record.path.replace("\\", "/")
        control_directory = relative[: len(relative) - len(inner) - 1]
        working = control_directory.rsplit("/", 1)[0] if "/" in control_directory else "."
        if root_name == ".svn" and inner != "wc.db":
            # One marker per working copy: wc.db (Subversion 1.7+), else entries, else format.
            if (path.parent / "wc.db").exists() or (inner == "format" and (path.parent / "entries").exists()):
                return []
        if root_name in {".svn", "CVS"} and inner != "wc.db" and relative.count("/") >= 2:
            # CVS and Subversion before 1.7 keep a control directory in every directory of a
            # working copy: report the copy once, at its top directory.
            parent_control = path.parents[2] / root_name
            if (parent_control / inner).exists():
                return []
        detail = f"{vcs_name} repository metadata is present."
        evidence = [record.path]
        if root_name == ".jj" and inner == "repo":
            detail = ("A Jujutsu workspace whose repository is shared with another workspace; "
                      "the pointer is not followed.")
        elif root_name in {".hg", "_darcs", ".bzr", ".jj", "CVS"} or inner == "entries":
            # Small text files with the repository format or server; binary markers
            # (wc.db, Pijul's pristine database) are never opened.
            content, error = _read_text(path, record.analysis_identity)
            if error:
                return [self._unknown(record, error)]
            lines = [line.strip() for line in (content or "").splitlines() if line.strip()]
            if root_name == "CVS":
                match = re.search(r"@([^:/]+)", content or "")
                detail = "CVS working copy; server host: " + (match.group(1).lower() if match else "not identified")
            elif lines:
                label = {".hg": "requirements", "_darcs": "format", ".bzr": "format",
                         ".jj": "backend", ".svn": "format"}[root_name]
                # Subversion's entries file lists the working copy after its format number.
                shown = lines[:1] if root_name == ".svn" else lines[:20]
                evidence.append(f"{label}: " + ", ".join(shown)[:300])
        return [Finding(
            "vcs", f"{vcs_name} repository metadata: {working}",
            detail, confidence="CONFIRMED", evidence=evidence, analyzer=self.name,
        )]

    def _vcs_metadata(
        self, path: Path, record: FileRecord, root_name: str, vcs_name: str, inner: str,
    ) -> list[Finding]:
        name = Path(record.path).name.lower()
        if root_name == ".git":
            if _is_worktree_pointer(inner):
                return [Finding(
                    "vcs", f"Git linked worktree: {inner.split('/')[1]}",
                    "The repository has a linked worktree; its location is not followed.",
                    confidence="CONFIRMED", evidence=[record.path], analyzer=self.name,
                )]
        elif _CONTROL_FILES[root_name].get(inner) == "marker":
            return self._control_marker(path, record, root_name, vcs_name, inner)
        elif inner not in _CONTROL_FILES[root_name]:
            return []
        content, error = _read_text(path, record.analysis_identity)
        if error:
            return [self._unknown(record, error)]
        text = content or ""
        if root_name == ".git" and name in {"config", "config.worktree"}:
            return self._git_config(record, text, "Git repository configuration")
        if root_name == ".jj" and inner == "repo/store/git/config":
            return self._git_config(record, text, "Jujutsu Git backend configuration")
        if root_name == ".git" and name == "head" and inner.startswith("refs/"):
            # refs/remotes/origin/HEAD names the remote's default branch, not the checkout.
            stripped = text.strip()
            return [Finding(
                "vcs", f"Git remote default branch: {inner.rsplit('/', 1)[0]}",
                f"{inner} references {stripped.partition(':')[2].strip() or stripped[:64]}.",
                confidence="CONFIRMED", evidence=[record.path], analyzer=self.name,
            )] if stripped else []
        if root_name == ".git" and name == "head":
            stripped = text.strip()
            if stripped.startswith("ref:"):
                return [Finding(
                    "vcs", "Git checkout HEAD reference",
                    f"HEAD references {stripped.partition(':')[2].strip()}.",
                    confidence="CONFIRMED", evidence=[record.path], analyzer=self.name,
                )]
            if re.fullmatch(r"[0-9a-fA-F]{40,64}", stripped):
                return [Finding(
                    "vcs", "Git detached HEAD",
                    f"HEAD contains a direct object identifier ({len(stripped)} hexadecimal characters).",
                    confidence="CONFIRMED", evidence=[record.path], analyzer=self.name,
                )]
        if root_name == ".git" and name == "shallow":
            count = sum(
                bool(re.fullmatch(r"[0-9a-fA-F]{40,64}", line.strip()))
                for line in text.splitlines()
            )
            return [Finding(
                "vcs", "Git shallow clone metadata",
                f"The shallow boundary file contains {count} commit boundary record(s).",
                confidence="CONFIRMED", evidence=[record.path], analyzer=self.name,
            )]
        if root_name == ".git" and name == "packed-refs":
            refs = [
                line for line in text.splitlines()
                if line and not line.startswith(("#", "^"))
            ]
            return [Finding(
                "vcs", "Git packed reference inventory",
                f"Detected {len(refs)} packed reference record(s).",
                confidence="CONFIRMED", evidence=[record.path], analyzer=self.name,
            )]
        if root_name == ".hg" and name == "hgrc":
            parser = configparser.ConfigParser(interpolation=None, strict=False)
            try:
                parser.read_string(text)
            except configparser.Error as exc:
                return [self._unknown(record, f"Invalid Mercurial config: {exc}")]
            refs = []
            for section in parser.sections():
                if section.lower() in {"paths", "path"}:
                    for key, raw in parser.items(section):
                        host, _ = _remote_host(raw)
                        refs.append((key, host, _hosting_provider(host)))
            return [Finding(
                "vcs", "Mercurial repository configuration",
                f"Detected {len(refs)} path alias(es). Hosting providers: "
                + (", ".join(sorted({item[2] for item in refs})) or "not identified"),
                confidence="CONFIRMED",
                evidence=[record.path] + [
                    f"path: {key} -> {provider} ({host or 'unknown host'})"
                    for key, host, provider in refs
                ],
                analyzer=self.name,
            )]
        if root_name == ".bzr" and inner == "branch/branch.conf":
            providers = []
            for line in text.splitlines():
                match = re.match(r"\s*(?:parent_location|push_location)\s*=\s*(\S+)", line)
                if match:
                    host, _ = _remote_host(match.group(1))
                    providers.append(_hosting_provider(host))
            return [Finding(
                "vcs", "Bazaar branch metadata",
                "Hosting providers: " + (", ".join(sorted(set(providers))) or "not identified"),
                confidence="CONFIRMED", evidence=[record.path], analyzer=self.name,
            )]
        if root_name == "_darcs" and inner == "prefs/repos":
            providers = []
            for remote in text.splitlines():
                host, _ = _remote_host(remote)
                if host:
                    providers.append(_hosting_provider(host))
            return [Finding(
                "vcs", "Darcs repository remote metadata",
                "Remote providers: " + (", ".join(sorted(set(providers))) or "not identified"),
                confidence="CONFIRMED", evidence=[record.path], analyzer=self.name,
            )]
        if root_name == ".pijul" and inner in {"config", "config.toml"}:
            providers = []
            for line in text.splitlines():
                if re.search(r"(?i)(?:remote|url|path)\s*=", line):
                    host, _ = _remote_host(line.split("=", 1)[1].strip().strip("\"'"))
                    if host:
                        providers.append(_hosting_provider(host))
            return [Finding(
                "vcs", "Pijul repository configuration",
                "Remote providers: " + (", ".join(sorted(set(providers))) or "not identified"),
                confidence="CONFIRMED", evidence=[record.path], analyzer=self.name,
            )]
        if root_name == ".jj" and inner == "repo/config.toml":
            providers = []
            for line in text.splitlines():
                if re.search(r"(?i)(?:remote|url)\s*=", line):
                    host, _ = _remote_host(line.split("=", 1)[1].strip().strip('"\''))
                    if host:
                        providers.append(_hosting_provider(host))
            return [Finding(
                "vcs", "Jujutsu repository configuration",
                "Remote providers: " + (", ".join(sorted(set(providers))) or "not identified"),
                confidence="CONFIRMED", evidence=[record.path], analyzer=self.name,
            )]
        return []

    def _gitmodules(self, path: Path, record: FileRecord) -> list[Finding]:
        content, error = _read_text(path, record.analysis_identity)
        if error:
            return [self._unknown(record, error)]
        parser = configparser.ConfigParser(
            interpolation=None, strict=False, allow_no_value=True, inline_comment_prefixes=("#", ";"),
        )
        try:
            parser.read_string(content or "")
        except configparser.Error as exc:
            return [self._unknown(record, f"Invalid .gitmodules: {exc}")]
        entries = []
        for section in parser.sections():
            if section.lower().startswith('submodule "'):
                module = section[10:-1] if section.endswith('"') else section
                host, _ = _remote_host(parser.get(section, "url", fallback=""))
                entries.append((module, host, _hosting_provider(host)))
        return [Finding(
            "vcs", f"Git submodule declarations: {record.path}",
            f"Detected {len(entries)} submodule declaration(s).",
            confidence="CONFIRMED",
            evidence=[record.path] + [
                f"submodule: {name}; host: {host or 'not identified'}; provider: {provider}"
                for name, host, provider in entries[:100]
            ],
            analyzer=self.name,
        )]

    def _gitattributes(self, path: Path, record: FileRecord) -> list[Finding]:
        content, error = _read_text(path, record.analysis_identity)
        if error:
            return [self._unknown(record, error)]
        lines = [
            number for number, line in enumerate((content or "").splitlines(), 1)
            if "filter=lfs" in line
        ]
        if not lines:
            return []
        return [Finding(
            "vcs", f"Git LFS tracking rules: {record.path}",
            f"Detected {len(lines)} Git LFS filter rule(s).",
            confidence="CONFIRMED",
            evidence=[f"{record.path}:{line}" for line in lines[:100]],
            analyzer=self.name,
        )]

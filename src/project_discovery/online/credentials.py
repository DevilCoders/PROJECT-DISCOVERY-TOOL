"""Provider API credentials, bound to the repository host they belong to.

Lookup order for a repository on ``host``:

1. ``PDT_API_TOKEN_<HOST>`` (host upper-cased, other characters replaced by ``_``; for
   example ``PDT_API_TOKEN_GITLAB_EXAMPLE_COM``) for any provider and host;
2. the provider's standard variables, only for its public host: ``PDT_GITHUB_TOKEN``,
   ``GITHUB_TOKEN``, ``GH_TOKEN`` (github.com); ``PDT_GITLAB_TOKEN``, ``GITLAB_TOKEN``
   (gitlab.com); ``PDT_BITBUCKET_TOKEN``, ``BITBUCKET_TOKEN`` or ``BITBUCKET_USERNAME`` +
   ``BITBUCKET_APP_PASSWORD`` (bitbucket.org); ``CODEBERG_TOKEN`` (codeberg.org);
3. with ``--use-credential-helper``, ``git credential fill`` for ``https://<host>``.

A token configured for one host is never sent to another. Values are never logged,
cached or written to reports; only the source name (for example ``env:GITHUB_TOKEN``) is.
"""
from __future__ import annotations

import base64
import os
import re
import shutil
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

_HOST_VARIABLE = re.compile(r"[^A-Z0-9]")
PUBLIC_TOKEN_VARIABLES = {
    ("github", "github.com"): ("PDT_GITHUB_TOKEN", "GITHUB_TOKEN", "GH_TOKEN"),
    ("gitlab", "gitlab.com"): ("PDT_GITLAB_TOKEN", "GITLAB_TOKEN"),
    ("bitbucket", "bitbucket.org"): ("PDT_BITBUCKET_TOKEN", "BITBUCKET_TOKEN"),
    ("gitea", "codeberg.org"): ("CODEBERG_TOKEN",),
}


@dataclass(frozen=True)
class ApiCredential:
    header: str
    value: str = field(repr=False)
    source: str = ""

    def headers(self) -> dict[str, str]:
        return {self.header: self.value}


def host_token_variable(host: str) -> str:
    return "PDT_API_TOKEN_" + _HOST_VARIABLE.sub("_", host.upper())


def _token_credential(provider: str, token: str, source: str) -> ApiCredential:
    if provider == "gitea":
        return ApiCredential("Authorization", f"token {token}", source)
    return ApiCredential("Authorization", f"Bearer {token}", source)


def _basic_credential(username: str, password: str, source: str) -> ApiCredential:
    encoded = base64.b64encode(f"{username}:{password}".encode("utf-8")).decode("ascii")
    return ApiCredential("Authorization", f"Basic {encoded}", source)


def git_credential_fill(host: str, *, timeout: float = 30.0) -> tuple[str | None, str] | None:
    """Ask the user's configured Git credential helper for https://host, non-interactively.

    Runs outside any repository (so a repository's own configuration cannot select the
    helper), never prompts, and never stores or rejects credentials.
    """
    git = shutil.which("git")
    if git is None:
        return None
    workdir = Path(tempfile.gettempdir())
    environment = os.environ.copy()
    environment.update({
        "GIT_TERMINAL_PROMPT": "0",
        "GCM_INTERACTIVE": "never",
        "GIT_CEILING_DIRECTORIES": str(workdir.parent),
    })
    for name in ("GIT_DIR", "GIT_WORK_TREE", "GIT_ASKPASS", "SSH_ASKPASS"):
        environment.pop(name, None)
    kwargs = {} if os.name == "nt" else {"start_new_session": True}
    try:
        result = subprocess.run(
            [git, "-c", "credential.interactive=false", "credential", "fill"],
            input=f"protocol=https\nhost={host}\n\n".encode("utf-8"),
            capture_output=True, timeout=timeout, env=environment, cwd=workdir, check=False,
            **kwargs,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if result.returncode != 0:
        return None
    values = {}
    for line in result.stdout.decode("utf-8", errors="replace").splitlines():
        key, separator, value = line.partition("=")
        if separator:
            values[key.strip()] = value
    password = values.get("password")
    if not password:
        return None
    return values.get("username"), password


def resolve_credential(provider: str, host: str, *, use_helper: bool = False) -> ApiCredential | None:
    host = host.lower()
    variable = host_token_variable(host)
    value = os.environ.get(variable, "").strip()
    if value:
        return _token_credential(provider, value, f"env:{variable}")
    for name in PUBLIC_TOKEN_VARIABLES.get((provider, host), ()):
        value = os.environ.get(name, "").strip()
        if value:
            return _token_credential(provider, value, f"env:{name}")
    if provider == "bitbucket" and host == "bitbucket.org":
        username = os.environ.get("BITBUCKET_USERNAME", "").strip()
        password = os.environ.get("BITBUCKET_APP_PASSWORD", "").strip()
        if username and password:
            return _basic_credential(username, password, "env:BITBUCKET_USERNAME+BITBUCKET_APP_PASSWORD")
    if use_helper:
        filled = git_credential_fill(host)
        if filled is not None:
            username, password = filled
            if provider in {"bitbucket", "bitbucket-server", "gitea"} and username:
                return _basic_credential(username, password, "git-credential-helper")
            return _token_credential(provider, password, "git-credential-helper")
    return None

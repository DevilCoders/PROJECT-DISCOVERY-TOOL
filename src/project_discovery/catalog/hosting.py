"""Source-hosting providers by host name: the operator's provider map first, then the public
services' host names, then host-name heuristics for self-hosted products.

``pdt scan --provider-map FILE`` names the hosts an organization runs (GitHub Enterprise
Server, self-managed GitLab, Bitbucket Data Center, Azure DevOps Server, Gitea, Forgejo, Gogs,
Gerrit, Gitolite or SourceHut instances), so their repositories are classified by what they
are instead of guessed from their names, and a host a heuristic would misname can be marked
unclassified. The local VCS analyzer, online targets and the no-download mode's API selection
all ask :func:`classify_host`. The map is configured once per process: the CLI configures the
coordinator, and analyzer worker processes receive it when they start.

The file is TOML::

    [[provider]]
    host = "git.example.com"         # one host, or "*.example.com" for every subdomain of it
    kind = "github-enterprise"
    api_url = "https://git.example.com/api/v3"   # optional: the no-download mode's API

Nothing here touches the network.
"""
from __future__ import annotations

import hashlib
import ipaddress
import tomllib
import urllib.parse
from dataclasses import dataclass
from pathlib import Path

# The kinds a provider map can name, with the provider label reports use. "unclassified"
# names a host no heuristic may classify.
KINDS: dict[str, str | None] = {
    "github-enterprise": "GitHub Enterprise",
    "gitlab-self-managed": "GitLab self-managed",
    "bitbucket-data-center": "Bitbucket Data Center",
    "azure-devops-server": "Azure DevOps Server",
    "gitea": "Gitea",
    "forgejo": "Forgejo",
    "gogs": "Gogs",
    "gerrit": "Gerrit",
    "gitolite": "Gitolite",
    "sourcehut": "SourceHut",
    "unclassified": None,
}
MAX_MAP_BYTES = 1024 * 1024
MAX_MAP_ENTRIES = 10_000
_ENTRY_KEYS = frozenset({"host", "kind", "api_url"})
# Public services, by the domains they serve from (the domain itself and its subdomains).
_PUBLIC = (
    (("github.com",), "GitHub"),
    (("gitlab.com",), "GitLab"),
    (("bitbucket.org",), "Bitbucket"),
    (("dev.azure.com", "visualstudio.com"), "Azure Repos"),
    (("source.developers.google.com",), "Google Cloud Source Repositories"),
    (("sr.ht",), "SourceHut"),
    (("codeberg.org",), "Forgejo"),
    (("nest.pijul.com",), "Pijul Nest"),
    (("hub.darcs.net",), "Darcs Hub"),
)
# Self-hosted products, guessed from a word in the host name.
_HEURISTICS = (
    ("github", "GitHub Enterprise"), ("gitlab", "GitLab self-managed"), ("bitbucket", "Bitbucket Data Center"),
    ("azure", "Azure DevOps Server"), ("codecommit", "AWS CodeCommit"), ("gitea", "Gitea"),
    ("forgejo", "Forgejo"), ("gogs", "Gogs"), ("gerrit", "Gerrit"), ("gitolite", "Gitolite"),
)
_LABEL_CHARACTERS = frozenset("abcdefghijklmnopqrstuvwxyz0123456789-")


@dataclass(frozen=True, slots=True)
class Fingerprint:
    """One provider-map entry."""

    host: str  # lower case; "*.example.com" names the subdomains of example.com
    kind: str
    api_url: str | None = None
    entry: int = 0  # its position in the file, from 1


@dataclass(frozen=True, slots=True)
class HostProvider:
    """What a host is, and how PDT knows."""

    label: str
    source: str  # "provider-map", "built-in" (a public service's host) or "host-name" (a guess)
    kind: str | None = None  # the provider-map kind, for a configured host
    api_url: str | None = None
    entry: int = 0  # the provider-map entry, from 1


class ProviderMap:
    """The fingerprints of one provider-map file, indexed by host and by wildcard domain."""

    def __init__(self, entries: tuple[Fingerprint, ...] = (), name: str = "", sha256: str = "") -> None:
        self.entries = tuple(entries)
        self.name = name  # the file's name, never its path
        self.sha256 = sha256
        self._hosts = {entry.host: entry for entry in self.entries if not entry.host.startswith("*.")}
        self._domains = {entry.host[2:]: entry for entry in self.entries if entry.host.startswith("*.")}

    def __bool__(self) -> bool:
        return bool(self.entries)

    def __eq__(self, other: object) -> bool:
        return isinstance(other, ProviderMap) and (self.entries, self.sha256) == (other.entries, other.sha256)

    def __hash__(self) -> int:
        return hash((self.entries, self.sha256))

    def __getstate__(self) -> tuple:
        return self.entries, self.name, self.sha256

    def __setstate__(self, state: tuple) -> None:
        self.__init__(*state)

    def match(self, host: str) -> Fingerprint | None:
        """The entry naming ``host``: its own, else the most specific wildcard domain above it."""
        entry = self._hosts.get(host)
        if entry is not None or not self._domains:
            return entry
        labels = host.split(".")
        for index in range(1, len(labels)):
            entry = self._domains.get(".".join(labels[index:]))
            if entry is not None:
                return entry
        return None

    def describe(self) -> dict:
        """What reports record about the map: its file name, digest and size."""
        kinds: dict[str, int] = {}
        for entry in self.entries:
            kinds[entry.kind] = kinds.get(entry.kind, 0) + 1
        return {"file": self.name, "sha256": self.sha256, "entries": len(self.entries),
                "kinds": dict(sorted(kinds.items()))}


_configured = ProviderMap()


def configure_provider_map(provider_map: ProviderMap | None) -> None:
    """Use ``provider_map`` for every classification in this process (None: no map)."""
    global _configured
    _configured = provider_map if provider_map is not None else ProviderMap()


def configured_provider_map() -> ProviderMap:
    return _configured


def normalize_host(host: str) -> str:
    """A host as the map and the rules compare it: lower case, no brackets, IPv6 zone or
    trailing dot, an IP address in its compressed form, an internationalized name in its
    ASCII (IDNA) form."""
    value = host.strip().lower().removeprefix("[").removesuffix("]").split("%", 1)[0].rstrip(".")
    if ":" in value or value[-1:].isdigit():
        try:
            return ipaddress.ip_address(value).compressed
        except ValueError:
            pass
    if not value.isascii():
        try:
            value = value.encode("idna").decode("ascii")
        except UnicodeError:
            pass
    return value


def _under(host: str, domain: str) -> bool:
    return host == domain or host.endswith("." + domain)


def _public(host: str) -> str | None:
    """The public service a normalized host belongs to, or None."""
    for domains, label in _PUBLIC:
        if any(_under(host, domain) for domain in domains):
            return label
    labels = host.split(".")
    if len(labels) >= 4 and labels[-2:] == ["amazonaws", "com"] and labels[-4] == "git-codecommit":
        return "AWS CodeCommit"
    return None


def classify_host(host: str | None, provider_map: ProviderMap | None = None) -> HostProvider | None:
    """The provider of ``host``: the provider map's entry, a public service, or a guess from a
    word in its name; None for a host none of them names (or one the map marks unclassified)."""
    if not host:
        return None
    value = normalize_host(host)
    entry = (provider_map if provider_map is not None else _configured).match(value)
    if entry is not None:
        label = KINDS[entry.kind]
        return HostProvider(label, "provider-map", entry.kind, entry.api_url, entry.entry) if label else None
    public = _public(value)
    if public is not None:
        return HostProvider(public, "built-in")
    for word, label in _HEURISTICS:
        if word in value:
            return HostProvider(label, "host-name")
    return None


# ---------------------------------------------------------------------------------------------
# The provider-map file


def _map_host(value: object, number: int) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"entry {number}: host must be a host name such as git.example.com")
    raw = value.strip()
    wildcard = raw.startswith("*.")
    name = normalize_host(raw[2:] if wildcard else raw)
    if not wildcard:
        try:
            return ipaddress.ip_address(name).compressed
        except ValueError:
            pass
    labels = name.split(".")
    if (any(not label or len(label) > 63 or label[0] == "-" or label[-1] == "-" or not set(label) <= _LABEL_CHARACTERS
            for label in labels) or len(name) > 253 or (wildcard and len(labels) < 2)):
        raise ValueError(f"entry {number}: {raw!r} is not a host name" + (
            " (a wildcard names the subdomains of a domain with at least two labels, *.example.com)"
            if wildcard else " (give the host alone: no scheme, port, path or user)"))
    return ("*." if wildcard else "") + name


def _map_api_url(value: object, number: int) -> str:
    """An API base URL: https, or http on a loopback host; no credentials, query or fragment."""
    label = f"entry {number}: api_url"
    if not isinstance(value, str):
        raise ValueError(f"{label} must be a URL")
    parsed = urllib.parse.urlsplit(value.strip())
    try:
        host = parsed.hostname
        parsed.port  # noqa: B018 - a port out of range raises here
    except ValueError as exc:
        raise ValueError(f"{label} is not a valid URL ({exc})") from exc
    if parsed.scheme not in {"https", "http"} or not host:
        raise ValueError(f"{label} must be an https:// URL")
    if parsed.scheme == "http":
        try:
            loopback = host == "localhost" or ipaddress.ip_address(host).is_loopback
        except ValueError:
            loopback = False
        if not loopback:
            raise ValueError(f"{label} must use https:// (plain http:// is allowed only for loopback hosts)")
    if parsed.username is not None or parsed.password is not None:
        raise ValueError(f"{label} must not embed credentials; use the documented token variables")
    if parsed.query or parsed.fragment:
        raise ValueError(f"{label} must not contain a query string or fragment")
    return urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, parsed.path.rstrip("/"), "", ""))


def parse_provider_map(data: bytes, name: str = "") -> ProviderMap:
    """A provider map from the bytes of its TOML file; ValueError names what is wrong."""
    if len(data) > MAX_MAP_BYTES:
        raise ValueError(f"the file is larger than {MAX_MAP_BYTES:,} bytes")
    try:
        document = tomllib.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
        raise ValueError(f"not a TOML file: {exc}") from exc
    unknown = sorted(set(document) - {"provider"})
    if unknown:
        raise ValueError(f"unknown top-level key {unknown[0]!r}: the file holds [[provider]] tables")
    tables = document.get("provider", [])
    if not isinstance(tables, list) or not all(isinstance(table, dict) for table in tables):
        raise ValueError("provider must be a list of [[provider]] tables")
    if len(tables) > MAX_MAP_ENTRIES:
        raise ValueError(f"more than {MAX_MAP_ENTRIES:,} [[provider]] entries")
    entries: list[Fingerprint] = []
    seen: dict[str, int] = {}
    for number, table in enumerate(tables, 1):
        extra = sorted(set(table) - _ENTRY_KEYS)
        if extra:
            raise ValueError(f"entry {number}: unknown key {extra[0]!r} (keys: host, kind, api_url)")
        host = _map_host(table.get("host"), number)
        public = _public(host.removeprefix("*."))
        if public is not None:
            # A self-hosted kind on a public service's host would also send its no-download
            # requests to that kind's API path there.
            raise ValueError(f"entry {number}: {host} is {public}, a public service PDT already knows; the "
                             "provider map names self-hosted servers")
        kind = table.get("kind")
        if kind not in KINDS:
            raise ValueError(f"entry {number}: kind must be one of: {', '.join(KINDS)}")
        if host in seen:
            raise ValueError(f"entry {number}: {host} is already named by entry {seen[host]}")
        seen[host] = number
        api_url = _map_api_url(table["api_url"], number) if "api_url" in table else None
        if api_url is not None and kind in {"gerrit", "gitolite", "sourcehut", "unclassified"}:
            raise ValueError(f"entry {number}: the no-download mode has no API for kind {kind}, so api_url "
                             "does not apply")
        entries.append(Fingerprint(host, kind, api_url, number))
    return ProviderMap(tuple(entries), name, hashlib.sha256(data).hexdigest())


def load_provider_map(path: Path) -> ProviderMap:
    """The provider map in ``path`` (``pdt scan --provider-map``)."""
    with Path(path).expanduser().open("rb") as stream:
        data = stream.read(MAX_MAP_BYTES + 1)
    return parse_provider_map(data, Path(path).name)

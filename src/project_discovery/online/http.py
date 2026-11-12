"""Bounded, rate-limited HTTPS client for PDT's opt-in online services (standard library only).

* HTTPS only; plain HTTP is accepted solely for loopback hosts (local mirrors and tests).
* System proxy settings (``HTTPS_PROXY``/``HTTP_PROXY``/``NO_PROXY``) are honored, and a
  custom CA bundle can be supplied (``--ca-bundle``, ``PDT_CA_BUNDLE``, ``REQUESTS_CA_BUNDLE``,
  ``CURL_CA_BUNDLE``; ``SSL_CERT_FILE`` works through OpenSSL's defaults). Certificate
  verification is never disabled.
* Responses are size-bounded, including gzip-decoded bodies. Redirects are followed only
  within the same scheme and host, so credentials never travel to another host.
* Credentials are passed as headers that are never logged, cached or repeated in errors.
* Transient failures (timeouts, connection resets, 429/5xx) are retried with backoff,
  honoring ``Retry-After`` up to a bound; everything else raises :class:`NetworkError`,
  which callers must report as UNKNOWN coverage.
"""
from __future__ import annotations

import http.client
import ipaddress
import json
import os
import random
import socket
import ssl
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import zlib
from collections import Counter, deque
from email.utils import parsedate_to_datetime
from pathlib import Path
from typing import Any, Mapping

from .. import __version__

USER_AGENT = (
    f"PDT/{__version__} (project-discovery-tool; "
    "+https://github.com/DevilCoders/PROJECT-DISCOVERY-TOOL)"
)
DEFAULT_TIMEOUT = 30.0
DEFAULT_RETRIES = 3
MAX_RESPONSE_BYTES = 32 * 1024 * 1024
MAX_RETRY_AFTER_SECONDS = 120.0
# GitHub: after a secondary rate limit without Retry-After, wait at least a minute.
SECONDARY_RATE_LIMIT_WAIT_SECONDS = 60.0
MAX_REDIRECTS = 5
CA_BUNDLE_VARIABLES = ("PDT_CA_BUNDLE", "REQUESTS_CA_BUNDLE", "CURL_CA_BUNDLE")
_RETRY_STATUSES = frozenset({408, 425, 429, 500, 502, 503, 504})


class NetworkError(RuntimeError):
    """A request did not produce a usable answer; callers report coverage as UNKNOWN."""

    def __init__(
        self, message: str, *, kind: str = "network", status: int | None = None,
        retry_after: float | None = None, received: int | None = None,
    ) -> None:
        super().__init__(message)
        self.kind = kind
        self.status = status
        self.retry_after = retry_after
        # For "too_large": the body bytes read before refusing (0 when Content-Length
        # already showed the response too large); None when unknown.
        self.received = received


def is_loopback_host(host: str | None) -> bool:
    if not host:
        return False
    if host.lower() == "localhost":
        return True
    try:
        return ipaddress.ip_address(host.strip("[]")).is_loopback
    except ValueError:
        return False


def validate_service_url(url: str, *, label: str) -> str:
    """Return a normalized base URL; HTTPS is required except for loopback hosts."""
    parsed = urllib.parse.urlsplit(url.strip())
    if parsed.scheme not in {"https", "http"} or not parsed.hostname:
        raise ValueError(f"{label} must be an https:// URL")
    if parsed.scheme == "http" and not is_loopback_host(parsed.hostname):
        raise ValueError(f"{label} must use https:// (plain http:// is allowed only for loopback hosts)")
    if parsed.username is not None or parsed.password is not None:
        raise ValueError(f"{label} must not embed credentials; use the documented token variables")
    if parsed.query or parsed.fragment:
        raise ValueError(f"{label} must not contain a query string or fragment")
    return urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, parsed.path.rstrip("/"), "", ""))


def resolve_ca_bundle(explicit: Path | None) -> Path | None:
    if explicit is not None:
        path = Path(explicit).expanduser()
        if not path.is_file():
            raise FileNotFoundError(f"CA bundle is not a file: {path}")
        return path
    for variable in CA_BUNDLE_VARIABLES:
        value = os.environ.get(variable)
        if value:
            path = Path(value).expanduser()
            if not path.is_file():
                raise FileNotFoundError(f"{variable} does not name a file: {path}")
            return path
    return None


def build_ssl_context(ca_bundle: Path | None) -> ssl.SSLContext:
    context = ssl.create_default_context(cafile=str(ca_bundle) if ca_bundle else None)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    return context


class RateLimiter:
    """Allow at most ``max_requests`` per rolling ``per_seconds`` window (thread-safe).

    A sliding window, not a token bucket: services such as the NVD API define their limits
    over a rolling window, which a refilling bucket would exceed.
    """

    def __init__(self, max_requests: int, per_seconds: float) -> None:
        if max_requests < 1 or per_seconds <= 0:
            raise ValueError("rate limits must be positive")
        self.max_requests = max_requests
        self.per_seconds = per_seconds
        self._times: deque[float] = deque()
        self._lock = threading.Lock()
        self.waited_seconds = 0.0

    def acquire(self) -> None:
        while True:
            with self._lock:
                now = time.monotonic()
                while self._times and now - self._times[0] >= self.per_seconds:
                    self._times.popleft()
                if len(self._times) < self.max_requests:
                    self._times.append(now)
                    return
                wait = self.per_seconds - (now - self._times[0])
            wait = max(0.005, min(wait, 1.0))
            self.waited_seconds += wait
            time.sleep(wait)


class _SameHostRedirects(urllib.request.HTTPRedirectHandler):
    """Follow redirects only to the same scheme and host; refuse everything else."""

    max_redirections = MAX_REDIRECTS

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        original = urllib.parse.urlsplit(req.full_url)
        target = urllib.parse.urlsplit(urllib.parse.urljoin(req.full_url, newurl))
        if (target.scheme, target.hostname, target.port) != (original.scheme, original.hostname, original.port):
            raise NetworkError(
                f"{original.hostname} redirected to another host ({target.hostname}); refused",
                kind="redirect", status=code,
            )
        redirected = super().redirect_request(req, fp, code, msg, headers, newurl)
        if redirected is not None:
            # Same host: keep the (unredirected) credential headers.
            for name, value in req.unredirected_hdrs.items():
                redirected.add_unredirected_header(name, value)
        return redirected


def _retry_after_seconds(value: str | None) -> float | None:
    if not value:
        return None
    try:
        return max(0.0, float(value))
    except ValueError:
        pass
    try:
        moment = parsedate_to_datetime(value)
    except (TypeError, ValueError):
        return None
    return max(0.0, moment.timestamp() - time.time())


def _reset_wait_seconds(value: str | None) -> float | None:
    """Seconds until a rate-limit window resets (epoch-seconds or delta-seconds header)."""
    if not value:
        return None
    try:
        number = float(value)
    except ValueError:
        return None
    return max(0.0, number - time.time()) if number > 1_000_000_000 else max(0.0, number)


def _read_bounded(response, max_bytes: int) -> bytes:
    encoding = (response.headers.get("Content-Encoding") or "").lower()
    declared = (response.headers.get("Content-Length") or "").strip()
    if not encoding and declared.isdigit() and int(declared) > max_bytes:
        # Refuse before reading: the body is never transferred.
        raise NetworkError(
            f"response of {int(declared):,} bytes exceeds the {max_bytes:,}-byte limit",
            kind="too_large", received=0,
        )
    raw = response.read(max_bytes + 1)
    if len(raw) > max_bytes:
        raise NetworkError(
            f"response exceeds the {max_bytes:,}-byte limit", kind="too_large", received=len(raw),
        )
    if encoding in {"gzip", "x-gzip", "deflate"}:
        decoder = zlib.decompressobj(16 + zlib.MAX_WBITS if "gzip" in encoding else zlib.MAX_WBITS)
        try:
            data = decoder.decompress(raw, max_bytes + 1)
        except zlib.error as exc:
            raise NetworkError(f"invalid {encoding} response: {exc}", kind="protocol") from exc
        if len(data) > max_bytes or decoder.unconsumed_tail:
            raise NetworkError(
                f"decompressed response exceeds the {max_bytes:,}-byte limit", kind="too_large",
                received=len(raw),
            )
        return data
    return raw


class HttpClient:
    """One client per scan; thread-safe; counts requests per host for report provenance."""

    def __init__(
        self,
        *,
        ca_bundle: Path | None = None,
        timeout: float = DEFAULT_TIMEOUT,
        retries: int = DEFAULT_RETRIES,
        max_backoff: float = 30.0,
    ) -> None:
        if timeout <= 0 or timeout > 600:
            raise ValueError("network timeout must be between 0 and 600 seconds")
        self.timeout = timeout
        self.retries = max(0, retries)
        self.max_backoff = max_backoff
        self.ca_bundle = resolve_ca_bundle(ca_bundle)
        context = build_ssl_context(self.ca_bundle)
        self._opener = urllib.request.build_opener(
            urllib.request.ProxyHandler(),  # HTTPS_PROXY / HTTP_PROXY / NO_PROXY
            urllib.request.HTTPSHandler(context=context),
            _SameHostRedirects(),
        )
        self._lock = threading.Lock()
        self.requests: Counter[str] = Counter()
        self.failures: Counter[str] = Counter()
        self.retried = 0
        self.bytes_received = 0

    def _count(self, counter: Counter, host: str) -> None:
        with self._lock:
            counter[host] += 1

    def request(
        self,
        method: str,
        url: str,
        *,
        body: Any | None = None,
        headers: Mapping[str, str] | None = None,
        secret_headers: Mapping[str, str] | None = None,
        limiter: RateLimiter | None = None,
        max_bytes: int = MAX_RESPONSE_BYTES,
        accept_status: tuple[int, ...] = (200,),
        not_found_ok: bool = False,
    ) -> tuple[int, bytes, Mapping[str, str]]:
        """Send one request with retries; return (status, body, headers).

        ``secret_headers`` (tokens, API keys) are attached as unredirected headers and
        never appear in messages. With ``not_found_ok`` a 404 returns (404, b"", headers).
        """
        parsed = urllib.parse.urlsplit(url)
        host = parsed.hostname or "?"
        payload = None
        request_headers = {
            "User-Agent": USER_AGENT,
            "Accept-Encoding": "gzip",
            **(headers or {}),
        }
        if body is not None:
            payload = json.dumps(body, separators=(",", ":")).encode("utf-8")
            request_headers["Content-Type"] = "application/json"
        attempt = 0
        while True:
            attempt += 1
            request = urllib.request.Request(url, data=payload, method=method, headers=request_headers)
            for name, value in (secret_headers or {}).items():
                request.add_unredirected_header(name, value)
            if limiter is not None:
                limiter.acquire()
            self._count(self.requests, host)
            delay = None
            try:
                with self._opener.open(request, timeout=self.timeout) as response:
                    status = response.status
                    data = _read_bounded(response, max_bytes)
                    with self._lock:
                        self.bytes_received += len(data)
                    if status not in accept_status:
                        raise NetworkError(f"unexpected HTTP {status} from {host}", kind="http", status=status)
                    return status, data, response.headers
            except urllib.error.HTTPError as exc:
                status = exc.code
                error_headers = exc.headers or {}
                retry_after = _retry_after_seconds(error_headers.get("Retry-After"))
                remaining = error_headers.get("X-RateLimit-Remaining") or error_headers.get("RateLimit-Remaining")
                secondary = False
                if status in {403, 429}:
                    try:
                        secondary = b"secondary rate limit" in exc.read(4096).lower()
                    except (OSError, http.client.HTTPException):
                        secondary = False
                exc.close()
                if status == 404 and not_found_ok:
                    return 404, b"", error_headers
                # GitHub's secondary rate limit answers 403 with Retry-After, or with only its
                # message, while the primary limit still has requests left.
                rate_limited = status == 429 or (
                    status == 403 and (remaining == "0" or retry_after is not None or secondary)
                )
                if rate_limited and retry_after is None:
                    if remaining == "0" or not secondary:
                        retry_after = _reset_wait_seconds(
                            error_headers.get("X-RateLimit-Reset") or error_headers.get("RateLimit-Reset"),
                        )
                    if retry_after is None and secondary:
                        retry_after = SECONDARY_RATE_LIMIT_WAIT_SECONDS
                if (status in _RETRY_STATUSES or rate_limited) and attempt <= self.retries:
                    if retry_after is not None and retry_after > MAX_RETRY_AFTER_SECONDS:
                        self._count(self.failures, host)
                        raise NetworkError(
                            f"{host} rate limit: retry after {retry_after:.0f} s exceeds the "
                            f"{MAX_RETRY_AFTER_SECONDS:.0f} s bound",
                            kind="rate_limit", status=status, retry_after=retry_after,
                        ) from None
                    delay = retry_after if retry_after is not None else self._backoff(attempt)
                else:
                    self._count(self.failures, host)
                    kind = "rate_limit" if rate_limited else "http"
                    raise NetworkError(
                        f"HTTP {status} from {host}{parsed.path}", kind=kind, status=status,
                        retry_after=retry_after,
                    ) from None
            except NetworkError:
                self._count(self.failures, host)
                raise
            except ssl.SSLCertVerificationError as exc:
                self._count(self.failures, host)
                raise NetworkError(
                    f"TLS certificate verification failed for {host}: {exc.verify_message}. "
                    "Use --ca-bundle for a private CA; verification is never disabled.",
                    kind="tls",
                ) from None
            except (urllib.error.URLError, TimeoutError, socket.timeout, ConnectionError,
                    http.client.HTTPException, ssl.SSLError, OSError) as exc:
                reason = getattr(exc, "reason", exc)
                if isinstance(reason, ssl.SSLCertVerificationError):
                    self._count(self.failures, host)
                    raise NetworkError(
                        f"TLS certificate verification failed for {host}: {reason.verify_message}. "
                        "Use --ca-bundle for a private CA; verification is never disabled.",
                        kind="tls",
                    ) from None
                kind = "timeout" if isinstance(reason, (TimeoutError, socket.timeout)) else "network"
                if attempt <= self.retries:
                    delay = self._backoff(attempt)
                else:
                    self._count(self.failures, host)
                    raise NetworkError(
                        f"{'timed out' if kind == 'timeout' else 'could not connect to'} {host}: "
                        f"{type(reason).__name__}: {reason}",
                        kind=kind,
                    ) from None
            with self._lock:
                self.retried += 1
            time.sleep(delay)

    def _backoff(self, attempt: int) -> float:
        return min(self.max_backoff, (2 ** (attempt - 1)) * 0.5) * (0.75 + random.random() / 2)

    def get_json(self, url: str, **kwargs) -> tuple[int, Any]:
        status, data, _ = self.request("GET", url, **kwargs)
        return status, _decode_json(data, url) if status != 404 else None

    def post_json(self, url: str, body: Any, **kwargs) -> tuple[int, Any]:
        status, data, _ = self.request("POST", url, body=body, **kwargs)
        return status, _decode_json(data, url)

    def statistics(self) -> dict[str, Any]:
        with self._lock:
            return {
                "requests": sum(self.requests.values()),
                "requests_by_host": dict(sorted(self.requests.items())),
                "failed_requests": sum(self.failures.values()),
                "retries": self.retried,
                "bytes_received": self.bytes_received,
            }


def _decode_json(data: bytes, url: str) -> Any:
    try:
        return json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
        host = urllib.parse.urlsplit(url).hostname
        raise NetworkError(f"{host} returned a response that is not valid JSON", kind="protocol") from exc

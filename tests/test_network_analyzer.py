from pathlib import Path

from project_discovery.analyzers.network_analyzer import NetworkIndicatorAnalyzer
from project_discovery.models import FileRecord


def _scan(tmp_path: Path, source: str):
    path = tmp_path / "network.py"
    path.write_text(source, encoding="utf-8")
    record = FileRecord(
        "src/network.py", path.stat().st_size, ".py", "Python", file_type="text"
    )
    return NetworkIndicatorAnalyzer().analyze(path, record)


def test_ipv4_ipv6_cidr_ports_uri_and_subdomain_detection(tmp_path: Path):
    findings = _scan(
        tmp_path,
        'IPV4 = "192.0.2.10"\n'
        'IPV6 = "2001:db8::1"\n'
        'NETWORK = "10.0.0.0/8"\n'
        'PORT = 5432\n'
        'URL = "https://admin:super-secret@api.dev.example.com:8443/v1/users?token=hidden"\n',
    )
    titles = [item.title for item in findings]
    assert any("IPv4 address" in title for title in titles)
    assert any("IPv6 address" in title for title in titles)
    assert any("CIDR" in title for title in titles)
    assert any("Port indicators" in title for title in titles)
    assert any("URL/URI indicators" in title for title in titles)
    domain = next(item for item in findings if "Hostname and domain" in item.title)
    assert "api.dev.example.com" in repr(domain.to_dict())
    assert all("super-secret" not in repr(item.to_dict()) for item in findings)
    assert all("token=hidden" not in repr(item.to_dict()) for item in findings)


def test_invalid_addresses_are_not_reported_as_valid_literals(tmp_path: Path):
    findings = _scan(tmp_path, 'IP = "999.999.999.999"\nPORT = 99999\n')
    assert not any("IPv4 address" in item.title for item in findings)
    assert not any("Port indicators" in item.title for item in findings)


def test_network_analyzer_uses_bounded_line_chunks(tmp_path: Path):
    source = "x = 1\n" + ("a" * (300 * 1024)) + '\nHOST = "198.51.100.5"\n'
    findings = _scan(tmp_path, source)
    assert any("198.51.100.5" in repr(item.evidence) for item in findings)


def test_bare_container_and_service_ports_are_detected(tmp_path: Path):
    findings = _scan(
        tmp_path,
        "EXPOSE 80\nlisten 443 ssl\nendpoint = \"192.0.2.20:8081\"\n",
    )
    ports = next(item for item in findings if "Port indicators" in item.title)
    for value in ("80", "443", "8081"):
        assert value in ports.detail


def test_ipv4_mapped_ipv6_literal_is_recognized(tmp_path: Path):
    findings = _scan(tmp_path, 'HOST = "::ffff:192.0.2.128"\n')
    ipv6 = next(item for item in findings if "IPv6 address" in item.title)
    assert "::ffff:c000:280" in repr(ipv6.evidence)

def test_network_analyzer_reports_oversized_and_growing_sources_as_unknown(tmp_path: Path, monkeypatch):
    import project_discovery.analyzers.network_analyzer as module

    path = tmp_path / "large-network.py"
    path.write_text('HOST = "192.0.2.1"\n' * 10, encoding="utf-8")
    monkeypatch.setattr(module, "_MAX_NETWORK_FILE_BYTES", 24)
    record = FileRecord(path.name, 1, ".py", "Python", file_type="text")
    findings = NetworkIndicatorAnalyzer().analyze(path, record)
    assert any(item.confidence == "UNKNOWN" and "budget reached" in item.title for item in findings)


def test_network_analyzer_caps_unique_indicator_cardinality(tmp_path: Path, monkeypatch):
    import project_discovery.analyzers.network_analyzer as module

    monkeypatch.setattr(module, "_MAX_NETWORK_INDICATORS", 1)
    findings = _scan(tmp_path, 'HOSTS = "192.0.2.1 198.51.100.2"\n')
    assert any(item.confidence == "UNKNOWN" and "budget reached" in item.title for item in findings)

from pathlib import Path

from project_discovery.analyzers.delivery.coverage_reports import CoverageArtifactAnalyzer
from project_discovery.models import FileRecord


def _scan(tmp_path: Path, name: str, content: str):
    path = tmp_path / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    record = FileRecord(name, path.stat().st_size, path.suffix.lower(), "Coverage")
    analyzer = CoverageArtifactAnalyzer()
    assert analyzer.supports(record)
    return analyzer.analyze(path, record)


def test_lcov_line_and_branch_counters(tmp_path: Path):
    findings = _scan(
        tmp_path, "lcov.info",
        "TN:\nSF:src/app.ts\nDA:1,1\nLF:10\nLH:7\nBRF:4\nBRH:2\nend_of_record\n",
    )
    assert "LCOV" in findings[0].title
    assert "lines: 7/10 (70.0%)" in findings[0].detail
    assert "branches: 2/4 (50.0%)" in findings[0].detail


def test_cobertura_and_jacoco_xml_reports(tmp_path: Path):
    cobertura = _scan(
        tmp_path, "coverage.xml",
        '<coverage lines-valid="20" lines-covered="15" branches-valid="8" branches-covered="4"/>',
    )
    jacoco = _scan(
        tmp_path, "jacoco.xml",
        '<report><counter type="LINE" missed="3" covered="7"/>'
        '<counter type="BRANCH" missed="2" covered="2"/></report>',
    )
    assert "lines: 15/20" in cobertura[0].detail
    assert "lines: 7/10" in jacoco[0].detail
    assert "branches: 2/4" in jacoco[0].detail


def test_clover_and_opencover_reports(tmp_path: Path):
    clover = _scan(
        tmp_path, "clover.xml",
        '<coverage><project><metrics statements="10" coveredstatements="8" '
        'conditionals="4" coveredconditionals="3"/></project></coverage>',
    )
    opencover = _scan(
        tmp_path, "opencover.xml",
        '<CoverageSession><Summary numSequencePoints="12" visitedSequencePoints="9" '
        'numBranchPoints="4" visitedBranchPoints="2"/></CoverageSession>',
    )
    assert "statements: 8/10" in clover[0].detail
    assert "lines: 9/12" in opencover[0].detail
    assert "branches: 2/4" in opencover[0].detail


def test_istanbul_and_go_cover_formats(tmp_path: Path):
    istanbul = _scan(
        tmp_path, "coverage-final.json",
        '{"src/app.js":{"s":{"0":1,"1":0},"f":{"0":1},"b":{"0":[1,0]}}}',
    )
    go = _scan(
        tmp_path, "coverage.out",
        "mode: atomic\nexample.com/app/main.go:10.1,12.2 2 1\n"
        "example.com/app/main.go:14.1,18.2 3 0\n",
    )
    assert "statements: 1/2" in istanbul[0].detail
    assert "functions: 1/1" in istanbul[0].detail
    assert "branches: 1/2" in istanbul[0].detail
    assert "statements: 2/5" in go[0].detail


def test_coverage_summary_json_and_malformed_input(tmp_path: Path):
    summary = _scan(
        tmp_path, "coverage-summary.json",
        '{"total":{"lines":{"total":100,"covered":80,"pct":80}}}',
    )
    broken = _scan(tmp_path, "coverage.json", "{broken")
    assert "lines: 80/100" in summary[0].detail
    assert summary[0].confidence == "CONFIRMED"
    assert "does not verify the test run" in summary[0].detail
    assert broken[0].confidence == "UNKNOWN"

def test_coverage_artifact_reports_oversized_and_growing_source_as_unknown(tmp_path: Path, monkeypatch):
    import project_discovery.analyzers.delivery.coverage_reports as module

    path = tmp_path / "coverage.out"
    path.write_text("mode: atomic\nfile.go:1.1,2.2 2 1\n", encoding="utf-8")
    monkeypatch.setattr(module, "_MAX_COVERAGE_ARTIFACT_BYTES", 8)
    record = FileRecord(path.name, 1, ".out", "Coverage")
    findings = CoverageArtifactAnalyzer().analyze(path, record)
    assert findings[0].confidence == "UNKNOWN"
    assert "grew beyond" in findings[0].detail


def test_coverage_reports_growth_as_unknown_and_redacts_parser_errors(tmp_path: Path, monkeypatch):
    from project_discovery.analyzers.delivery import coverage_reports as coverage_analyzer

    path = tmp_path / "coverage.json"
    path.write_text('{"total":{"lines":{"total":10,"covered":8}}}', encoding="utf-8")
    record = FileRecord(path.name, 1, ".json", "JSON")
    monkeypatch.setattr(
        coverage_analyzer, "_MAX_COVERAGE_ARTIFACT_BYTES", 8
    )
    budget = CoverageArtifactAnalyzer().analyze(path, record)
    assert len(budget) == 1 and budget[0].confidence == "UNKNOWN"
    assert "resource limit" in budget[0].title.lower()

    monkeypatch.setattr(
        coverage_analyzer, "_MAX_COVERAGE_ARTIFACT_BYTES", 1024
    )
    monkeypatch.setattr(
        coverage_analyzer.json, "loads",
        lambda _: (_ for _ in ()).throw(ValueError('api_key="coverage-parser-secret"')),
    )
    error = CoverageArtifactAnalyzer().analyze(path, record)
    assert error[0].confidence == "UNKNOWN"
    assert "coverage-parser-secret" not in error[0].detail

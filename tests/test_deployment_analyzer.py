import json
from pathlib import Path


from project_discovery.analyzers.deployment_analyzer import DeploymentIntelligenceAnalyzer
from project_discovery.models import FileRecord


def _record(path: Path, relative: str) -> FileRecord:
    return FileRecord(relative, path.stat().st_size, path.suffix.lower(), "Configuration")


def test_dockerfile_inventory_and_root_user_warning(tmp_path: Path):
    path = tmp_path / "Dockerfile"
    path.write_text(
        "FROM python:latest\nWORKDIR /app\nCOPY . .\nRUN pip install -r requirements.txt\n"
        "EXPOSE 8000\nUSER root\nCMD [\"python\", \"app.py\"]\n",
        encoding="utf-8",
    )
    findings = DeploymentIntelligenceAnalyzer().analyze(path, _record(path, "Dockerfile"))
    assert any(item.category == "containers" for item in findings)
    assert any("Mutable container base image" in item.title for item in findings)
    assert any("runs as root" in item.title for item in findings)


def test_compose_service_inventory_and_privileged_warning(tmp_path: Path):
    path = tmp_path / "compose.yaml"
    path.write_text(
        "services:\n  api:\n    image: example/api:1.0\n    ports:\n      - \"8080:80\"\n"
        "    privileged: true\n  db:\n    image: postgres:16\n",
        encoding="utf-8",
    )
    findings = DeploymentIntelligenceAnalyzer().analyze(
        path, _record(path, "compose.yaml")
    )
    assert any(item.category == "containers" for item in findings)
    assert any("privileged" in item.title for item in findings)


def test_kubernetes_resource_and_pod_security_findings(tmp_path: Path):
    path = tmp_path / "deployment.yaml"
    path.write_text(
        "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: api\n"
        "spec:\n  template:\n    spec:\n      hostNetwork: true\n"
        "      containers:\n        - name: api\n          image: example/api:v1\n"
        "          securityContext:\n            privileged: true\n",
        encoding="utf-8",
    )
    findings = DeploymentIntelligenceAnalyzer().analyze(
        path, _record(path, "k8s/deployment.yaml")
    )
    assert any(item.title == "Kubernetes Deployment: api" for item in findings)
    assert any("privileged container" in item.title for item in findings)
    assert any("host network" in item.title for item in findings)


def test_github_actions_workflow_inventory_and_permissions(tmp_path: Path):
    path = tmp_path / "ci.yml"
    path.write_text(
        "name: CI\non: pull_request_target\npermissions: write-all\njobs:\n"
        "  test:\n    runs-on: ubuntu-latest\n    steps:\n"
        "      - name: Checkout\n        uses: actions/checkout@v4\n"
        "      - name: Test\n        run: pytest\n",
        encoding="utf-8",
    )
    findings = DeploymentIntelligenceAnalyzer().analyze(
        path, _record(path, ".github/workflows/ci.yml")
    )
    assert any(item.category == "ci_cd" for item in findings)
    assert any("Broad CI workflow permissions" in item.title for item in findings)
    assert any("pull_request_target" in item.title for item in findings)
    assert any("Mutable CI action reference" in item.title for item in findings)
    assert "pytest" not in repr([item.to_dict() for item in findings])


def test_terraform_resource_inventory_and_risky_public_ingress(tmp_path: Path):
    path = tmp_path / "main.tf"
    path.write_text(
        'resource "aws_security_group" "web" {\n'
        '  ingress {\n    cidr_blocks = ["0.0.0.0/0"]\n  }\n}\n',
        encoding="utf-8",
    )
    findings = DeploymentIntelligenceAnalyzer().analyze(path, _record(path, "main.tf"))
    assert any("Terraform declarations" in item.title for item in findings)
    assert any("public_ingress" in item.title for item in findings)


def test_cloudformation_json_and_malformed_yaml(tmp_path: Path):
    path = tmp_path / "template.json"
    path.write_text(json.dumps({
        "Resources": {"bucket": {"Type": "AWS::S3::Bucket"}}
    }), encoding="utf-8")
    findings = DeploymentIntelligenceAnalyzer().analyze(
        path, _record(path, "template.json")
    )
    assert findings[0].category == "infrastructure"
    assert "1 resource declaration" in findings[0].detail

    malformed = tmp_path / "bad.yaml"
    malformed.write_text("kind: [unterminated", encoding="utf-8")
    failure = DeploymentIntelligenceAnalyzer().analyze(
        malformed, _record(malformed, "bad.yaml")
    )
    assert failure[0].confidence == "UNKNOWN"


def test_missing_yaml_dependency_is_unknown(tmp_path: Path, monkeypatch):
    path = tmp_path / "compose.yaml"
    path.write_text("services: {}", encoding="utf-8")
    analyzer = DeploymentIntelligenceAnalyzer()
    record = _record(path, "compose.yaml")
    import builtins
    original = builtins.__import__

    def blocked(name, *args, **kwargs):
        if name == "yaml":
            raise ImportError("missing")
        return original(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", blocked)
    findings = analyzer.analyze(path, record)
    assert findings[0].confidence == "UNKNOWN"
    assert "infrastructure extra" in findings[0].detail


def test_ansible_playbook_list_is_inventoried(tmp_path: Path):
    path = tmp_path / "site.yml"
    path.write_text(
        "- hosts: all\n  tasks:\n    - name: install package\n      package:\n        name: nginx\n",
        encoding="utf-8",
    )
    findings = DeploymentIntelligenceAnalyzer().analyze(
        path, _record(path, "ansible/playbooks/site.yml")
    )
    assert any(item.title.startswith("Ansible playbook:") for item in findings)

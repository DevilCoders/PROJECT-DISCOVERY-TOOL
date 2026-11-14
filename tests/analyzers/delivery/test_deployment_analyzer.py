import json
from pathlib import Path

from project_discovery.analyzers.delivery.deployment import DeploymentIntelligenceAnalyzer
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


def _deploy(tmp_path: Path, relative: str, content: str):
    path = tmp_path / relative.replace("/", "_")
    path.write_text(content, encoding="utf-8")
    return DeploymentIntelligenceAnalyzer().analyze(path, _record(path, relative))


def test_pods_cronjobs_and_every_container_are_checked(tmp_path: Path):
    # Regressions: a bare Pod and a CronJob showed 0 containers and were never checked, and a
    # later unprivileged container hid a privileged one.
    pod = _deploy(tmp_path, "pod.yaml", (
        "apiVersion: v1\nkind: Pod\nmetadata: {name: shell}\nspec:\n  hostNetwork: true\n"
        "  containers:\n  - name: c\n    image: busybox:1.36\n    securityContext: {privileged: true}\n"
    ))
    titles = [item.title for item in pod]
    assert "Kubernetes Pod: shell" in titles and "Potential Kubernetes risk: privileged container" in titles
    assert "1 container declaration(s)" in pod[0].detail
    cron = _deploy(tmp_path, "cron.yaml", (
        "apiVersion: batch/v1\nkind: CronJob\nmetadata: {name: backup}\nspec:\n  schedule: '0 1 * * *'\n"
        "  jobTemplate:\n    spec:\n      template:\n        spec:\n          containers:\n"
        "          - name: b\n            image: backup:2.1\n            securityContext: {allowPrivilegeEscalation: true}\n"
    ))
    assert "Potential Kubernetes risk: privilege escalation allowed" in [item.title for item in cron]
    two = _deploy(tmp_path, "web.yaml", (
        "apiVersion: apps/v1\nkind: Deployment\nmetadata: {name: web}\nspec:\n  template:\n    spec:\n"
        "      containers:\n      - {name: agent, image: agent:1, securityContext: {privileged: true}}\n"
        "      - {name: app, image: app:1, securityContext: {privileged: false}}\n"
    ))
    assert "Potential Kubernetes risk: privileged container" in [item.title for item in two]


def test_workflow_triggers_permissions_and_other_ci_providers(tmp_path: Path):
    for on in ("[push, pull_request_target]", "\n  pull_request_target:\n    types: [opened]"):
        findings = _deploy(tmp_path, ".github/workflows/ci.yml", f"on: {on}\njobs:\n  test:\n    runs-on: ubuntu-latest\n    steps: []\n")
        assert any("pull_request_target" in item.title for item in findings), on
    job_scope = _deploy(tmp_path, ".github/workflows/rel.yml", (
        "on: push\njobs:\n  release:\n    permissions: {contents: write}\n    runs-on: ubuntu-latest\n    steps: []\n"
    ))
    assert any(item.title.startswith("Broad CI workflow permissions") for item in job_scope)
    gitlab = _deploy(tmp_path, ".gitlab-ci.yml", (
        "stages: [build, test]\nvariables: {A: b}\n.template: {script: [x]}\n"
        "build: {stage: build, script: [make]}\ntest: {stage: test, script: [make test]}\n"
    ))
    assert "Detected 2 job(s)" in gitlab[0].detail
    azure = _deploy(tmp_path, "azure-pipelines.yml", (
        "stages:\n- stage: Build\n  jobs:\n  - job: compile\n    steps: [{script: make}]\n"
        "  - deployment: ship\n    environment: prod\n"
    ))
    assert "Detected 2 job(s)" in azure[0].detail


def test_dockerfile_flags_stages_scratch_and_continuations(tmp_path: Path):
    findings = _deploy(tmp_path, "Dockerfile", (
        "FROM --platform=$BUILDPLATFORM golang:1.22 AS build\nRUN apt-get update \\\n    && apt-get install -y git\n"
        "FROM build AS test\nFROM scratch\nCOPY --from=build /out /\n"
    ))
    recipe = findings[0]
    assert "Base images: golang:1.22, build, scratch" in recipe.detail
    assert "&&" not in repr(recipe.evidence)
    assert not any(item.title.startswith("Mutable container base image") for item in findings)


def test_only_lists_of_plays_are_ansible_playbooks(tmp_path: Path):
    filebeat = _deploy(tmp_path, "filebeat.yml", "output.elasticsearch:\n  hosts: ['es:9200']\n")
    assert not any("Ansible" in item.title for item in filebeat)
    playbook = _deploy(tmp_path, "site.yml", "- hosts: web\n  tasks:\n  - name: ping\n    ping: {}\n")
    assert any(item.title == "Ansible playbook: site.yml" for item in playbook)


def test_ipv6_any_is_public_ingress(tmp_path: Path):
    findings = _deploy(tmp_path, "sg.tf", 'resource "aws_security_group" "web" {\n  ipv6_cidr_blocks = ["::/0"]\n}\n')
    assert any(item.title == "Potential Terraform risk: public_ingress" for item in findings)

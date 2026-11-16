"""The provenance graph: remotes, submodules, package registries, CI workflows, container images
and deployment targets correlated by the code index's provenance pass."""
from __future__ import annotations

import json
from pathlib import Path

from project_discovery.analyzers.delivery.deployment import DeploymentIntelligenceAnalyzer, image_registry
from project_discovery.cli import run_scan
from project_discovery.intelligence.facts import collecting_facts
from project_discovery.models import FileRecord

DIGEST = "sha256:" + "a" * 64
SHA = "0123456789abcdef0123456789abcdef01234567"
PROJECT = {
    ".git/config": '[remote "origin"]\n\turl = https://github.com/acme/app.git\n'
                   '[remote "mirror"]\n\turl = http://git.acme.example/app.git\n',
    ".gitmodules": '[submodule "vendor/lib"]\n\tpath = vendor/lib\n\turl = git://git.example.org/lib.git\n',
    "package-lock.json": json.dumps({"lockfileVersion": 3, "packages": {
        "": {"name": "app"},
        "node_modules/left-pad": {"version": "1.3.0", "resolved": "https://registry.npmjs.org/left-pad/-/l-1.3.0.tgz"},
        "node_modules/@acme/internal": {"version": "2.0.0", "resolved": "https://npm.acme.example/@acme/i-2.0.0.tgz"},
    }}),
    ".github/workflows/release.yml": (
        "on: push\npermissions:\n  contents: read\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n"
        "      - uses: actions/checkout@v4\n"
        f"      - uses: docker/build-push-action@{SHA}\n"
        "      - run: |\n          npm publish\n          kubectl apply -f k8s/\n"),
    ".circleci/config.yml": "version: 2.1\njobs: {}\n",
    "Dockerfile": f"FROM node:20 AS build\nRUN npm ci\nFROM gcr.io/distroless/nodejs20@{DIGEST}\nCOPY --from=build /app /app\n",
    "k8s/deployment.yaml": (
        "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: app\nspec:\n  template:\n    spec:\n"
        "      containers:\n        - name: app\n          image: registry.acme.example:5000/app:1.2\n"),
    "infra/main.tf": 'provider "aws" {\n  region = "eu-west-1"\n}\n\nresource "google_storage_bucket" "b" {\n  name = "x"\n}\n',
    "vercel.json": "{}\n",
}


def _write(root: Path, files: dict[str, str]) -> None:
    for name, content in files.items():
        target = root / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")


def _facts(tmp_path: Path, relative: str, content: str) -> list[tuple]:
    path = tmp_path / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    record = FileRecord(relative, path.stat().st_size, path.suffix.lower(), "YAML")
    analyzer = DeploymentIntelligenceAnalyzer()
    assert analyzer.supports(record), relative
    with collecting_facts() as facts:
        analyzer.analyze(path, record)
    return [(kind, name, json.loads(detail)) for kind, name, detail in facts.facts]


def test_ci_workflows_name_their_actions_publish_and_deploy_steps(tmp_path: Path):
    facts = _facts(tmp_path, ".github/workflows/release.yml", PROJECT[".github/workflows/release.yml"])
    workflow = next(detail for kind, _, detail in facts if kind == "ci_workflow")
    assert workflow["actions"] == ["actions/checkout@v4", f"docker/build-push-action@{SHA}"]
    assert (workflow["unpinned_actions"], workflow["write_permissions"]) == (1, False)
    assert workflow["publishes"] == ["container registry", "npm"] and workflow["deploys"] == ["Kubernetes"]
    gitlab = _facts(tmp_path, ".gitlab-ci.yml",
                    "deploy:\n  stage: deploy\n  script:\n    - helm upgrade --install app ./chart\n    - twine upload dist/*\n")
    assert [(name, detail["publishes"], detail["deploys"]) for kind, name, detail in gitlab if kind == "ci_workflow"] == [
        ("GitLab CI", ["PyPI"], ["Kubernetes (Helm)"])]
    azure = _facts(tmp_path, "azure-pipelines.yml", (
        "stages:\n  - stage: release\n    jobs:\n      - deployment: web\n        strategy:\n          runOnce:\n"
        "            deploy:\n              steps:\n                - task: AzureWebApp@1\n"
        "                - task: Docker@2\n                  inputs:\n                    command: push\n"))
    assert [(detail["publishes"], detail["deploys"]) for kind, _, detail in azure if kind == "ci_workflow"] == [
        (["container registry"], ["Azure App Service"])]


def test_container_images_name_their_registries():
    assert image_registry("nginx:1.25") == "docker.io"
    assert image_registry("library/nginx") == "docker.io"
    assert image_registry("ghcr.io/acme/app:1") == "ghcr.io"
    assert image_registry("registry.acme.example:5000/app") == "registry.acme.example:5000"
    assert image_registry("localhost/app") == "localhost"
    assert image_registry("123456789012.dkr.ecr.eu-west-1.amazonaws.com/app") == (
        "123456789012.dkr.ecr.eu-west-1.amazonaws.com")
    assert image_registry("${REGISTRY}/app") == "" and image_registry("") == ""


def test_the_scan_correlates_every_source_into_one_graph(tmp_path: Path):
    project = tmp_path / "project"
    _write(project, PROJECT)
    output = tmp_path / "out"
    assert run_scan(project, output, {"json"}, 1, quiet=True) == 0
    report = json.loads((output / "discovery-report.json").read_text(encoding="utf-8"))
    graph = report["metrics"]["code_index"]["provenance"]
    nodes = {node["id"]: node for node in graph["nodes"]}
    edges = {(edge["from"], edge["to"], edge["relation"]): edge for edge in graph["edges"]}
    project_id = "project:this project"
    assert edges[(project_id, "source_host:github.com", "hosted-at")]["remote"] == ["origin"]
    assert nodes["source_host:github.com"]["provider"] == "GitHub"
    assert (project_id, "source_host:git.example.org", "includes-submodule-from") in edges
    npm = edges[(project_id, "package_registry:registry.npmjs.org", "resolves-packages-from")]
    assert (npm["ecosystem"], npm["packages"]) == (["npm"], 1)
    workflow = "ci_workflow:.github/workflows/release.yml"
    assert (project_id, workflow, "built-by") in edges and (workflow, "ci_system:GitHub Actions", "runs-on") in edges
    assert edges[(workflow, "ci_action:actions/checkout", "uses")]["ref"] == ["v4"]
    assert edges[(workflow, "ci_action:docker/build-push-action", "uses")]["pinned"] == [True]
    assert (workflow, "publish_target:npm", "publishes-to") in edges
    assert (workflow, "deploy_target:Kubernetes", "deploys-to") in edges
    # A CI system only its configuration file names is a workflow of its own.
    assert ("ci_workflow:.circleci/config.yml", "ci_system:CircleCI", "runs-on") in edges
    images = {key[1]: edge for key, edge in edges.items() if key[2] == "pulls-images-from"}
    assert set(images) == {"image_registry:docker.io", "image_registry:gcr.io",
                           "image_registry:registry.acme.example:5000"}
    assert images["image_registry:gcr.io"]["pinned_images"] == 1
    deployed = {key[1] for key in edges if key[0] == project_id and key[2] == "deploys-to"}
    assert {"deploy_target:Kubernetes", "deploy_target:AWS", "deploy_target:Google Cloud",
            "deploy_target:Vercel"} <= deployed
    findings = {item["title"]: item for item in report["findings"] if item["analyzer"] == "code-index"}
    summary = findings["Software provenance"]["detail"]
    for part in ("hosted at: Self-hosted or unclassified (git.acme.example: mirror), GitHub (github.com: origin)",
                 "packages from: ", "registry.npmjs.org (npm: 1)",
                 "built by: GitHub Actions (1 workflow), CircleCI (1 workflow)",
                 "CI actions: 2 reference(s), 1 not pinned to a commit", "publishes to: container registry, npm",
                 "deploys to: ", "it does not prove where releases are actually built"):
        assert part in summary, part
    mixed = findings["Packages of one ecosystem from several registries"]
    assert mixed["severity"] == "LOW" and mixed["evidence"] == ["npm: npm registry (1), npm.acme.example (1)"]
    insecure = findings["Source locations over an unencrypted transport"]
    assert len(insecure["evidence"]) == 2
    assert any("git://git.example.org/lib.git" in item for item in insecure["evidence"])


def test_a_project_without_sources_has_no_provenance_findings(tmp_path: Path):
    project = tmp_path / "project"
    _write(project, {"app.py": "print('hello')\n"})
    output = tmp_path / "out"
    assert run_scan(project, output, {"json"}, 1, quiet=True) == 0
    report = json.loads((output / "discovery-report.json").read_text(encoding="utf-8"))
    graph = report["metrics"]["code_index"]["provenance"]
    assert graph["nodes"] == [{"id": "project:this project", "kind": "project", "label": "this project"}]
    assert not [item for item in report["findings"] if item["title"] == "Software provenance"]

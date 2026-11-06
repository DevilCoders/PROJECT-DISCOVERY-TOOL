"""Staging and launching for the Windows AppContainer plugin sandbox.

Staging is plain file copying, so it is tested on every platform with a stand-in
container; the launcher and the container's folder are tested on Windows.
"""
import os
import subprocess
import sys
import time
from pathlib import Path

import pytest

from project_discovery import plugin_appcontainer as appcontainer

WINDOWS = sys.platform == "win32"


class FakeContainer:
    def __init__(self) -> None:
        self.granted: list[Path] = []

    def grant_read(self, path: Path) -> None:
        self.granted.append(Path(path))


def _distribution(site: Path, name: str, package: str, *, requires=()) -> None:
    """Install a minimal distribution (package plus .dist-info with RECORD) into ``site``."""
    (site / package).mkdir(parents=True)
    (site / package / "__init__.py").write_text(f"NAME = {name!r}\n", encoding="utf-8")
    info = site / f"{name.replace('-', '_')}-1.0.dist-info"
    info.mkdir()
    metadata = ["Metadata-Version: 2.1", f"Name: {name}", "Version: 1.0"]
    metadata += [f"Requires-Dist: {item}" for item in requires]
    (info / "METADATA").write_text("\n".join(metadata) + "\n", encoding="utf-8")
    record = [f"{package}/__init__.py,,", f"{info.name}/METADATA,,", f"{info.name}/RECORD,,"]
    (info / "RECORD").write_text("\n".join(record) + "\n", encoding="utf-8")


@pytest.fixture
def site(tmp_path, monkeypatch):
    site = tmp_path / "site"
    site.mkdir()
    _distribution(site, "fixture-red-plugin", "fixture_red_plugin",
                  requires=["fixture-red-dependency>=1", 'fixture-red-optional; extra == "speed"'])
    _distribution(site, "fixture-red-dependency", "fixture_red_dependency")
    _distribution(site, "fixture-red-optional", "fixture_red_optional")
    monkeypatch.syspath_prepend(str(site))
    return site


def test_staging_copies_pdt_the_plugin_and_its_required_dependencies(tmp_path, site):
    container = FakeContainer()
    point = {"value": "fixture_red_plugin:Analyzer", "distribution": "fixture-red-plugin"}
    staged = appcontainer.stage_site(container, tmp_path / "work", point)
    assert (staged / "project_discovery" / "plugin_host.py").is_file()
    assert (staged / "fixture_red_plugin" / "__init__.py").is_file()
    assert (staged / "fixture_red_dependency" / "__init__.py").is_file()
    assert (staged / "fixture_red_plugin-1.0.dist-info" / "METADATA").is_file()
    # An extra the plugin did not ask for is not a dependency.
    assert not (staged / "fixture_red_optional").exists()
    # Access was granted on the folder before anything was copied into it.
    assert len(container.granted) == 1 and container.granted[0].name.startswith(".site-")
    assert not list((tmp_path / "work").glob(".site-*"))


def test_staging_is_reused_until_a_staged_file_changes(tmp_path, site):
    container = FakeContainer()
    point = {"value": "fixture_red_plugin:Analyzer", "distribution": "fixture-red-plugin"}
    first = appcontainer.stage_site(container, tmp_path / "work", point)
    assert appcontainer.stage_site(container, tmp_path / "work", point) == first
    source = site / "fixture_red_dependency" / "__init__.py"
    source.write_text("NAME = 'changed and longer'\n", encoding="utf-8")
    os.utime(source, ns=(time.time_ns(), time.time_ns() + 10**9))
    second = appcontainer.stage_site(container, tmp_path / "work", point)
    assert second != first
    assert "changed" in (second / "fixture_red_dependency" / "__init__.py").read_text(encoding="utf-8")


def test_a_plugin_without_a_distribution_is_staged_from_its_module(tmp_path, monkeypatch):
    modules = tmp_path / "modules"
    modules.mkdir()
    (modules / "fixture_red_single.py").write_text("X = 1\n", encoding="utf-8")
    monkeypatch.syspath_prepend(str(modules))
    staged = appcontainer.stage_site(FakeContainer(), tmp_path / "work", {"value": "fixture_red_single:X"})
    assert (staged / "fixture_red_single.py").read_text(encoding="utf-8") == "X = 1\n"


def test_oversized_plugins_are_refused_not_copied(tmp_path, site, monkeypatch):
    monkeypatch.setattr(appcontainer, "MAX_STAGED_BYTES", 1024)
    point = {"value": "fixture_red_plugin:Analyzer", "distribution": "fixture-red-plugin"}
    with pytest.raises(appcontainer.AppContainerError, match="--plugin-isolation process"):
        appcontainer.stage_site(FakeContainer(), tmp_path / "work", point)
    assert not (tmp_path / "work").exists() or not any((tmp_path / "work").iterdir())


def test_host_environment_has_the_profile_variables_and_no_secrets(tmp_path, monkeypatch):
    monkeypatch.setenv("PDT_FIXTURE_SECRET_TOKEN", "do-not-leak")
    environment = appcontainer.host_environment(tmp_path)
    assert "PDT_FIXTURE_SECRET_TOKEN" not in environment
    assert {"USERPROFILE", "LOCALAPPDATA", "APPDATA", "TEMP", "TMP", "HOME"} <= set(environment)


@pytest.mark.skipif(not WINDOWS, reason="Windows AppContainer launcher")
def test_appcontainer_process_pipes_exit_codes_and_kill(tmp_path):
    shared = appcontainer.prepared()
    python = str(shared.runtime / "python.exe")
    scratch = tmp_path / "scratch"
    scratch.mkdir()
    shared.container.grant_read(scratch)
    echo = appcontainer.AppContainerProcess(
        [python, "-I", "-S", "-c", "import sys; sys.stdout.write(sys.stdin.read()); sys.exit(7)"],
        executable=python, cwd=str(scratch), env=appcontainer.host_environment(scratch),
        container=shared.container,
    )
    echo.stdin.write(b"round trip")
    echo.stdin.close()
    assert echo.stdout.read() == b"round trip"
    assert echo.wait(timeout=60) == 7 and echo.poll() == 7
    echo.close_handle()

    sleeper = appcontainer.AppContainerProcess(
        [python, "-I", "-S", "-c", "import time; time.sleep(60)"],
        executable=python, cwd=str(scratch), env=appcontainer.host_environment(scratch),
        container=shared.container,
    )
    assert sleeper.poll() is None
    with pytest.raises(subprocess.TimeoutExpired):
        sleeper.wait(timeout=0.1)
    sleeper.kill()
    assert sleeper.wait(timeout=30) == 1
    for stream in (sleeper.stdin, sleeper.stdout, sleeper.stderr, echo.stdout, echo.stderr):
        stream.close()


@pytest.mark.skipif(not WINDOWS, reason="Windows AppContainer folder")
def test_files_left_in_the_container_folder_are_removed():
    container = appcontainer.prepared().container
    folder = container.storage_folder()
    assert folder is not None and folder.is_dir()
    leftover = folder / "pdt-test-leftover.txt"
    leftover.write_text("data a previous host could have left", encoding="utf-8")
    container.clear_storage()
    assert not leftover.exists()

import json
from pathlib import Path

from project_discovery.analyzers.domains.ml import AIMLIntelligenceAnalyzer
from project_discovery.models import FileRecord


def _record(path: Path, relative: str) -> FileRecord:
    return FileRecord(relative, path.stat().st_size, path.suffix.lower(), "Unknown")


def test_detects_framework_training_and_inference_without_execution(tmp_path: Path):
    path = tmp_path / "train.py"
    path.write_text(
        "import torch\nfrom transformers import Trainer\n"
        "class MyTrainer(Trainer):\n    pass\n"
        "def train(model, optimizer):\n"
        "    loss.backward()\n    optimizer.step()\n"
        "    model.generate()\n",
        encoding="utf-8",
    )
    findings = AIMLIntelligenceAnalyzer().analyze(path, _record(path, "train.py"))
    titles = [item.title for item in findings]
    assert any("AI/ML frameworks imported" in title for title in titles)
    assert any("training pipeline" in title for title in titles)
    assert any("inference/export" in title for title in titles)
    assert all(item.analyzer == "ai-ml-intelligence" for item in findings)


def test_indexes_model_config_without_leaking_arbitrary_values(tmp_path: Path):
    path = tmp_path / "config.json"
    path.write_text(json.dumps({
        "model_type": "transformer",
        "architectures": ["ExampleForCausalLM"],
        "hidden_size": 4096,
        "private_note": "not-for-report",
    }), encoding="utf-8")
    findings = AIMLIntelligenceAnalyzer().analyze(
        path, _record(path, "models/config.json")
    )
    assert len(findings) == 1
    assert "model_type=transformer" in findings[0].detail
    assert "not-for-report" not in repr(findings[0].to_dict())


def test_inventories_binary_artifacts_without_opening_them(tmp_path: Path):
    path = tmp_path / "weights.safetensors"
    path.write_bytes(b"\x00\x01private-model-payload")
    record = _record(path, "checkpoints/weights.safetensors")
    findings = AIMLIntelligenceAnalyzer().analyze(path, record)
    assert len(findings) == 1
    assert findings[0].confidence == "CONFIRMED"
    assert "not opened" in findings[0].detail


def test_dataset_artifact_detection_and_size_limit(tmp_path: Path):
    path = tmp_path / "train.parquet"
    path.write_bytes(b"parquet")
    analyzer = AIMLIntelligenceAnalyzer()
    record = _record(path, "datasets/train.parquet")
    assert analyzer.supports(record)
    assert analyzer.analyze(path, record)[0].category == "datasets"
    record.error = "oversized"
    assert not analyzer.supports(record)


def test_unrelated_json_is_not_misclassified(tmp_path: Path):
    path = tmp_path / "settings.json"
    path.write_text('{"theme":"dark","port":8080}', encoding="utf-8")
    analyzer = AIMLIntelligenceAnalyzer()
    record = _record(path, "settings.json")
    assert analyzer.supports(record) is False


def test_ordinary_python_is_not_reported_as_an_ml_pipeline(tmp_path: Path):
    # Regression: fit/predict/map/export/generate calls and substrings such as the
    # "mps" in json.dumps or "tpu" in output produced ML findings in non-ML code.
    path = tmp_path / "service.py"
    path.write_text(
        "import json\n"
        "def run(model, items, output):\n"
        "    model.fit(items)\n"
        "    result = list(map(str, items))\n"
        "    output.write(json.dumps(result))\n"
        "    return generate(output)\n",
        encoding="utf-8",
    )
    assert AIMLIntelligenceAnalyzer().analyze(path, _record(path, "service.py")) == []


def test_accelerator_references_match_whole_name_components(tmp_path: Path):
    path = tmp_path / "gpu.py"
    path.write_text(
        "import json\nimport torch\n"
        "available = torch.cuda.is_available()\n"
        "payload = json.dumps({})\n",
        encoding="utf-8",
    )
    findings = AIMLIntelligenceAnalyzer().analyze(path, _record(path, "gpu.py"))
    accelerator = next(item for item in findings if item.title.startswith("Accelerator/device"))
    assert accelerator.evidence == ["gpu.py:3 (torch.cuda.is_available)"]


def test_notebook_code_cells_are_analyzed_with_cell_locations(tmp_path: Path):
    # Regression: .ipynb notebooks, where most ML code lives, were not analyzed.
    path = tmp_path / "train.ipynb"
    path.write_text(json.dumps({
        "cells": [
            {"cell_type": "markdown", "source": ["import tensorflow  # prose, not code\n"]},
            {"cell_type": "code", "source": ["%matplotlib inline\n", "!pip install torch\n", "import torch\n"]},
            {"cell_type": "code", "source": "model.fit(data)\n"},
        ],
        "metadata": {}, "nbformat": 4, "nbformat_minor": 5,
    }), encoding="utf-8")
    analyzer = AIMLIntelligenceAnalyzer()
    record = _record(path, "notebooks/train.ipynb")
    assert analyzer.supports(record)
    findings = analyzer.analyze(path, record)
    frameworks = next(item for item in findings if "AI/ML frameworks imported" in item.title)
    assert frameworks.evidence == ["notebooks/train.ipynb:cell 2 line 3 (PyTorch)"]
    training = next(item for item in findings if "training pipeline" in item.title)
    assert training.evidence == ["notebooks/train.ipynb:cell 3 line 1 (model.fit)"]
    broken = tmp_path / "broken.ipynb"
    broken.write_text("{not json", encoding="utf-8")
    assert analyzer.analyze(broken, _record(broken, "broken.ipynb"))[0].confidence == "UNKNOWN"

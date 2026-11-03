"""Static AI/ML framework, training-pipeline and model-artifact discovery.

The analyzer reads source/configuration text only. It never imports frameworks,
loads checkpoints, deserializes model files, executes notebooks, or opens binary
model/dataset payloads.
"""
from __future__ import annotations

import ast
import json
from pathlib import Path

from .base import Analyzer
from ..models import FileRecord, Finding


_FRAMEWORKS = {
    "torch": "PyTorch",
    "tensorflow": "TensorFlow",
    "keras": "Keras",
    "jax": "JAX",
    "flax": "Flax",
    "optax": "Optax",
    "transformers": "Hugging Face Transformers",
    "diffusers": "Hugging Face Diffusers",
    "datasets": "Hugging Face Datasets",
    "accelerate": "Hugging Face Accelerate",
    "sentence_transformers": "Sentence Transformers",
    "onnx": "ONNX",
    "onnxruntime": "ONNX Runtime",
    "lightning": "Lightning",
    "pytorch_lightning": "PyTorch Lightning",
    "deepspeed": "DeepSpeed",
    "bitsandbytes": "bitsandbytes",
    "vllm": "vLLM",
    "llama_cpp": "llama.cpp bindings",
    "mlx": "MLX",
    "paddle": "PaddlePaddle",
    "mindspore": "MindSpore",
    "triton": "Triton",
    "torch_geometric": "PyTorch Geometric",
    "tensorrt": "TensorRT",
    "xgboost": "XGBoost",
    "lightgbm": "LightGBM",
    "sklearn": "scikit-learn",
    "catboost": "CatBoost",
    "ray": "Ray",
}
_MODEL_EXTENSIONS = {
    ".safetensors", ".pt", ".pth", ".ckpt", ".onnx", ".gguf", ".h5",
    ".keras", ".tflite", ".mlmodel", ".mlpackage", ".engine", ".plan",
    ".pkl", ".pickle", ".joblib",
}
_DATA_EXTENSIONS = {
    ".parquet", ".arrow", ".tfrecord", ".tfrecords", ".csv", ".tsv",
    ".jsonl", ".jsonlines", ".npz", ".npy", ".hdf5", ".h5",
}
_MODEL_METADATA_NAMES = {
    "config.json", "generation_config.json", "tokenizer.json",
    "tokenizer_config.json", "special_tokens_map.json", "vocab.json",
    "merges.txt", "added_tokens.json", "model_index.json",
}
_MODEL_CONFIG_KEYS = {
    "model_type", "architectures", "hidden_size", "num_hidden_layers",
    "num_attention_heads", "vocab_size", "intermediate_size",
}
_TRAINING_CALLS = {
    "backward", "optimizer.step", "zero_grad", "fit", "fit_generator",
    "train_step", "training_step", "compute_loss", "gradient",
}
_INFERENCE_CALLS = {
    "generate", "predict", "infer", "inference", "from_pretrained",
    "save_pretrained", "export",
}
_DATA_CALLS = {
    "dataloader", "dataset", "tf.data", "from_tensor_slices",
    "load_dataset", "map", "streaming",
}
_GPU_TOKENS = {
    "cuda", "rocm", "mps", "xpu", "tpu", "device",
}


def _dotted(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = _dotted(node.value)
        return f"{parent}.{node.attr}" if parent else node.attr
    if isinstance(node, ast.Call):
        return _dotted(node.func)
    return ""


def _python_evidence(path: Path, relative: str) -> list[Finding]:
    try:
        source = path.read_text(encoding="utf-8")
        tree = ast.parse(source, filename=relative)
    except (OSError, UnicodeDecodeError, SyntaxError) as exc:
        return [Finding(
            "machine_learning",
            f"AI/ML source analysis unavailable: {relative}",
            f"{type(exc).__name__}: {exc}",
            confidence="UNKNOWN",
            evidence=[relative],
            analyzer="ai-ml-intelligence",
        )]

    imports: dict[str, int] = {}
    calls: list[tuple[str, int]] = []
    class_bases: list[tuple[str, int]] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                top = alias.name.split(".", 1)[0]
                imports.setdefault(top, node.lineno)
        elif isinstance(node, ast.ImportFrom) and node.module:
            top = node.module.split(".", 1)[0]
            imports.setdefault(top, node.lineno)
        elif isinstance(node, ast.Call):
            name = _dotted(node.func)
            if name:
                calls.append((name, node.lineno))
        elif isinstance(node, ast.ClassDef):
            class_bases.extend((_dotted(base), node.lineno) for base in node.bases)

    findings: list[Finding] = []
    detected = sorted(
        ((name, line) for module, line in imports.items() if (name := _FRAMEWORKS.get(module))),
        key=lambda item: item[0].lower(),
    )
    if detected:
        names = [name for name, _ in detected]
        findings.append(Finding(
            "machine_learning",
            f"AI/ML frameworks imported: {relative}",
            "Statically observed imports: " + ", ".join(names) + ". Import presence "
            "does not prove that a model is trained or executed.",
            confidence="CONFIRMED",
            evidence=[f"{relative}:{line} ({name})" for name, line in detected],
            analyzer="ai-ml-intelligence",
        ))

    call_names = {name.lower() for name, _ in calls}
    base_names = {name.lower() for name, _ in class_bases}
    training = [
        (name, line) for name, line in calls
        if name.lower().split(".")[-1] in _TRAINING_CALLS
        or name.lower() in _TRAINING_CALLS
    ]
    if training or any("trainer" in name for name in base_names):
        evidence = [f"{relative}:{line} ({name})" for name, line in training[:50]]
        evidence.extend(
            f"{relative}:{line} (base {name})"
            for name, line in class_bases if "trainer" in name.lower()
        )
        findings.append(Finding(
            "machine_learning",
            f"Potential model training pipeline: {relative}",
            "Training-related calls or trainer base classes were found. Static evidence "
            "does not establish that a training run completed.",
            confidence="INFERRED",
            evidence=evidence or [relative],
            analyzer="ai-ml-intelligence",
        ))

    inference = [
        (name, line) for name, line in calls
        if name.lower().split(".")[-1] in _INFERENCE_CALLS
        or name.lower() in _INFERENCE_CALLS
    ]
    if inference:
        findings.append(Finding(
            "machine_learning",
            f"Model inference/export operations: {relative}",
            f"Observed {len(inference)} inference, generation, loading or export call sites.",
            confidence="INFERRED",
            evidence=[f"{relative}:{line} ({name})" for name, line in inference[:50]],
            analyzer="ai-ml-intelligence",
        ))

    data_calls = [
        (name, line) for name, line in calls
        if name.lower().split(".")[-1] in _DATA_CALLS or name.lower() in _DATA_CALLS
    ]
    if data_calls:
        findings.append(Finding(
            "datasets",
            f"Dataset pipeline references: {relative}",
            f"Observed {len(data_calls)} dataset or input-pipeline call sites.",
            confidence="INFERRED",
            evidence=[f"{relative}:{line} ({name})" for name, line in data_calls[:50]],
            analyzer="ai-ml-intelligence",
        ))

    gpu_refs = [
        (name, line) for name, line in calls
        if any(token in name.lower() for token in _GPU_TOKENS)
    ]
    if gpu_refs:
        findings.append(Finding(
            "gpu_compute",
            f"Accelerator/device references: {relative}",
            f"Observed {len(gpu_refs)} device or accelerator-related call sites.",
            confidence="INFERRED",
            evidence=[f"{relative}:{line} ({name})" for name, line in gpu_refs[:50]],
            analyzer="ai-ml-intelligence",
        ))
    return findings


class AIMLIntelligenceAnalyzer(Analyzer):
    """Discover ML frameworks and artifact inventories without loading model data."""

    name = "ai-ml-intelligence"
    domains = ("machine_learning", "datasets", "model_artifacts", "gpu_compute")
    languages = ("Python", "JSON", "Jupyter Notebook")

    def supports(self, record: FileRecord) -> bool:
        if record.error:
            return False
        name = Path(record.path).name.lower()
        path_parts = {part.lower() for part in Path(record.path).parts}
        return (
            record.extension in {".py", ".pyi"}
            or record.extension in _MODEL_EXTENSIONS
            or record.extension in _DATA_EXTENSIONS
            or name in _MODEL_METADATA_NAMES
            or (record.extension == ".json" and bool(
                path_parts & {"model", "models", "checkpoint", "checkpoints", "tokenizer"}
            ))
        )

    def analyze(self, path: Path, record: FileRecord) -> list[Finding]:
        if record.extension in {".py", ".pyi"}:
            return _python_evidence(path, record.path)

        name = Path(record.path).name.lower()
        if record.extension in _MODEL_EXTENSIONS:
            return [Finding(
                "model_artifacts",
                f"Model artifact detected: {record.path}",
                f"Recognized model/checkpoint artifact ({record.extension}). The binary "
                "payload was not opened, deserialized or executed.",
                confidence="CONFIRMED",
                evidence=[record.path, f"{record.size_bytes} bytes"],
                analyzer=self.name,
            )]
        if record.extension in _DATA_EXTENSIONS:
            return [Finding(
                "datasets",
                f"Potential dataset artifact: {record.path}",
                f"Recognized data container ({record.extension}); contents and schema "
                "were not loaded.",
                confidence="CONFIRMED",
                evidence=[record.path, f"{record.size_bytes} bytes"],
                analyzer=self.name,
            )]
        if name in _MODEL_METADATA_NAMES or record.extension == ".json":
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
                return [Finding(
                    "model_artifacts",
                    f"Model metadata parse error: {record.path}",
                    f"{type(exc).__name__}: {exc}",
                    confidence="UNKNOWN",
                    evidence=[record.path],
                    analyzer=self.name,
                )]
            if not isinstance(data, dict):
                return []
            present = sorted(_MODEL_CONFIG_KEYS & set(data))
            if not present:
                return []
            architecture = data.get("architectures", [])
            model_type = data.get("model_type")
            summary = []
            if isinstance(model_type, str):
                summary.append(f"model_type={model_type}")
            if isinstance(architecture, list):
                summary.extend(
                    f"architecture={item}" for item in architecture if isinstance(item, str)
                )
            summary.append("metadata fields: " + ", ".join(present))
            return [Finding(
                "model_artifacts",
                f"Model configuration metadata: {record.path}",
                "; ".join(summary),
                confidence="CONFIRMED",
                evidence=[record.path],
                analyzer=self.name,
            )]
        return []

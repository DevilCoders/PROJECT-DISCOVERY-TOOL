"""Static message broker and event-system client discovery."""
from __future__ import annotations

import ast
import re
from pathlib import Path

from ...core.source_utils import describe_error, parse_python, read_text_bounded
from ...models import FileRecord, Finding
from ..base import Analyzer

_SOURCE_EXTENSIONS = {
    ".py", ".pyi", ".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx",
    ".java", ".kt", ".kts", ".cs", ".go", ".rs", ".rb", ".php",
}
_PYTHON_MODULES = {
    "kafka": "Kafka", "confluent_kafka": "Kafka", "pika": "RabbitMQ",
    "kombu": "RabbitMQ", "celery": "Celery", "nats": "NATS",
    "paho": "MQTT", "zmq": "ZeroMQ", "pulsar": "Apache Pulsar",
    "stomp": "STOMP",
    "google.cloud.pubsub_v1": "Google Pub/Sub",
    "azure.servicebus": "Azure Service Bus",
}
_IMPORT_PATTERNS = {
    "Kafka": re.compile(r"(?:kafkajs|confluent-kafka|kafka-go|org\.apache\.kafka|segmentio/kafka-go)", re.I),
    # Whole words: "pika" inside "Pikachu" is not a RabbitMQ client.
    "RabbitMQ": re.compile(r"\b(?:amqplib|rabbitmq|pika|com\.rabbitmq|amqp091-go)\b", re.I),
    "NATS": re.compile(r"(?:from\s+nats|require\s*\(\s*['\"]nats['\"]|nats\.go)", re.I),
    "MQTT": re.compile(r"(?:from\s+paho|require\s*\(\s*['\"]mqtt['\"]|eclipse\.paho)", re.I),
    "ZeroMQ": re.compile(r"(?:import\s+zmq|require\s*\(\s*['\"]zeromq['\"]|\bzeromq\b)", re.I),
    "Celery": re.compile(r"(?:from\s+celery|import\s+celery|shared_task)", re.I),
    "AWS SQS/SNS": re.compile(r"(?:boto3(?:(?!sqs|sns|boto3)[^\n])*+(?:sqs|sns)|@aws-sdk/client-sqs|@aws-sdk/client-sns|services\.sqs|services\.sns)", re.I),
    "Google Pub/Sub": re.compile(r"(?:google\.cloud\.pubsub|@google-cloud/pubsub)", re.I),
    "Azure Service Bus": re.compile(r"(?:azure\.servicebus|@azure/service-bus|com\.azure\.messaging\.servicebus)", re.I),
    "Apache Pulsar": re.compile(r"\b(?:pulsar|org\.apache\.pulsar)\b", re.I),
    "STOMP": re.compile(r"\b(?:stomp|stompjs|org\.springframework\.messaging)\b", re.I),
}
_OPERATIONS = {
    "Kafka": {"produce", "send", "poll", "subscribe", "commit", "send_and_wait"},
    "RabbitMQ": {"basic_publish", "basic_consume", "basic_ack", "publish", "consume"},
    "NATS": {"publish", "subscribe", "request", "publish_async"},
    "MQTT": {"publish", "subscribe", "unsubscribe"},
    "ZeroMQ": {"send", "recv", "send_string", "recv_string"},
    "Celery": {"delay", "apply_async", "send_task"},
    "AWS SQS/SNS": {"send_message", "receive_message", "delete_message", "publish"},
    "Google Pub/Sub": {"publish", "subscribe", "pull", "ack"},
    "Azure Service Bus": {"send_messages", "receive_messages", "complete_message"},
    "Apache Pulsar": {"send", "receive", "subscribe", "acknowledge"},
    "STOMP": {"send", "subscribe", "ack", "nack"},
}


def _python_scan(source: str, relative: str):
    try:
        tree = parse_python(source, filename=relative)
    except SyntaxError:
        return {}, {}
    imports: dict[str, set[int]] = {}
    operations: dict[str, set[int]] = {}
    aliases: dict[str, str] = {}
    boto3_names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name == "boto3":
                    boto3_names.add(alias.asname or "boto3")  # SQS/SNS only by its client
                module = alias.name
                root = module.split(".", 1)[0]
                broker = _PYTHON_MODULES.get(module) or _PYTHON_MODULES.get(root)
                if broker:
                    imports.setdefault(broker, set()).add(node.lineno)
                    aliases[alias.asname or root] = broker
        elif isinstance(node, ast.ImportFrom) and node.module:
            module = node.module
            root = module.split(".", 1)[0]
            broker = _PYTHON_MODULES.get(module) or _PYTHON_MODULES.get(root)
            if broker:
                imports.setdefault(broker, set()).add(node.lineno)
                for alias in node.names:
                    aliases[alias.asname or alias.name] = broker
        elif isinstance(node, ast.Assign) and isinstance(node.value, ast.Call):
            func = node.value.func
            if (isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name)
                    and func.value.id in boto3_names and func.attr in {"client", "resource"} and node.value.args
                    and isinstance(node.value.args[0], ast.Constant)
                    and str(node.value.args[0].value).lower() in {"sqs", "sns"}):
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        aliases[target.id] = "AWS SQS/SNS"
        if isinstance(node, ast.Call):
            func = node.func
            method = func.attr if isinstance(func, ast.Attribute) else (
                func.id if isinstance(func, ast.Name) else ""
            )
            if isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name):
                if func.value.id in boto3_names and method in {"client", "resource"} and node.args and (
                    isinstance(node.args[0], ast.Constant) and str(node.args[0].value).lower() in {"sqs", "sns"}
                ):
                    imports.setdefault("AWS SQS/SNS", set()).add(node.lineno)
                broker = aliases.get(func.value.id)
                if broker and method in _OPERATIONS[broker]:
                    operations.setdefault(broker, set()).add(node.lineno)
            # Celery's calling API is task.delay() / task.apply_async(), on any receiver.
            if method in {"delay", "apply_async"} and "Celery" in imports:
                operations.setdefault("Celery", set()).add(node.lineno)
    return imports, operations


class MessagingIntelligenceAnalyzer(Analyzer):
    """Inventory broker clients and producer/consumer API references statically."""

    name = "messaging-intelligence"
    domains = ("messaging", "networking")
    languages = (
        "Python", "JavaScript", "TypeScript", "Java", "Kotlin", "C#",
        "Go", "Rust", "Ruby", "PHP",
    )

    def supports(self, record: FileRecord) -> bool:
        return record.error is None and record.extension in _SOURCE_EXTENSIONS

    def analyze(self, path: Path, record: FileRecord) -> list[Finding]:
        try:
            source = read_text_bounded(
                path, 16 * 1024 * 1024,
                expected_identity=record.analysis_identity,
            )
        except (OSError, UnicodeDecodeError) as exc:
            return [Finding(
                "messaging", f"Messaging analysis unavailable: {record.path}",
                describe_error(exc), confidence="UNKNOWN", severity="LOW",
                evidence=[record.path], analyzer=self.name,
            )]
        if record.extension in {".py", ".pyi"}:
            imports, operations = _python_scan(source, record.path)
        else:
            lines = source.splitlines()
            imports = {
                broker: {number for number, line in enumerate(lines, 1) if pattern.search(line)}
                for broker, pattern in _IMPORT_PATTERNS.items()
            }
            imports = {broker: locations for broker, locations in imports.items() if locations}
            operations: dict[str, set[int]] = {}
            for broker, methods in _OPERATIONS.items():
                if broker not in imports:
                    continue
                pattern = re.compile(
                    r"\.\s*(?:" + "|".join(re.escape(method) for method in sorted(methods))
                    + r")\s*\("
                )
                locations = {
                    number for number, line in enumerate(lines, 1) if pattern.search(line)
                }
                if locations:
                    operations[broker] = locations

        findings = []
        for broker in sorted(set(imports) | set(operations)):
            import_lines = sorted(imports.get(broker, set()))
            operation_lines = sorted(operations.get(broker, set()))
            evidence = [f"{record.path}:{line} (client reference)" for line in import_lines]
            evidence.extend(
                f"{record.path}:{line} (producer/consumer API)" for line in operation_lines
            )
            findings.append(Finding(
                "messaging",
                f"{broker} messaging references: {record.path}",
                f"Detected {len(import_lines)} client reference(s) and "
                f"{len(operation_lines)} producer/consumer API call site(s). This is a "
                "static code inventory, not a live broker topology.",
                confidence="CONFIRMED" if import_lines else "INFERRED",
                evidence=evidence[:100] or [record.path],
                analyzer=self.name,
            ))
        return findings

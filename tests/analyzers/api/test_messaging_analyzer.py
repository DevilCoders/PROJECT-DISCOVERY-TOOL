from pathlib import Path

from project_discovery.analyzers.api.messaging import MessagingIntelligenceAnalyzer
from project_discovery.models import FileRecord


def _scan(tmp_path: Path, filename: str, source: str):
    path = tmp_path / filename
    path.write_text(source, encoding="utf-8")
    record = FileRecord(filename, path.stat().st_size, path.suffix.lower(), "Source")
    analyzer = MessagingIntelligenceAnalyzer()
    assert analyzer.supports(record)
    return analyzer.analyze(path, record)


def test_python_kafka_and_rabbitmq_client_references(tmp_path: Path):
    findings = _scan(
        tmp_path, "workers.py",
        "from kafka import KafkaProducer, KafkaConsumer\n"
        "import pika\nproducer.send('events', value=payload)\n"
        "channel.basic_publish(exchange='', routing_key='jobs', body=payload)\n",
    )
    assert any("Kafka messaging references" in item.title for item in findings)
    assert any("RabbitMQ messaging references" in item.title for item in findings)


def test_javascript_mqtt_and_aws_sqs_references(tmp_path: Path):
    findings = _scan(
        tmp_path, "worker.ts",
        "const mqtt = require('mqtt');\n"
        "import { SQSClient } from '@aws-sdk/client-sqs';\n"
        "client.publish('topic', payload);\n"
        "client.sendMessage({ QueueUrl: queue });\n",
    )
    assert any("MQTT messaging references" in item.title for item in findings)
    assert any("AWS SQS/SNS messaging references" in item.title for item in findings)


def test_unrelated_source_has_no_messaging_findings(tmp_path: Path):
    assert _scan(tmp_path, "main.py", "def main():\n    return 1\n") == []


def test_non_source_file_is_not_supported():
    record = FileRecord("schema.sql", 20, ".sql", "SQL")
    assert MessagingIntelligenceAnalyzer().supports(record) is False


def test_boto3_celery_and_whole_word_brokers(tmp_path: Path):
    # Regressions: any boto3 import was SQS/SNS, Celery's task.delay() never counted, and
    # "pika" inside "Pikachu" was a CONFIRMED RabbitMQ reference.
    s3 = _scan(tmp_path, "s3.py", "import boto3\nboto3.client('s3').list_buckets()\n")
    assert not any("SQS" in item.title for item in s3)
    sqs = _scan(tmp_path, "queue.py", "import boto3\nqueue = boto3.client('sqs')\nqueue.send_message(QueueUrl='u', MessageBody='b')\n")
    assert any("SQS" in item.title for item in sqs)
    celery = _scan(tmp_path, "tasks.py", "from celery import shared_task\n@shared_task\ndef add(x, y):\n    return x + y\nadd.delay(1, 2)\n")
    assert any("1 producer/consumer" in item.detail or "operation" in item.detail.lower() for item in celery)
    pikachu = _scan(tmp_path, "game.js", "const hero = 'Pikachu';\n")
    assert not any("RabbitMQ" in item.title for item in pikachu)

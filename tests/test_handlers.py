import json

import pytest

from cleanup.cleanup import handler as cleanup_handler
from cleanup.config import ScannerConfig
from cleanup.scanner import handler as scanner_handler

from .fakes import FakeEC2, FakeELBv2, FakeSNS


@pytest.fixture(autouse=True)
def env(monkeypatch):
    monkeypatch.setenv("FINDINGS_TOPIC_ARN", "arn:aws:sns:us-east-1:123456789012:findings")
    monkeypatch.setenv("AWS_REGION", "us-east-1")
    yield


def test_scanner_handler_publishes_findings():
    ec2 = FakeEC2()
    ec2.addresses = [{"AllocationId": "eipalloc-1", "Tags": []}]
    elbv2 = FakeELBv2()
    sns = FakeSNS()

    result = scanner_handler({}, None, ec2=ec2, elbv2=elbv2, sns=sns)

    assert result["findings_count"] == 1
    assert len(sns.published) == 1


def test_scanner_handler_requires_topic_arn(monkeypatch):
    monkeypatch.delenv("FINDINGS_TOPIC_ARN", raising=False)
    with pytest.raises(KeyError):
        ScannerConfig.from_env()


def test_cleanup_handler_dry_run_from_sqs_event(monkeypatch):
    monkeypatch.delenv("APPLY", raising=False)
    ec2 = FakeEC2()
    ec2.addresses = [{"AllocationId": "eipalloc-1", "Tags": []}]
    body = {"items": [{"kind": "elastic_ip", "resource_id": "eipalloc-1", "region": "us-east-1"}]}
    event = {"Records": [{"body": json.dumps(body)}]}

    result = cleanup_handler(event, None, ec2=ec2, elbv2=FakeELBv2())

    assert result["dry_run"] == ["elastic_ip:eipalloc-1"]
    assert result["deleted"] == []
    assert ec2.released_allocation_ids == []


def test_cleanup_handler_apply_mode(monkeypatch):
    monkeypatch.setenv("APPLY", "true")
    ec2 = FakeEC2()
    ec2.addresses = [{"AllocationId": "eipalloc-1", "Tags": []}]
    body = {"items": [{"kind": "elastic_ip", "resource_id": "eipalloc-1", "region": "us-east-1"}]}
    event = {"Records": [{"body": json.dumps(body)}]}

    result = cleanup_handler(event, None, ec2=ec2, elbv2=FakeELBv2())

    assert result["deleted"] == ["elastic_ip:eipalloc-1"]
    assert ec2.released_allocation_ids == ["eipalloc-1"]

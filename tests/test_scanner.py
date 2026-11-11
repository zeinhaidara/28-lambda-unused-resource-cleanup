from datetime import UTC, datetime, timedelta

from cleanup.config import ScannerConfig
from cleanup.scanner import (
    find_old_unused_amis,
    find_orphaned_load_balancers,
    find_unattached_security_groups,
    find_unused_eips,
    publish_findings,
    scan_all,
)

from .fakes import FakeEC2, FakeELBv2, FakeSNS

CFG = ScannerConfig(
    ami_age_days=90,
    protect_tag_key="cleanup-protect",
    protect_tag_value="true",
    sns_topic_arn="arn:aws:sns:us-east-1:123456789012:findings",
    region="us-east-1",
)


def test_find_unused_eips_skips_associated():
    ec2 = FakeEC2()
    ec2.addresses = [
        {"AllocationId": "eipalloc-unused", "Tags": []},
        {"AllocationId": "eipalloc-used", "AssociationId": "eipassoc-1", "Tags": []},
    ]
    findings = find_unused_eips(ec2, CFG)
    assert [f.resource_id for f in findings] == ["eipalloc-unused"]


def test_find_unused_eips_skips_protected():
    ec2 = FakeEC2()
    ec2.addresses = [
        {
            "AllocationId": "eipalloc-protected",
            "Tags": [{"Key": "cleanup-protect", "Value": "true"}],
        }
    ]
    assert find_unused_eips(ec2, CFG) == []


def test_find_old_unused_amis_respects_age_and_usage():
    ec2 = FakeEC2()
    now = datetime(2026, 1, 1, tzinfo=UTC)
    old_date = (now - timedelta(days=200)).strftime("%Y-%m-%dT%H:%M:%S.000Z")
    recent_date = (now - timedelta(days=5)).strftime("%Y-%m-%dT%H:%M:%S.000Z")
    ec2.images = [
        {"ImageId": "ami-old-unused", "CreationDate": old_date, "Tags": []},
        {"ImageId": "ami-old-in-use", "CreationDate": old_date, "Tags": []},
        {"ImageId": "ami-recent", "CreationDate": recent_date, "Tags": []},
    ]
    ec2.reservations = [{"Instances": [{"ImageId": "ami-old-in-use"}]}]

    findings = find_old_unused_amis(ec2, CFG, now=now)
    assert [f.resource_id for f in findings] == ["ami-old-unused"]


def test_find_unattached_security_groups():
    ec2 = FakeEC2()
    ec2.security_groups = [
        {"GroupId": "sg-attached", "GroupName": "web", "Tags": []},
        {"GroupId": "sg-orphan", "GroupName": "old-app", "Tags": []},
        {"GroupId": "sg-default", "GroupName": "default", "Tags": []},
    ]
    ec2.network_interfaces = [{"Groups": [{"GroupId": "sg-attached"}]}]

    findings = find_unattached_security_groups(ec2, CFG)
    assert [f.resource_id for f in findings] == ["sg-orphan"]


def test_find_orphaned_load_balancers():
    elbv2 = FakeELBv2()
    elbv2.load_balancers = [
        {"LoadBalancerArn": "arn:lb:healthy"},
        {"LoadBalancerArn": "arn:lb:orphan"},
    ]
    elbv2.target_groups_by_lb_arn = {
        "arn:lb:healthy": [{"TargetGroupArn": "arn:tg:healthy"}],
        "arn:lb:orphan": [{"TargetGroupArn": "arn:tg:empty"}],
    }
    elbv2.target_health_by_tg_arn = {
        "arn:tg:healthy": [{"TargetHealth": {"State": "healthy"}}],
        "arn:tg:empty": [{"TargetHealth": {"State": "unhealthy"}}],
    }

    findings = find_orphaned_load_balancers(elbv2, CFG)
    assert [f.resource_id for f in findings] == ["arn:lb:orphan"]


def test_scan_all_combines_everything():
    ec2 = FakeEC2()
    ec2.addresses = [{"AllocationId": "eipalloc-unused", "Tags": []}]
    elbv2 = FakeELBv2()
    findings = scan_all(ec2, elbv2, CFG)
    assert len(findings) == 1


def test_publish_findings_sends_sns_message():
    sns = FakeSNS()
    ec2 = FakeEC2()
    ec2.addresses = [{"AllocationId": "eipalloc-unused", "Tags": []}]
    findings = find_unused_eips(ec2, CFG)

    message_id = publish_findings(sns, CFG, findings)

    assert message_id == "msg-1"
    assert len(sns.published) == 1
    assert sns.published[0]["TopicArn"] == CFG.sns_topic_arn


def test_publish_findings_skips_when_nothing_found():
    sns = FakeSNS()
    message_id = publish_findings(sns, CFG, [])
    assert message_id is None
    assert sns.published == []

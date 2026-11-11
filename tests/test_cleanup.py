from cleanup.cleanup import process_approval_message, process_item
from cleanup.config import CleanupConfig
from cleanup.models import ApprovalItem

from .fakes import FakeEC2, FakeELBv2

DRY_RUN_CFG = CleanupConfig(apply=False, region="us-east-1")
APPLY_CFG = CleanupConfig(apply=True, region="us-east-1")


def _eip_fixture():
    ec2 = FakeEC2()
    ec2.addresses = [{"AllocationId": "eipalloc-unused", "Tags": []}]
    return ec2


def test_dry_run_makes_no_delete_calls():
    ec2 = _eip_fixture()
    item = ApprovalItem(kind="elastic_ip", resource_id="eipalloc-unused", region="us-east-1")

    outcome = process_item(ec2, FakeELBv2(), DRY_RUN_CFG, item)

    assert outcome == "dry_run"
    assert ec2.released_allocation_ids == []


def test_apply_deletes_confirmed_unused_eip():
    ec2 = _eip_fixture()
    item = ApprovalItem(kind="elastic_ip", resource_id="eipalloc-unused", region="us-east-1")

    outcome = process_item(ec2, FakeELBv2(), APPLY_CFG, item)

    assert outcome == "deleted"
    assert ec2.released_allocation_ids == ["eipalloc-unused"]


def test_recheck_skips_eip_that_became_associated():
    ec2 = FakeEC2()
    ec2.addresses = [
        {"AllocationId": "eipalloc-1", "AssociationId": "eipassoc-new", "Tags": []}
    ]
    item = ApprovalItem(kind="elastic_ip", resource_id="eipalloc-1", region="us-east-1")

    outcome = process_item(ec2, FakeELBv2(), APPLY_CFG, item)

    assert outcome == "skipped"
    assert ec2.released_allocation_ids == []


def test_recheck_skips_resource_no_longer_present():
    ec2 = FakeEC2()
    ec2.addresses = []
    item = ApprovalItem(kind="elastic_ip", resource_id="eipalloc-gone", region="us-east-1")

    outcome = process_item(ec2, FakeELBv2(), APPLY_CFG, item)

    assert outcome == "skipped"


def test_recheck_skips_ami_now_in_use():
    ec2 = FakeEC2()
    ec2.images = [{"ImageId": "ami-1", "CreationDate": "2020-01-01T00:00:00.000Z", "Tags": []}]
    ec2.reservations = [{"Instances": [{"ImageId": "ami-1"}]}]
    item = ApprovalItem(kind="ami", resource_id="ami-1", region="us-east-1")

    outcome = process_item(ec2, FakeELBv2(), APPLY_CFG, item)

    assert outcome == "skipped"
    assert ec2.deregistered_image_ids == []


def test_recheck_skips_security_group_now_attached():
    ec2 = FakeEC2()
    ec2.security_groups = [{"GroupId": "sg-1", "GroupName": "app", "Tags": []}]
    ec2.network_interfaces = [{"Groups": [{"GroupId": "sg-1"}]}]
    item = ApprovalItem(kind="security_group", resource_id="sg-1", region="us-east-1")

    outcome = process_item(ec2, FakeELBv2(), APPLY_CFG, item)

    assert outcome == "skipped"
    assert ec2.deleted_group_ids == []


def test_recheck_skips_load_balancer_now_healthy():
    elbv2 = FakeELBv2()
    elbv2.load_balancers = [{"LoadBalancerArn": "arn:lb:1"}]
    elbv2.target_groups_by_lb_arn = {"arn:lb:1": [{"TargetGroupArn": "arn:tg:1"}]}
    elbv2.target_health_by_tg_arn = {"arn:tg:1": [{"TargetHealth": {"State": "healthy"}}]}
    item = ApprovalItem(kind="load_balancer", resource_id="arn:lb:1", region="us-east-1")

    outcome = process_item(FakeEC2(), elbv2, APPLY_CFG, item)

    assert outcome == "skipped"
    assert elbv2.deleted_lb_arns == []


def test_apply_deletes_confirmed_orphaned_load_balancer():
    elbv2 = FakeELBv2()
    elbv2.load_balancers = [{"LoadBalancerArn": "arn:lb:1"}]
    elbv2.target_groups_by_lb_arn = {"arn:lb:1": []}
    item = ApprovalItem(kind="load_balancer", resource_id="arn:lb:1", region="us-east-1")

    outcome = process_item(FakeEC2(), elbv2, APPLY_CFG, item)

    assert outcome == "deleted"
    assert elbv2.deleted_lb_arns == ["arn:lb:1"]


def test_process_approval_message_never_touches_unlisted_resources():
    ec2 = FakeEC2()
    ec2.addresses = [
        {"AllocationId": "eipalloc-approved", "Tags": []},
        {"AllocationId": "eipalloc-not-approved", "Tags": []},
    ]
    body = {
        "items": [
            {"kind": "elastic_ip", "resource_id": "eipalloc-approved", "region": "us-east-1"}
        ]
    }

    result = process_approval_message(ec2, FakeELBv2(), APPLY_CFG, body)

    assert result["deleted"] == ["elastic_ip:eipalloc-approved"]
    assert ec2.released_allocation_ids == ["eipalloc-approved"]
    assert "eipalloc-not-approved" in [a["AllocationId"] for a in ec2.addresses]

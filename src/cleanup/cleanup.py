"""Cleanup phase: delete only what an approval message explicitly names.

Before deleting, each item is re-checked against live AWS state. If a
resource no longer matches the "unused" condition it was approved under
(it changed state between scan and approval), it is skipped, never deleted.
"""
from __future__ import annotations

import json
import logging
from typing import Any

from .config import CleanupConfig
from .models import ApprovalItem

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)


class RecheckFailed(Exception):
    """Raised when a resource no longer matches the approved unused state."""


def _recheck_eip(ec2: Any, resource_id: str) -> None:
    response = ec2.describe_addresses(AllocationIds=[resource_id])
    addresses = response.get("Addresses", [])
    if not addresses:
        raise RecheckFailed(f"elastic ip {resource_id} no longer exists")
    if addresses[0].get("AssociationId"):
        raise RecheckFailed(f"elastic ip {resource_id} is now associated")


def _delete_eip(ec2: Any, resource_id: str) -> None:
    ec2.release_address(AllocationId=resource_id)


def _recheck_ami(ec2: Any, resource_id: str) -> None:
    images = ec2.describe_images(ImageIds=[resource_id]).get("Images", [])
    if not images:
        raise RecheckFailed(f"ami {resource_id} no longer exists")
    in_use = {
        instance["ImageId"]
        for reservation in ec2.describe_instances().get("Reservations", [])
        for instance in reservation.get("Instances", [])
    }
    if resource_id in in_use:
        raise RecheckFailed(f"ami {resource_id} is now in use by an instance")


def _delete_ami(ec2: Any, resource_id: str) -> None:
    ec2.deregister_image(ImageId=resource_id)


def _recheck_security_group(ec2: Any, resource_id: str) -> None:
    groups = ec2.describe_security_groups(GroupIds=[resource_id]).get("SecurityGroups", [])
    if not groups:
        raise RecheckFailed(f"security group {resource_id} no longer exists")
    referenced = {
        group["GroupId"]
        for eni in ec2.describe_network_interfaces().get("NetworkInterfaces", [])
        for group in eni.get("Groups", [])
    }
    if resource_id in referenced:
        raise RecheckFailed(f"security group {resource_id} is now attached to a network interface")


def _delete_security_group(ec2: Any, resource_id: str) -> None:
    ec2.delete_security_group(GroupId=resource_id)


def _recheck_load_balancer(elbv2: Any, resource_id: str) -> None:
    lbs = elbv2.describe_load_balancers(LoadBalancerArns=[resource_id]).get("LoadBalancers", [])
    if not lbs:
        raise RecheckFailed(f"load balancer {resource_id} no longer exists")
    target_groups = elbv2.describe_target_groups(LoadBalancerArn=resource_id).get(
        "TargetGroups", []
    )
    for tg in target_groups:
        health = elbv2.describe_target_health(TargetGroupArn=tg["TargetGroupArn"])
        for description in health.get("TargetHealthDescriptions", []):
            if description.get("TargetHealth", {}).get("State") == "healthy":
                raise RecheckFailed(f"load balancer {resource_id} now has a healthy target")


def _delete_load_balancer(elbv2: Any, resource_id: str) -> None:
    elbv2.delete_load_balancer(LoadBalancerArn=resource_id)


_RECHECKERS = {
    "elastic_ip": _recheck_eip,
    "ami": _recheck_ami,
    "security_group": _recheck_security_group,
    "load_balancer": _recheck_load_balancer,
}

_DELETERS = {
    "elastic_ip": _delete_eip,
    "ami": _delete_ami,
    "security_group": _delete_security_group,
    "load_balancer": _delete_load_balancer,
}


def process_item(ec2: Any, elbv2: Any, cfg: CleanupConfig, item: ApprovalItem) -> str:
    """Returns one of: "deleted", "dry_run", "skipped"."""
    client = elbv2 if item.kind == "load_balancer" else ec2
    recheck = _RECHECKERS[item.kind]

    try:
        recheck(client, item.resource_id)
    except RecheckFailed as exc:
        logger.warning("skipping %s %s: %s", item.kind, item.resource_id, exc)
        return "skipped"

    if not cfg.apply:
        logger.info("dry-run: would delete %s %s", item.kind, item.resource_id)
        return "dry_run"

    _DELETERS[item.kind](client, item.resource_id)
    logger.info("deleted %s %s", item.kind, item.resource_id)
    return "deleted"


def process_approval_message(ec2: Any, elbv2: Any, cfg: CleanupConfig, body: dict) -> dict:
    items = [ApprovalItem.from_dict(raw) for raw in body.get("items", [])]
    results = {"deleted": [], "dry_run": [], "skipped": []}
    for item in items:
        outcome = process_item(ec2, elbv2, cfg, item)
        results[outcome].append(f"{item.kind}:{item.resource_id}")
    return results


def handler(event: dict, context: Any, ec2: Any = None, elbv2: Any = None) -> dict:
    import boto3

    cfg = CleanupConfig.from_env()
    ec2 = ec2 or boto3.client("ec2", region_name=cfg.region)
    elbv2 = elbv2 or boto3.client("elbv2", region_name=cfg.region)

    summary = {"deleted": [], "dry_run": [], "skipped": []}
    for record in event.get("Records", []):
        body = json.loads(record["body"])
        result = process_approval_message(ec2, elbv2, cfg, body)
        for key in summary:
            summary[key].extend(result[key])
    return summary

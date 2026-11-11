"""Scan phase: find unused resources and publish findings for approval.

The scanner never deletes anything. It only reads AWS state and publishes
a findings message to SNS so a human can review and approve specific items.
"""
from __future__ import annotations

import json
import logging
from datetime import UTC, datetime, timedelta
from typing import Any

from .config import ScannerConfig
from .models import Finding

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)


def _has_protect_tag(tags: list[dict] | None, key: str, value: str) -> bool:
    for tag in tags or []:
        if tag.get("Key") == key and tag.get("Value") == value:
            return True
    return False


def find_unused_eips(ec2: Any, cfg: ScannerConfig) -> list[Finding]:
    findings = []
    response = ec2.describe_addresses()
    for address in response.get("Addresses", []):
        if address.get("AssociationId"):
            continue
        if _has_protect_tag(address.get("Tags"), cfg.protect_tag_key, cfg.protect_tag_value):
            continue
        findings.append(
            Finding(
                kind="elastic_ip",
                resource_id=address["AllocationId"],
                reason="not associated with any network interface",
                region=cfg.region,
            )
        )
    return findings


def find_old_unused_amis(
    ec2: Any, cfg: ScannerConfig, now: datetime | None = None
) -> list[Finding]:
    now = now or datetime.now(UTC)
    cutoff = now - timedelta(days=cfg.ami_age_days)

    images = ec2.describe_images(Owners=["self"]).get("Images", [])
    instances_in_use = {
        instance["ImageId"]
        for reservation in ec2.describe_instances().get("Reservations", [])
        for instance in reservation.get("Instances", [])
    }

    findings = []
    for image in images:
        created = datetime.fromisoformat(image["CreationDate"].replace("Z", "+00:00"))
        if created >= cutoff:
            continue
        if image["ImageId"] in instances_in_use:
            continue
        if _has_protect_tag(image.get("Tags"), cfg.protect_tag_key, cfg.protect_tag_value):
            continue
        age_days = (now - created).days
        findings.append(
            Finding(
                kind="ami",
                resource_id=image["ImageId"],
                reason=f"unused and {age_days} days old (threshold {cfg.ami_age_days})",
                region=cfg.region,
            )
        )
    return findings


def find_unattached_security_groups(ec2: Any, cfg: ScannerConfig) -> list[Finding]:
    groups = ec2.describe_security_groups().get("SecurityGroups", [])
    referenced_group_ids = {
        group["GroupId"]
        for eni in ec2.describe_network_interfaces().get("NetworkInterfaces", [])
        for group in eni.get("Groups", [])
    }

    findings = []
    for group in groups:
        if group["GroupName"] == "default":
            continue
        if group["GroupId"] in referenced_group_ids:
            continue
        if _has_protect_tag(group.get("Tags"), cfg.protect_tag_key, cfg.protect_tag_value):
            continue
        findings.append(
            Finding(
                kind="security_group",
                resource_id=group["GroupId"],
                reason="not referenced by any network interface",
                region=cfg.region,
            )
        )
    return findings


def find_orphaned_load_balancers(elbv2: Any, cfg: ScannerConfig) -> list[Finding]:
    findings = []
    load_balancers = elbv2.describe_load_balancers().get("LoadBalancers", [])
    for lb in load_balancers:
        lb_arn = lb["LoadBalancerArn"]
        tags_response = elbv2.describe_tags(ResourceArns=[lb_arn])
        tag_descriptions = tags_response.get("TagDescriptions", [])
        tags = tag_descriptions[0].get("Tags") if tag_descriptions else []
        if _has_protect_tag(tags, cfg.protect_tag_key, cfg.protect_tag_value):
            continue

        target_groups = elbv2.describe_target_groups(LoadBalancerArn=lb_arn).get("TargetGroups", [])
        has_healthy_target = False
        for tg in target_groups:
            health = elbv2.describe_target_health(TargetGroupArn=tg["TargetGroupArn"])
            for description in health.get("TargetHealthDescriptions", []):
                if description.get("TargetHealth", {}).get("State") == "healthy":
                    has_healthy_target = True
                    break
            if has_healthy_target:
                break

        if has_healthy_target:
            continue

        findings.append(
            Finding(
                kind="load_balancer",
                resource_id=lb_arn,
                reason="no healthy registered targets in any target group",
                region=cfg.region,
            )
        )
    return findings


def scan_all(ec2: Any, elbv2: Any, cfg: ScannerConfig) -> list[Finding]:
    return [
        *find_unused_eips(ec2, cfg),
        *find_old_unused_amis(ec2, cfg),
        *find_unattached_security_groups(ec2, cfg),
        *find_orphaned_load_balancers(elbv2, cfg),
    ]


def publish_findings(sns: Any, cfg: ScannerConfig, findings: list[Finding]) -> str | None:
    if not findings:
        logger.info("no unused resources found, nothing published")
        return None

    message = {
        "findings": [finding.to_dict() for finding in findings],
        "count": len(findings),
    }
    response = sns.publish(
        TopicArn=cfg.sns_topic_arn,
        Subject=f"{len(findings)} unused resource(s) awaiting approval",
        Message=json.dumps(message),
    )
    message_id = response["MessageId"]
    logger.info("published %d finding(s) as message %s", len(findings), message_id)
    return message_id


def handler(event: dict, context: Any, ec2: Any = None, elbv2: Any = None, sns: Any = None) -> dict:
    import boto3

    cfg = ScannerConfig.from_env()
    ec2 = ec2 or boto3.client("ec2", region_name=cfg.region)
    elbv2 = elbv2 or boto3.client("elbv2", region_name=cfg.region)
    sns = sns or boto3.client("sns", region_name=cfg.region)

    findings = scan_all(ec2, elbv2, cfg)
    message_id = publish_findings(sns, cfg, findings)
    return {"findings_count": len(findings), "sns_message_id": message_id}

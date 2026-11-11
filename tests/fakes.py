"""Hand-written fakes standing in for boto3 clients. No network, no moto."""
from __future__ import annotations

import copy


class FakeEC2:
    def __init__(self):
        self.addresses: list[dict] = []
        self.images: list[dict] = []
        self.reservations: list[dict] = []
        self.security_groups: list[dict] = []
        self.network_interfaces: list[dict] = []
        self.released_allocation_ids: list[str] = []
        self.deregistered_image_ids: list[str] = []
        self.deleted_group_ids: list[str] = []

    def describe_addresses(self, AllocationIds: list[str] | None = None) -> dict:
        addresses = self.addresses
        if AllocationIds:
            addresses = [a for a in addresses if a["AllocationId"] in AllocationIds]
        return {"Addresses": copy.deepcopy(addresses)}

    def describe_images(
        self, Owners: list[str] | None = None, ImageIds: list[str] | None = None
    ) -> dict:
        images = self.images
        if ImageIds:
            images = [i for i in images if i["ImageId"] in ImageIds]
        return {"Images": copy.deepcopy(images)}

    def describe_instances(self) -> dict:
        return {"Reservations": copy.deepcopy(self.reservations)}

    def describe_security_groups(self, GroupIds: list[str] | None = None) -> dict:
        groups = self.security_groups
        if GroupIds:
            groups = [g for g in groups if g["GroupId"] in GroupIds]
        return {"SecurityGroups": copy.deepcopy(groups)}

    def describe_network_interfaces(self) -> dict:
        return {"NetworkInterfaces": copy.deepcopy(self.network_interfaces)}

    def release_address(self, AllocationId: str) -> dict:
        self.released_allocation_ids.append(AllocationId)
        self.addresses = [a for a in self.addresses if a["AllocationId"] != AllocationId]
        return {}

    def deregister_image(self, ImageId: str) -> dict:
        self.deregistered_image_ids.append(ImageId)
        self.images = [i for i in self.images if i["ImageId"] != ImageId]
        return {}

    def delete_security_group(self, GroupId: str) -> dict:
        self.deleted_group_ids.append(GroupId)
        self.security_groups = [g for g in self.security_groups if g["GroupId"] != GroupId]
        return {}


class FakeELBv2:
    def __init__(self):
        self.load_balancers: list[dict] = []
        self.tags_by_arn: dict[str, list[dict]] = {}
        self.target_groups_by_lb_arn: dict[str, list[dict]] = {}
        self.target_health_by_tg_arn: dict[str, list[dict]] = {}
        self.deleted_lb_arns: list[str] = []

    def describe_load_balancers(self, LoadBalancerArns: list[str] | None = None) -> dict:
        lbs = self.load_balancers
        if LoadBalancerArns:
            lbs = [lb for lb in lbs if lb["LoadBalancerArn"] in LoadBalancerArns]
        return {"LoadBalancers": copy.deepcopy(lbs)}

    def describe_tags(self, ResourceArns: list[str]) -> dict:
        descriptions = []
        for arn in ResourceArns:
            descriptions.append({"ResourceArn": arn, "Tags": self.tags_by_arn.get(arn, [])})
        return {"TagDescriptions": copy.deepcopy(descriptions)}

    def describe_target_groups(self, LoadBalancerArn: str) -> dict:
        return {
            "TargetGroups": copy.deepcopy(self.target_groups_by_lb_arn.get(LoadBalancerArn, []))
        }

    def describe_target_health(self, TargetGroupArn: str) -> dict:
        return {
            "TargetHealthDescriptions": copy.deepcopy(
                self.target_health_by_tg_arn.get(TargetGroupArn, [])
            )
        }

    def delete_load_balancer(self, LoadBalancerArn: str) -> dict:
        self.deleted_lb_arns.append(LoadBalancerArn)
        self.load_balancers = [
            lb for lb in self.load_balancers if lb["LoadBalancerArn"] != LoadBalancerArn
        ]
        return {}


class FakeSNS:
    def __init__(self):
        self.published: list[dict] = []
        self._next_id = 1

    def publish(self, TopicArn: str, Subject: str, Message: str) -> dict:
        message_id = f"msg-{self._next_id}"
        self._next_id += 1
        self.published.append({"TopicArn": TopicArn, "Subject": Subject, "Message": Message})
        return {"MessageId": message_id}


class FakeSQS:
    def __init__(self):
        self.sent: list[dict] = []

    def send_message(self, QueueUrl: str, MessageBody: str) -> dict:
        self.sent.append({"QueueUrl": QueueUrl, "MessageBody": MessageBody})
        return {"MessageId": "sqs-msg-1"}

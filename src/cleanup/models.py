"""Shared data shapes for findings and approvals."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

ResourceKind = Literal[
    "elastic_ip",
    "ami",
    "security_group",
    "load_balancer",
]


@dataclass(frozen=True)
class Finding:
    kind: ResourceKind
    resource_id: str
    reason: str
    region: str

    def to_dict(self) -> dict:
        return {
            "kind": self.kind,
            "resource_id": self.resource_id,
            "reason": self.reason,
            "region": self.region,
        }


@dataclass(frozen=True)
class ApprovalItem:
    kind: ResourceKind
    resource_id: str
    region: str

    @classmethod
    def from_dict(cls, data: dict) -> ApprovalItem:
        return cls(
            kind=data["kind"],
            resource_id=data["resource_id"],
            region=data["region"],
        )

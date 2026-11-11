"""Environment-driven configuration for both lambdas."""
from __future__ import annotations

import os
from dataclasses import dataclass


def _env_bool(name: str, default: bool) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip().lower() in ("1", "true", "yes", "on")


def _env_int(name: str, default: int) -> int:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return int(raw)


@dataclass(frozen=True)
class ScannerConfig:
    ami_age_days: int
    protect_tag_key: str
    protect_tag_value: str
    sns_topic_arn: str
    region: str

    @classmethod
    def from_env(cls) -> ScannerConfig:
        return cls(
            ami_age_days=_env_int("AMI_AGE_THRESHOLD_DAYS", 90),
            protect_tag_key=os.environ.get("PROTECT_TAG_KEY", "cleanup-protect"),
            protect_tag_value=os.environ.get("PROTECT_TAG_VALUE", "true"),
            sns_topic_arn=os.environ["FINDINGS_TOPIC_ARN"],
            region=os.environ.get("AWS_REGION", "us-east-1"),
        )


@dataclass(frozen=True)
class CleanupConfig:
    apply: bool
    region: str

    @classmethod
    def from_env(cls) -> CleanupConfig:
        return cls(
            apply=_env_bool("APPLY", False),
            region=os.environ.get("AWS_REGION", "us-east-1"),
        )

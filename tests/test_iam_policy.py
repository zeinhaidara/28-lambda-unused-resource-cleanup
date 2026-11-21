"""Structural checks on iam/cleanup-policy.json, so scoping can't quietly regress."""
import json
from pathlib import Path

POLICY = json.loads(
    (Path(__file__).parent.parent / "iam" / "cleanup-policy.json").read_text(encoding="utf-8")
)
DELETE_ACTIONS = {
    "ec2:ReleaseAddress",
    "ec2:DeregisterImage",
    "ec2:DeleteSecurityGroup",
    "elasticloadbalancing:DeleteLoadBalancer",
}


def _actions(statement):
    action = statement["Action"]
    return {action} if isinstance(action, str) else set(action)


def _resources(statement):
    res = statement["Resource"]
    return [res] if isinstance(res, str) else res


def test_delete_allows_are_scoped_to_resource_arns():
    allows = [s for s in POLICY["Statement"]
              if s["Effect"] == "Allow" and _actions(s) & DELETE_ACTIONS]
    assert {a for s in allows for a in _actions(s)} == DELETE_ACTIONS
    for s in allows:
        for arn in _resources(s):
            assert arn != "*"
            assert arn.startswith(("arn:aws:ec2:", "arn:aws:elasticloadbalancing:"))


def test_protect_tag_is_denied_for_every_delete_action():
    denies = [s for s in POLICY["Statement"] if s["Effect"] == "Deny"]
    assert len(denies) == 1
    deny = denies[0]
    assert _actions(deny) == DELETE_ACTIONS
    assert deny["Condition"] == {"StringEquals": {"aws:ResourceTag/cleanup-protect": "true"}}


def test_only_describe_actions_use_wildcard_resource():
    for s in POLICY["Statement"]:
        if s["Effect"] == "Allow" and "*" in _resources(s):
            assert all(":Describe" in a for a in _actions(s)), s["Sid"]

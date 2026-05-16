"""
checks.py — Core security check engine.
Each check returns a Finding dict with: id, title, severity, description, affected, passed.
"""

import re
from dataclasses import dataclass, field
from typing import Any


SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}


@dataclass
class Finding:
    id: str
    title: str
    severity: str        # CRITICAL | HIGH | MEDIUM | LOW | INFO
    description: str
    affected: list       # list of affected statement/resource strings
    passed: bool
    remediation: str = ""
    reference: str = ""


def _statements(config: dict) -> list:
    return config.get("Statement", [])


# ─────────────────────────────────────────────
# CHECK FUNCTIONS
# ─────────────────────────────────────────────

def check_wildcard_action(config: dict) -> Finding:
    """Detects Action: * (full admin access)."""
    affected = []
    for stmt in _statements(config):
        actions = stmt.get("Action", [])
        if isinstance(actions, str):
            actions = [actions]
        if "*" in actions and stmt.get("Effect") == "Allow":
            resource = stmt.get("Resource", "unknown")
            affected.append(f"Action:* on Resource:{resource}")

    return Finding(
        id="IAM-001",
        title="Wildcard Action (Action: *)",
        severity="CRITICAL",
        description=(
            "One or more statements grant ALL actions (*) to a resource. "
            "This is equivalent to full admin access and violates the principle of least privilege."
        ),
        affected=affected,
        passed=len(affected) == 0,
        remediation=(
            "Replace Action: * with only the specific actions required. "
            "For example, use ['s3:GetObject'] instead of '*' for read-only S3 access."
        ),
        reference="https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html#grant-least-privilege",
    )


def check_wildcard_resource(config: dict) -> Finding:
    """Detects Resource: * combined with sensitive actions."""
    sensitive_prefixes = {"iam:", "sts:", "kms:", "ec2:", "lambda:", "secretsmanager:"}
    affected = []
    for stmt in _statements(config):
        resource = stmt.get("Resource", "")
        actions = stmt.get("Action", [])
        if isinstance(actions, str):
            actions = [actions]
        if resource == "*" and stmt.get("Effect") == "Allow":
            sensitive = [a for a in actions if any(a.startswith(p) for p in sensitive_prefixes) or a == "*"]
            if sensitive:
                affected.append(f"Actions {sensitive} on Resource:*")

    return Finding(
        id="IAM-002",
        title="Wildcard Resource with Sensitive Actions",
        severity="HIGH",
        description=(
            "Sensitive AWS actions (IAM, STS, KMS, EC2, Lambda, SecretsManager) are applied "
            "to Resource: *, meaning they apply to ALL resources in the account."
        ),
        affected=affected,
        passed=len(affected) == 0,
        remediation=(
            "Scope Resource to specific ARNs. Example: "
            "'arn:aws:s3:::my-bucket/*' instead of '*'."
        ),
        reference="https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_resource.html",
    )


def check_public_principal(config: dict) -> Finding:
    """Detects Principal: * (anonymous/public access)."""
    affected = []
    for stmt in _statements(config):
        principal = stmt.get("Principal", None)
        effect = stmt.get("Effect", "")
        if principal == "*" and effect == "Allow":
            actions = stmt.get("Action", [])
            if isinstance(actions, str):
                actions = [actions]
            affected.append(f"Principal:* allowed actions: {actions}")

    return Finding(
        id="S3-001",
        title="Public Principal (Principal: *)",
        severity="CRITICAL",
        description=(
            "One or more statements allow access from ANY principal (anonymous public). "
            "This is the most common cause of S3 data breaches."
        ),
        affected=affected,
        passed=len(affected) == 0,
        remediation=(
            "Remove Principal: * from Allow statements. "
            "Use specific IAM roles/users or apply aws:SourceAccount conditions. "
            "Enable S3 Block Public Access at the account level."
        ),
        reference="https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html",
    )


def check_missing_mfa_condition(config: dict) -> Finding:
    """Checks if sensitive actions lack MFA enforcement."""
    sensitive_prefixes = {"iam:", "sts:AssumeRole", "*"}
    affected = []
    for stmt in _statements(config):
        actions = stmt.get("Action", [])
        if isinstance(actions, str):
            actions = [actions]
        is_sensitive = any(
            a == "*" or a.startswith("iam:") or a == "sts:AssumeRole"
            for a in actions
        )
        if is_sensitive and stmt.get("Effect") == "Allow":
            conditions = stmt.get("Condition", {})
            mfa_present = (
                conditions.get("Bool", {}).get("aws:MultiFactorAuthPresent") == "true"
                or conditions.get("BoolIfExists", {}).get("aws:MultiFactorAuthPresent") == "true"
            )
            if not mfa_present:
                affected.append(f"Actions {actions} — no MFA condition")

    return Finding(
        id="IAM-003",
        title="Sensitive Actions Missing MFA Condition",
        severity="HIGH",
        description=(
            "Sensitive IAM or STS actions are permitted without requiring MFA. "
            "Without MFA enforcement, a compromised access key grants full control."
        ),
        affected=affected,
        passed=len(affected) == 0,
        remediation=(
            "Add a Condition block: "
            '{"Bool": {"aws:MultiFactorAuthPresent": "true"}} '
            "to all statements involving IAM, STS, or admin-level actions."
        ),
        reference="https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_mfa_configure-api-require.html",
    )


def check_allow_s3_write_public(config: dict) -> Finding:
    """Detects public write access to S3."""
    write_actions = {"s3:PutObject", "s3:DeleteObject", "s3:PutBucketPolicy", "*"}
    affected = []
    for stmt in _statements(config):
        principal = stmt.get("Principal", "")
        effect = stmt.get("Effect", "")
        actions = stmt.get("Action", [])
        if isinstance(actions, str):
            actions = [actions]
        if principal == "*" and effect == "Allow":
            dangerous = [a for a in actions if a in write_actions]
            if dangerous:
                resource = stmt.get("Resource", "unknown")
                affected.append(f"Public write actions {dangerous} on {resource}")

    return Finding(
        id="S3-002",
        title="Public S3 Write Access",
        severity="CRITICAL",
        description=(
            "S3 write or delete actions are allowed for any public principal. "
            "This allows anyone on the internet to upload, overwrite, or delete objects."
        ),
        affected=affected,
        passed=len(affected) == 0,
        remediation=(
            "Remove PutObject/DeleteObject from public-facing policies. "
            "If uploads are needed, use pre-signed URLs with expiry instead of bucket policies."
        ),
        reference="https://docs.aws.amazon.com/AmazonS3/latest/userguide/PresignedUrlUploadObject.html",
    )


def check_missing_condition_block(config: dict) -> Finding:
    """Flags Allow statements with no Condition constraints."""
    affected = []
    for i, stmt in enumerate(_statements(config)):
        if stmt.get("Effect") == "Allow" and not stmt.get("Condition"):
            actions = stmt.get("Action", [])
            if isinstance(actions, str):
                actions = [actions]
            affected.append(f"Statement {i+1} — Actions: {actions} — no Condition block")

    return Finding(
        id="IAM-004",
        title="Allow Statements Without Conditions",
        severity="MEDIUM",
        description=(
            "One or more Allow statements have no Condition block. "
            "Adding conditions (IP restrictions, MFA, VPC source) significantly reduces attack surface."
        ),
        affected=affected,
        passed=len(affected) == 0,
        remediation=(
            "Add conditions such as aws:SourceIp, aws:MultiFactorAuthPresent, "
            "or aws:SourceVpc to limit where and how access is granted."
        ),
        reference="https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_condition.html",
    )


def check_old_policy_version(config: dict) -> Finding:
    """Checks if policy uses latest language version."""
    version = config.get("Version", "")
    passed = version == "2012-10-17"
    return Finding(
        id="IAM-005",
        title="Outdated Policy Language Version",
        severity="LOW",
        description=(
            f"Policy Version is '{version}'. The current recommended version is '2012-10-17', "
            "which enables policy variables and modern features."
        ),
        affected=[] if passed else [f"Version: '{version}'"],
        passed=passed,
        remediation='Set "Version": "2012-10-17" at the top of your policy document.',
        reference="https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_version.html",
    )


# ─────────────────────────────────────────────
# RUNNER
# ─────────────────────────────────────────────

def run_all_checks(config: dict) -> list[Finding]:
    check_fns = [
        check_wildcard_action,
        check_wildcard_resource,
        check_public_principal,
        check_missing_mfa_condition,
        check_allow_s3_write_public,
        check_missing_condition_block,
        check_old_policy_version,
    ]
    findings = [fn(config) for fn in check_fns]
    findings.sort(key=lambda f: SEVERITY_ORDER.get(f.severity, 99))
    return findings

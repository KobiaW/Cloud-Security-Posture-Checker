"""
tests/test_checks.py — Unit tests for the security check engine.
Run with: pytest tests/
"""

import pytest
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from app.checks import (
    check_wildcard_action,
    check_wildcard_resource,
    check_public_principal,
    check_missing_mfa_condition,
    check_allow_s3_write_public,
    check_missing_condition_block,
    check_old_policy_version,
    run_all_checks,
)


# ─── Fixtures ────────────────────────────────────────────────────────────────

@pytest.fixture
def wildcard_policy():
    return {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Action": "*", "Resource": "*"}
        ],
    }

@pytest.fixture
def secure_policy():
    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["s3:GetObject"],
                "Resource": "arn:aws:s3:::my-bucket/reports/*",
                "Principal": {"AWS": "arn:aws:iam::123456789012:role/ReadRole"},
                "Condition": {
                    "Bool": {"aws:MultiFactorAuthPresent": "true"}
                },
            }
        ],
    }

@pytest.fixture
def public_s3_policy():
    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": "*",
                "Action": ["s3:GetObject", "s3:PutObject"],
                "Resource": "arn:aws:s3:::public-bucket/*",
            }
        ],
    }


# ─── Tests ───────────────────────────────────────────────────────────────────

class TestWildcardAction:
    def test_fails_on_wildcard(self, wildcard_policy):
        finding = check_wildcard_action(wildcard_policy)
        assert not finding.passed
        assert finding.severity == "CRITICAL"

    def test_passes_on_specific_actions(self, secure_policy):
        finding = check_wildcard_action(secure_policy)
        assert finding.passed

    def test_correct_check_id(self, wildcard_policy):
        finding = check_wildcard_action(wildcard_policy)
        assert finding.id == "IAM-001"


class TestWildcardResource:
    def test_detects_sensitive_action_on_star_resource(self):
        policy = {
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Action": ["iam:CreateUser"], "Resource": "*"}
            ],
        }
        finding = check_wildcard_resource(policy)
        assert not finding.passed
        assert finding.severity == "HIGH"

    def test_passes_on_scoped_resource(self, secure_policy):
        finding = check_wildcard_resource(secure_policy)
        assert finding.passed


class TestPublicPrincipal:
    def test_detects_public_principal(self, public_s3_policy):
        finding = check_public_principal(public_s3_policy)
        assert not finding.passed
        assert finding.severity == "CRITICAL"

    def test_passes_specific_principal(self, secure_policy):
        finding = check_public_principal(secure_policy)
        assert finding.passed


class TestMissingMFA:
    def test_detects_missing_mfa_on_iam_actions(self):
        policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": ["iam:CreateUser", "iam:DeleteUser"],
                    "Resource": "*",
                }
            ],
        }
        finding = check_missing_mfa_condition(policy)
        assert not finding.passed

    def test_passes_when_mfa_present(self, secure_policy):
        finding = check_missing_mfa_condition(secure_policy)
        assert finding.passed


class TestPublicS3Write:
    def test_detects_public_write(self, public_s3_policy):
        finding = check_allow_s3_write_public(public_s3_policy)
        assert not finding.passed
        assert finding.severity == "CRITICAL"

    def test_passes_on_read_only(self):
        policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": "*",
                    "Action": ["s3:GetObject"],
                    "Resource": "arn:aws:s3:::public-bucket/*",
                }
            ],
        }
        finding = check_allow_s3_write_public(policy)
        assert finding.passed


class TestMissingCondition:
    def test_flags_unconditioned_allow(self, wildcard_policy):
        finding = check_missing_condition_block(wildcard_policy)
        assert not finding.passed
        assert finding.severity == "MEDIUM"

    def test_passes_when_condition_present(self, secure_policy):
        finding = check_missing_condition_block(secure_policy)
        assert finding.passed


class TestPolicyVersion:
    def test_fails_on_old_version(self):
        policy = {"Version": "2008-10-17", "Statement": []}
        finding = check_old_policy_version(policy)
        assert not finding.passed

    def test_passes_on_correct_version(self):
        policy = {"Version": "2012-10-17", "Statement": []}
        finding = check_old_policy_version(policy)
        assert finding.passed

    def test_fails_on_missing_version(self):
        policy = {"Statement": []}
        finding = check_old_policy_version(policy)
        assert not finding.passed


class TestRunAllChecks:
    def test_returns_all_findings(self, wildcard_policy):
        findings = run_all_checks(wildcard_policy)
        assert len(findings) == 7

    def test_sorted_by_severity(self, wildcard_policy):
        findings = run_all_checks(wildcard_policy)
        severities = [f.severity for f in findings if not f.passed]
        order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        assert severities == sorted(severities, key=lambda s: order.get(s, 99))

    def test_secure_policy_all_pass(self, secure_policy):
        findings = run_all_checks(secure_policy)
        failed = [f for f in findings if not f.passed]
        assert len(failed) == 0

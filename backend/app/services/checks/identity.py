"""Identity / IAM baseline checks."""

import csv
import io
import time
from datetime import datetime, timezone

from .base import CRITICAL, HIGH, LOW, MEDIUM, CheckContext, Finding, finding

CATEGORY = "Identity"


def _credential_report(iam) -> list[dict]:
    """Generate (if needed) and parse the IAM credential report into rows."""
    for _ in range(10):
        try:
            resp = iam.get_credential_report()
            content = resp["Content"].decode("utf-8")
            reader = csv.DictReader(io.StringIO(content))
            return list(reader)
        except iam.exceptions.CredentialReportNotPresentException:
            iam.generate_credential_report()
            time.sleep(2)
        except iam.exceptions.CredentialReportExpiredException:
            iam.generate_credential_report()
            time.sleep(2)
        except iam.exceptions.CredentialReportNotReadyException:
            time.sleep(2)
    return []


def _age_days(value: str) -> float | None:
    if not value or value in ("N/A", "no_information", "not_supported"):
        return None
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
        return (datetime.now(timezone.utc) - dt).total_seconds() / 86400
    except ValueError:
        return None


def run(ctx: CheckContext) -> list[Finding]:
    findings: list[Finding] = []
    iam = ctx.client("iam")
    rows = _credential_report(iam)

    findings += _root_checks(ctx, iam, rows)
    findings += _user_key_checks(ctx, rows)
    findings += _password_policy(ctx, iam)
    findings += _human_users(ctx, iam)
    return findings


def _root_checks(ctx, iam, rows) -> list[Finding]:
    out: list[Finding] = []
    root_arn = f"arn:aws:iam::{ctx.account_id}:root"

    # Root MFA via account summary.
    summary = iam.get_account_summary().get("SummaryMap", {})
    if summary.get("AccountMFAEnabled", 0) != 1:
        out.append(finding(
            ctx, category=CATEGORY, severity=CRITICAL,
            title="Root account does not have MFA enabled",
            resource=root_arn,
            description="The AWS account root user does not have multi-factor "
                        "authentication enabled.",
            remediation="Enable a hardware or virtual MFA device on the root user.",
            source="iam_root_mfa", raw={"SummaryMap": summary},
        ))

    root = next((r for r in rows if r.get("user") == "<root_account>"), None)
    if root:
        if root.get("access_key_1_active") == "true" or root.get("access_key_2_active") == "true":
            out.append(finding(
                ctx, category=CATEGORY, severity=CRITICAL,
                title="Root account has active access keys",
                resource=root_arn,
                description="The root user has one or more active access keys. Root "
                            "access keys grant unrestricted account access.",
                remediation="Delete all root account access keys and use IAM roles/users instead.",
                source="iam_root_access_keys", raw=root,
            ))
    return out


def _user_key_checks(ctx, rows) -> list[Finding]:
    out: list[Finding] = []
    for r in rows:
        user = r.get("user", "")
        if user == "<root_account>":
            continue
        arn = r.get("arn", user)

        k1 = r.get("access_key_1_active") == "true"
        k2 = r.get("access_key_2_active") == "true"

        # Two active keys.
        if k1 and k2:
            out.append(finding(
                ctx, category=CATEGORY, severity=MEDIUM,
                title=f"User '{user}' has two active access keys",
                resource=arn,
                description="The user has two active access keys, doubling the "
                            "credential exposure surface.",
                remediation="Remove the unused access key; a user should have at most one.",
                source="iam_user_two_keys", raw=r,
            ))

        # Keys older than 90 days.
        for idx in ("1", "2"):
            if r.get(f"access_key_{idx}_active") != "true":
                continue
            age = _age_days(r.get(f"access_key_{idx}_last_rotated", ""))
            if age is not None and age > 90:
                out.append(finding(
                    ctx, category=CATEGORY, severity=MEDIUM,
                    title=f"User '{user}' access key {idx} is {int(age)} days old",
                    resource=f"{arn}#key{idx}",
                    description=f"Access key {idx} has not been rotated in {int(age)} days.",
                    remediation="Rotate access keys at least every 90 days.",
                    source="iam_key_age_90", raw=r,
                ))

        # Console access without MFA.
        if r.get("password_enabled") == "true" and r.get("mfa_active") != "true":
            out.append(finding(
                ctx, category=CATEGORY, severity=HIGH,
                title=f"User '{user}' has console access without MFA",
                resource=arn,
                description="The user can sign in to the console with a password but "
                            "has no MFA device.",
                remediation="Require MFA for all users with console access.",
                source="iam_console_no_mfa", raw=r,
            ))
    return out


def _password_policy(ctx, iam) -> list[Finding]:
    try:
        policy = iam.get_account_password_policy().get("PasswordPolicy", {})
    except iam.exceptions.NoSuchEntityException:
        return [finding(
            ctx, category=CATEGORY, severity=MEDIUM,
            title="No IAM account password policy is set",
            resource=f"arn:aws:iam::{ctx.account_id}:account-password-policy",
            description="The account has no password policy, so weak passwords are permitted.",
            remediation="Configure a strong password policy (length >= 14, complexity, rotation).",
            source="iam_password_policy", raw={},
        )]

    weak = []
    if policy.get("MinimumPasswordLength", 0) < 14:
        weak.append("minimum length below 14")
    if not policy.get("RequireSymbols"):
        weak.append("symbols not required")
    if not policy.get("RequireNumbers"):
        weak.append("numbers not required")
    if not policy.get("RequireUppercaseCharacters"):
        weak.append("uppercase not required")
    if not policy.get("RequireLowercaseCharacters"):
        weak.append("lowercase not required")

    if weak:
        return [finding(
            ctx, category=CATEGORY, severity=LOW,
            title="IAM password policy is weak",
            resource=f"arn:aws:iam::{ctx.account_id}:account-password-policy",
            description="Password policy weaknesses: " + ", ".join(weak) + ".",
            remediation="Strengthen the password policy to meet CIS benchmarks.",
            source="iam_password_policy", raw=policy,
        )]
    return []


def _human_users(ctx, iam) -> list[Finding]:
    """Surface IAM users whose names look like email addresses (likely humans)."""
    out: list[Finding] = []
    paginator = iam.get_paginator("list_users")
    humans = []
    for page in paginator.paginate():
        for u in page.get("Users", []):
            if "@" in u.get("UserName", ""):
                humans.append(u["UserName"])
    if humans:
        out.append(finding(
            ctx, category=CATEGORY, severity=LOW,
            title=f"{len(humans)} IAM user(s) appear to be human (email-format names)",
            resource=f"arn:aws:iam::{ctx.account_id}:user/*",
            description="Human IAM users were detected: " + ", ".join(humans) +
                        ". Humans should authenticate via SSO/Identity Center, not IAM users.",
            remediation="Migrate human users to AWS IAM Identity Center (SSO).",
            source="iam_human_users", raw={"users": humans},
        ))
    return out

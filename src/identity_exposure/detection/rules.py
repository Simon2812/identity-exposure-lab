"""Detection rules for risky Active Directory and Entra ID conditions."""

from __future__ import annotations

from identity_exposure.graph import find_paths_to_privilege
from identity_exposure.models import Finding, IdentitySnapshot, Severity


HIGH_RISK_APP_PERMISSIONS = {
    "Directory.ReadWrite.All",
    "RoleManagement.ReadWrite.Directory",
    "AppRoleAssignment.ReadWrite.All",
    "User.ReadWrite.All",
    "Group.ReadWrite.All",
}


def analyze_snapshot(snapshot: IdentitySnapshot) -> list[Finding]:
    """Run all identity exposure rules and return findings by severity."""
    findings: list[Finding] = []
    # Each rule is deliberately small and composable so new identity checks can
    # be added without changing ingestion or report generation.
    findings.extend(_disabled_privileged_accounts(snapshot))
    findings.extend(_stale_privileged_accounts(snapshot))
    findings.extend(_privileged_without_mfa(snapshot))
    findings.extend(_password_never_expires(snapshot))
    findings.extend(_kerberoastable_privileged_users(snapshot))
    findings.extend(_guest_privilege(snapshot))
    findings.extend(_risky_app_permissions(snapshot))
    findings.extend(_stale_app_secrets(snapshot))
    findings.extend(_conditional_access_gaps(snapshot))
    findings.extend(_privilege_paths(snapshot))
    return sorted(findings, key=lambda finding: _severity_rank(finding.severity), reverse=True)


def _disabled_privileged_accounts(snapshot: IdentitySnapshot) -> list[Finding]:
    return [
        Finding(
            rule_id="ID-001",
            title="Disabled privileged account still assigned privilege",
            severity=Severity.MEDIUM,
            description=f"{user.display_name} is disabled but still marked as privileged.",
            affected_object=user.user_principal_name,
            evidence=[f"user_id={user.id}", f"source={user.source.value}"],
            remediation="Remove privileged assignments from disabled accounts.",
        )
        for user in snapshot.users
        if user.privileged and not user.enabled
    ]


def _stale_privileged_accounts(snapshot: IdentitySnapshot) -> list[Finding]:
    findings = []
    for user in snapshot.users:
        # The sample threshold is conservative for a demo dataset: stale admin
        # accounts should be reviewed before they become forgotten backdoors.
        if user.privileged and user.last_sign_in_days is not None and user.last_sign_in_days >= 45:
            findings.append(
                Finding(
                    rule_id="ID-002",
                    title="Stale privileged identity",
                    severity=Severity.HIGH,
                    description=(
                        f"{user.display_name} is privileged and has not signed in for "
                        f"{user.last_sign_in_days} days."
                    ),
                    affected_object=user.user_principal_name,
                    evidence=[f"last_sign_in_days={user.last_sign_in_days}"],
                    remediation="Review whether the account still needs privileged access.",
                )
            )
    return findings


def _privileged_without_mfa(snapshot: IdentitySnapshot) -> list[Finding]:
    findings = []
    for user in snapshot.users:
        if user.privileged and user.mfa_enabled is False:
            findings.append(
                Finding(
                    rule_id="ID-003",
                    title="Privileged Entra ID account without MFA",
                    severity=Severity.CRITICAL,
                    description=f"{user.display_name} is privileged but MFA is not enabled.",
                    affected_object=user.user_principal_name,
                    evidence=[f"user_id={user.id}", "mfa_enabled=false"],
                    remediation="Require phishing-resistant MFA for privileged identities.",
                )
            )
    return findings


def _password_never_expires(snapshot: IdentitySnapshot) -> list[Finding]:
    findings = []
    for user in snapshot.users:
        if user.password_never_expires:
            # Privileged accounts get a higher severity because the same policy
            # gap creates more blast radius when the identity has admin access.
            severity = Severity.HIGH if user.privileged else Severity.MEDIUM
            findings.append(
                Finding(
                    rule_id="ID-004",
                    title="Password never expires",
                    severity=severity,
                    description=f"{user.display_name} has password_never_expires enabled.",
                    affected_object=user.user_principal_name,
                    evidence=[f"source={user.source.value}", f"privileged={user.privileged}"],
                    remediation="Review password policy and migrate service use cases to managed identities.",
                )
            )
    return findings


def _kerberoastable_privileged_users(snapshot: IdentitySnapshot) -> list[Finding]:
    findings = []
    for user in snapshot.users:
        if user.spn_count > 0:
            severity = Severity.CRITICAL if user.privileged else Severity.HIGH
            findings.append(
                Finding(
                    rule_id="ID-005",
                    title="Kerberoastable AD account",
                    severity=severity,
                    description=f"{user.display_name} has {user.spn_count} SPN value(s).",
                    affected_object=user.user_principal_name,
                    evidence=[f"spn_count={user.spn_count}", f"privileged={user.privileged}"],
                    remediation="Use gMSA/managed service accounts and remove unnecessary SPNs.",
                )
            )
    return findings


def _guest_privilege(snapshot: IdentitySnapshot) -> list[Finding]:
    return [
        Finding(
            rule_id="ID-006",
            title="Guest identity has privileged access",
            severity=Severity.CRITICAL,
            description=f"Guest user {user.display_name} is privileged.",
            affected_object=user.user_principal_name,
            evidence=[f"user_id={user.id}", "user_type=Guest"],
            remediation="Remove privileged roles from guest accounts unless explicitly approved.",
        )
        for user in snapshot.users
        if user.user_type.lower() == "guest" and user.privileged
    ]


def _risky_app_permissions(snapshot: IdentitySnapshot) -> list[Finding]:
    findings = []
    for app in snapshot.applications:
        risky_permissions = sorted(set(app.app_permissions).intersection(HIGH_RISK_APP_PERMISSIONS))
        if risky_permissions:
            # Role management permissions are treated as critical because they
            # can be used to alter privileged assignments across the tenant.
            severity = (
                Severity.CRITICAL
                if "RoleManagement.ReadWrite.Directory" in risky_permissions
                else Severity.HIGH
            )
            findings.append(
                Finding(
                    rule_id="ID-007",
                    title="Application has high-risk Entra permissions",
                    severity=severity,
                    description=f"{app.display_name} has high-impact application permissions.",
                    affected_object=app.display_name,
                    evidence=risky_permissions,
                    remediation="Apply least privilege and require admin consent review for high-risk permissions.",
                )
            )
    return findings


def _stale_app_secrets(snapshot: IdentitySnapshot) -> list[Finding]:
    findings = []
    for app in snapshot.applications:
        if app.secret_age_days is not None and app.secret_age_days >= 180:
            findings.append(
                Finding(
                    rule_id="ID-008",
                    title="Stale application secret",
                    severity=Severity.MEDIUM,
                    description=f"{app.display_name} has a secret aged {app.secret_age_days} days.",
                    affected_object=app.display_name,
                    evidence=[f"secret_age_days={app.secret_age_days}"],
                    remediation="Rotate secrets and prefer certificate or workload identity federation where possible.",
                )
            )
    return findings


def _conditional_access_gaps(snapshot: IdentitySnapshot) -> list[Finding]:
    enabled_mfa_all = [
        policy
        for policy in snapshot.conditional_access_policies
        if policy.state.lower() == "enabled" and policy.requires_mfa and policy.includes_all_users
    ]
    if enabled_mfa_all:
        return []
    # The evidence lists every policy so the report explains whether the gap is
    # missing coverage, disabled state, or a policy scoped too narrowly.
    return [
        Finding(
            rule_id="ID-009",
            title="No enabled tenant-wide MFA Conditional Access policy",
            severity=Severity.HIGH,
            description="No enabled Conditional Access policy requires MFA for all users.",
            affected_object="conditional_access",
            evidence=[
                f"{policy.display_name}: state={policy.state}, requires_mfa={policy.requires_mfa}, "
                f"includes_all_users={policy.includes_all_users}"
                for policy in snapshot.conditional_access_policies
            ],
            remediation="Create or enable a Conditional Access policy requiring MFA for all users with approved exclusions.",
        )
    ]


def _privilege_paths(snapshot: IdentitySnapshot) -> list[Finding]:
    findings = []
    for path in find_paths_to_privilege(snapshot):
        # Path findings are produced by the graph layer; this rule converts the
        # path into report language and remediation guidance.
        findings.append(
            Finding(
                rule_id="ID-010",
                title="Non-privileged identity has path to privileged object",
                severity=Severity.HIGH,
                description=f"Identity {path.start} can reach privileged target {path.target}.",
                affected_object=path.start,
                evidence=[
                    " -> ".join(path.nodes),
                    " relationships=" + " -> ".join(path.relationships),
                ],
                remediation="Review group nesting, app ownership and high-risk app permissions.",
            )
        )
    return findings


def _severity_rank(severity: Severity) -> int:
    return {
        Severity.LOW: 1,
        Severity.MEDIUM: 2,
        Severity.HIGH: 3,
        Severity.CRITICAL: 4,
    }[severity]

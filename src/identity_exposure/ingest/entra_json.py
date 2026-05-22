"""JSON parser for Entra ID users, applications and access policies."""

from __future__ import annotations

import json
from pathlib import Path

from identity_exposure.models import (
    Application,
    ConditionalAccessPolicy,
    Group,
    IdentitySource,
    User,
)


def load_entra_export(
    path: Path,
) -> tuple[list[User], list[Group], list[Application], list[ConditionalAccessPolicy]]:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    # The loader maps camelCase export fields into the internal snake_case
    # model once, keeping detection rules independent from source formatting.
    users = [
        User(
            id=item["id"],
            display_name=item["displayName"],
            user_principal_name=item["userPrincipalName"],
            source=IdentitySource.ENTRA,
            enabled=item.get("accountEnabled", True),
            privileged=item.get("privileged", False),
            mfa_enabled=item.get("mfaEnabled"),
            last_sign_in_days=item.get("lastSignInDays"),
            user_type=item.get("userType", "Member"),
        )
        for item in data.get("users", [])
    ]
    groups = [
        Group(
            id=item["id"],
            display_name=item["displayName"],
            source=IdentitySource.ENTRA,
            privileged=item.get("privileged", False),
            members=item.get("members", []),
        )
        for item in data.get("groups", [])
    ]
    applications = [
        # Application ownership and permissions feed the exposure graph, so
        # missing arrays are treated as empty rather than invalid input.
        Application(
            id=item["id"],
            display_name=item["displayName"],
            owners=item.get("owners", []),
            app_permissions=item.get("appPermissions", []),
            secret_age_days=item.get("secretAgeDays"),
        )
        for item in data.get("applications", [])
    ]
    policies = [
        # Conditional Access fields are optional in the sample format; defaults
        # make incomplete exports explicit but still analyzable.
        ConditionalAccessPolicy(
            id=item["id"],
            display_name=item["displayName"],
            state=item.get("state", "disabled"),
            requires_mfa=item.get("requiresMfa", False),
            includes_all_users=item.get("includesAllUsers", False),
            excludes_guests=item.get("excludesGuests", False),
        )
        for item in data.get("conditionalAccessPolicies", [])
    ]
    return users, groups, applications, policies

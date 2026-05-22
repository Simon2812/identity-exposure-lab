"""CSV parser for Active Directory users, groups and memberships."""

from __future__ import annotations

import csv
from pathlib import Path

from identity_exposure.models import Group, IdentitySource, User


def load_ad_users(path: Path) -> list[User]:
    users: list[User] = []
    with Path(path).open(newline="", encoding="utf-8") as file:
        for row in csv.DictReader(file):
            # CSV exports often represent booleans as text; normalize them here
            # so detection rules can work with typed values only.
            users.append(
                User(
                    id=row["id"],
                    display_name=row["display_name"],
                    user_principal_name=row["user_principal_name"],
                    source=IdentitySource.AD,
                    enabled=_bool(row.get("enabled", "true")),
                    privileged=_bool(row.get("privileged", "false")),
                    password_never_expires=_bool(row.get("password_never_expires", "false")),
                    spn_count=int(row.get("spn_count") or 0),
                    last_sign_in_days=_int_or_none(row.get("last_sign_in_days")),
                    user_type="Member",
                )
            )
    return users


def load_ad_groups(path: Path) -> list[Group]:
    groups: list[Group] = []
    with Path(path).open(newline="", encoding="utf-8") as file:
        for row in csv.DictReader(file):
            # The sample format stores group members as a semicolon-separated
            # list, matching the way many quick directory exports are shared.
            members = [
                member.strip() for member in row.get("members", "").split(";") if member.strip()
            ]
            groups.append(
                Group(
                    id=row["id"],
                    display_name=row["display_name"],
                    source=IdentitySource.AD,
                    privileged=_bool(row.get("privileged", "false")),
                    members=members,
                )
            )
    return groups


def _bool(value: str | bool | None) -> bool:
    if isinstance(value, bool):
        return value
    return str(value or "").strip().lower() in {"true", "1", "yes", "y"}


def _int_or_none(value: str | None) -> int | None:
    if value is None or value == "":
        return None
    return int(value)

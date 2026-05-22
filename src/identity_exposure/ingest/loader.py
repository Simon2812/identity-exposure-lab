"""Snapshot loader that combines supported identity data sources."""

from __future__ import annotations

from pathlib import Path

from identity_exposure.ingest.ad_csv import load_ad_groups, load_ad_users
from identity_exposure.ingest.entra_json import load_entra_export
from identity_exposure.models import IdentitySnapshot


def load_snapshot(ad_users: Path, ad_groups: Path, entra_export: Path) -> IdentitySnapshot:
    ad_user_items = load_ad_users(ad_users)
    ad_group_items = load_ad_groups(ad_groups)
    entra_users, entra_groups, applications, policies = load_entra_export(entra_export)
    return IdentitySnapshot(
        users=ad_user_items + entra_users,
        groups=ad_group_items + entra_groups,
        applications=applications,
        conditional_access_policies=policies,
    )

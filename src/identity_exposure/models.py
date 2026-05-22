"""Domain models used throughout identity exposure analysis."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class Severity(str, Enum):
    """Ordered severity labels used to prioritize findings."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class IdentitySource(str, Enum):
    """Identity provider labels supported by the analysis model."""

    AD = "ad"
    ENTRA = "entra"


@dataclass(frozen=True)
class User:
    """Normalized user account from Active Directory or Entra ID."""

    id: str
    display_name: str
    user_principal_name: str
    source: IdentitySource
    enabled: bool = True
    privileged: bool = False
    mfa_enabled: bool | None = None
    password_never_expires: bool = False
    spn_count: int = 0
    last_sign_in_days: int | None = None
    user_type: str = "Member"


@dataclass(frozen=True)
class Group:
    """Identity group with membership and privilege metadata."""

    id: str
    display_name: str
    source: IdentitySource
    privileged: bool = False
    members: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class Application:
    """Entra application registration with ownership and permission details."""

    id: str
    display_name: str
    owners: list[str]
    app_permissions: list[str]
    secret_age_days: int | None = None


@dataclass(frozen=True)
class ConditionalAccessPolicy:
    """Relevant Conditional Access policy attributes for exposure checks."""

    id: str
    display_name: str
    state: str
    requires_mfa: bool
    includes_all_users: bool
    excludes_guests: bool = False


@dataclass(frozen=True)
class IdentitySnapshot:
    """Complete tenant and directory snapshot used as analysis input."""

    users: list[User]
    groups: list[Group]
    applications: list[Application]
    conditional_access_policies: list[ConditionalAccessPolicy]


@dataclass(frozen=True)
class Finding:
    """Security finding with severity, evidence and affected object context."""

    rule_id: str
    title: str
    severity: Severity
    description: str
    evidence: list[str]
    affected_object: str | None = None
    remediation: str | None = None


@dataclass(frozen=True)
class GraphEdge:
    """Directed relationship between two identity graph nodes."""

    source: str
    target: str
    relationship: str


@dataclass(frozen=True)
class ExposurePath:
    """Reachable path from a starting identity to a privileged target."""

    start: str
    target: str
    relationships: list[str]
    nodes: list[str]

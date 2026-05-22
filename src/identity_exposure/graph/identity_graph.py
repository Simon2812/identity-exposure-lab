"""Graph construction and traversal utilities for identity relationships."""

from __future__ import annotations

from collections import defaultdict, deque

from identity_exposure.models import ExposurePath, GraphEdge, IdentitySnapshot


def build_edges(snapshot: IdentitySnapshot) -> list[GraphEdge]:
    edges: list[GraphEdge] = []
    for group in snapshot.groups:
        for member_id in group.members:
            # Group membership is directional: the member can inherit access
            # from the group, not the other way around.
            edges.append(GraphEdge(source=member_id, target=group.id, relationship="member_of"))
    for app in snapshot.applications:
        for owner_id in app.owners:
            edges.append(GraphEdge(source=owner_id, target=app.id, relationship="owns_app"))
        for permission in app.app_permissions:
            # Application permissions become graph targets so ownership paths
            # can expose indirect access to high-impact cloud permissions.
            edges.append(GraphEdge(source=app.id, target=permission, relationship="has_permission"))
    return edges


def find_paths_to_privilege(snapshot: IdentitySnapshot, max_depth: int = 4) -> list[ExposurePath]:
    # Privileged targets include explicit privileged objects plus selected app
    # permissions that are powerful enough to matter on their own.
    privileged_targets = {group.id for group in snapshot.groups if group.privileged}
    privileged_targets.update(user.id for user in snapshot.users if user.privileged)
    privileged_targets.update(
        permission
        for app in snapshot.applications
        for permission in app.app_permissions
        if permission in {"Directory.ReadWrite.All", "RoleManagement.ReadWrite.Directory"}
    )

    adjacency: dict[str, list[tuple[str, str]]] = defaultdict(list)
    for edge in build_edges(snapshot):
        adjacency[edge.source].append((edge.target, edge.relationship))

    paths: list[ExposurePath] = []
    for user in snapshot.users:
        if user.privileged or not user.enabled:
            continue
        # Breadth-first search returns short, explainable exposure paths for
        # enabled non-privileged users without exploring the whole graph.
        queue = deque([(user.id, [user.id], [])])
        visited = {user.id}
        while queue:
            node, nodes, relationships = queue.popleft()
            if len(relationships) >= max_depth:
                continue
            for next_node, relationship in adjacency.get(node, []):
                if next_node in visited:
                    continue
                next_nodes = nodes + [next_node]
                next_relationships = relationships + [relationship]
                if next_node in privileged_targets:
                    # Stop at the first privileged target on this branch; the
                    # reported path should show the direct exposure chain.
                    paths.append(
                        ExposurePath(
                            start=user.id,
                            target=next_node,
                            nodes=next_nodes,
                            relationships=next_relationships,
                        )
                    )
                    continue
                visited.add(next_node)
                queue.append((next_node, next_nodes, next_relationships))
    return paths

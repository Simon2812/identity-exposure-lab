"""Graph analysis exports for privilege path discovery."""

from identity_exposure.graph.identity_graph import build_edges, find_paths_to_privilege

__all__ = ["build_edges", "find_paths_to_privilege"]

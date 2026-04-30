"""Structured JSON export for Pathdog results."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    import networkx as nx

    from .findings import Finding
    from .pathfinder import PathResult
    from .quickwins import QuickWin


def _display_name(G: "nx.DiGraph", nid: str) -> str:
    return G.nodes[nid].get("name", nid) if nid in G else nid


def _path_to_dict(G: "nx.DiGraph", path: "PathResult") -> dict:
    return {
        "hops": path.hops,
        "weight": path.total_weight,
        "nodes": [
            {
                "id": nid,
                "name": _display_name(G, nid),
                "kind": G.nodes[nid].get("kind", "") if nid in G else "",
            }
            for nid in path.nodes
        ],
        "edges": [
            {
                "src": edge["src"],
                "src_name": _display_name(G, edge["src"]),
                "dst": edge["dst"],
                "dst_name": _display_name(G, edge["dst"]),
                "relation": edge["relation"],
                "weight": edge["weight"],
                "relations": dict(edge.get("relations") or {}),
            }
            for edge in path.edges
        ],
    }


def _quickwins_to_dict(quickwins: dict[str, list["QuickWin"]] | None) -> dict:
    if not quickwins:
        return {}
    return {
        category: [
            {
                "node_id": item.node_id,
                "node_name": item.node_name,
                "node_kind": item.node_kind,
                "detail": item.detail,
                "commands": item.commands,
            }
            for item in items
        ]
        for category, items in quickwins.items()
    }


def _node_ref(G: "nx.DiGraph", nid: str | None) -> dict | None:
    if not nid:
        return None
    return {
        "id": nid,
        "name": _display_name(G, nid),
        "kind": G.nodes[nid].get("kind", "") if nid in G else "",
    }


def _node_visibility_to_dict(G: "nx.DiGraph", node_data: dict | None) -> dict | None:
    if not node_data:
        return None
    return {
        "node": _node_ref(G, node_data.get("node_id")),
        "target": _node_ref(G, node_data.get("target")),
        "outbound_paths": [
            _path_to_dict(G, path)
            for path in node_data.get("outbound_paths", [])
        ],
        "outbound_intermediate": [
            {
                "node": _node_ref(G, item["node"]),
                "score": item["score"],
                "path": _path_to_dict(G, item["path"]) if item.get("path") else None,
            }
            for item in node_data.get("outbound_intermediate", [])
        ],
        "inbound_sources": [
            {
                "node": _node_ref(G, item["node"]),
                "score": item["score"],
                "path": _path_to_dict(G, item["path"]) if item.get("path") else None,
            }
            for item in node_data.get("inbound_sources", [])
        ],
        "outbound_control": [
            {
                "dst": _node_ref(G, item["dst"]),
                "relation": item["relation"],
                "via_group": item["via_group"],
            }
            for item in node_data.get("outbound_control", [])
        ],
        "inbound_control": [
            {
                "src": _node_ref(G, item["src"]),
                "relation": item["relation"],
            }
            for item in node_data.get("inbound_control", [])
        ],
        "stats": node_data.get("stats"),
    }


def build_json_report(
    *,
    G: "nx.DiGraph",
    target: str | None = None,
    results: list[tuple[str, list["PathResult"]]] | None = None,
    stats: dict | None = None,
    intermediates: dict[str, list[dict]] | None = None,
    quickwins: dict[str, list["QuickWin"]] | None = None,
    pivots: list[dict] | None = None,
    findings: list["Finding"] | None = None,
    node_data: dict | None = None,
) -> dict:
    results = results or []
    intermediates = intermediates or {}
    pivots = pivots or []
    findings = findings or []

    return {
        "meta": {"generator": "pathdog", "schema": 1},
        "graph": {
            "nodes": G.number_of_nodes(),
            "edges": G.number_of_edges(),
            "stats": stats,
        },
        "target": {
            "id": target,
            "name": _display_name(G, target) if target else None,
        },
        "owned_results": [
            {
                "source": {
                    "id": source,
                    "name": _display_name(G, source),
                    "kind": G.nodes[source].get("kind", "") if source in G else "",
                },
                "paths": [_path_to_dict(G, path) for path in paths],
                "intermediate_targets": [
                    {
                        "node": item["node"],
                        "node_name": _display_name(G, item["node"]),
                        "score": item["score"],
                        "path": _path_to_dict(G, item["path"]) if item.get("path") else None,
                    }
                    for item in intermediates.get(source, [])
                ],
            }
            for source, paths in results
        ],
        # Internal pivot dicts use "path_to_da" (legacy: target was always DA);
        # the public JSON field is renamed "path_to_target" because -t can now
        # point anywhere. Same value, clearer name for consumers.
        "pivots": [
            {
                "node": item["node"],
                "node_name": _display_name(G, item["node"]),
                "vectors": item["vectors"],
                "vector_commands": item["vector_commands"],
                "score": item["score"],
                "path_to_target": _path_to_dict(G, item["path_to_da"]) if item.get("path_to_da") else None,
            }
            for item in pivots
        ],
        "quickwins": _quickwins_to_dict(quickwins),
        "findings": [finding.to_dict() for finding in findings],
        "node_visibility": _node_visibility_to_dict(G, node_data),
    }


def write_json_report(path: str, report: dict) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2, sort_keys=True)

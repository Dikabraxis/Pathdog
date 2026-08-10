"""Compatibility reporting for SharpHound archives and BloodHound edges."""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from functools import lru_cache
from importlib.resources import files

import networkx as nx

from .loader import CollectionMetadata
from .schema import (
    BLOODHOUND_SCHEMA_VERSION,
    KNOWN_BLOODHOUND_EDGES,
    SHARPHOUND_SCHEMA_VERSION,
    SUPPORTED_TRAVERSABLE_EDGES,
)

VALID_EDGES_SNAPSHOT_COMMIT = "ecccc9f"
VALID_EDGES_SNAPSHOT_DATE = "2026-08-07"

_KIND_TO_SCHEMA = {
    "aiacas": "AIACA",
    "certtemplates": "CertTemplate",
    "computers": "Computer",
    "containers": "Container",
    "domains": "Domain",
    "enterprisecas": "EnterpriseCA",
    "gpos": "GPO",
    "groups": "Group",
    "issuancepolicies": "IssuancePolicy",
    "ntauthstores": "NTAuthStore",
    "ous": "OU",
    "rootcas": "RootCA",
    "users": "User",
}


@dataclass(frozen=True)
class InvalidEdgePair:
    source_kind: str
    relation: str
    target_kind: str
    source: str
    target: str


@dataclass
class CompatibilityReport:
    bloodhound_schema: str = BLOODHOUND_SCHEMA_VERSION
    sharphound_schema: str = SHARPHOUND_SCHEMA_VERSION
    valid_edges_snapshot_commit: str = VALID_EDGES_SNAPSHOT_COMMIT
    valid_edges_snapshot_date: str = VALID_EDGES_SNAPSHOT_DATE
    objects: dict[str, int] = field(default_factory=dict)
    relationship_types: list[str] = field(default_factory=list)
    supported_attack_edges: list[str] = field(default_factory=list)
    known_context_edges: list[str] = field(default_factory=list)
    unsupported_attack_edges: list[str] = field(default_factory=list)
    unknown_edges: list[str] = field(default_factory=list)
    invalid_edge_pairs: list[InvalidEdgePair] = field(default_factory=list)
    collections: list[dict] = field(default_factory=list)
    collection_span_days: float | None = None

    @property
    def compatible(self) -> bool:
        # Pair validation is advisory: older, still-ingestible SharpHound
        # archives can contain legacy source/target combinations that the
        # latest valid_edges snapshot no longer emits. Unknown or unsupported
        # attack edges are the conditions that require operator review.
        return not self.unknown_edges and not self.unsupported_attack_edges

    def to_dict(self) -> dict:
        result = asdict(self)
        result["compatible"] = self.compatible
        return result


@lru_cache(maxsize=1)
def _valid_edge_triples() -> frozenset[tuple[str, str, str]]:
    resource = files("pathdog").joinpath("data", "valid_edges.json")
    schema = json.loads(resource.read_text(encoding="utf-8"))
    triples: set[tuple[str, str, str]] = set()
    for item in schema:
        source = item.get("source")
        target = item.get("target")
        edge_groups = item.get("edges", {})
        for edge_type in ("ingest", "post"):
            for relation in edge_groups.get(edge_type, []):
                triples.add((str(source), str(relation), str(target)))
    return frozenset(triples)


def _collection_span_days(
    collections: list[CollectionMetadata],
) -> float | None:
    timestamps = [
        timestamp
        for collection in collections
        for timestamp in collection.collection_times
    ]
    if len(timestamps) < 2:
        return None
    return round((max(timestamps) - min(timestamps)).total_seconds() / 86_400, 1)


def analyze_compatibility(
    graph: nx.DiGraph,
    collections: list[CollectionMetadata] | None = None,
) -> CompatibilityReport:
    relationship_types = set(graph.graph.get("relationship_types", []))
    unknown = set(graph.graph.get("unknown_edge_types", []))
    unsupported = set(graph.graph.get("unsupported_traversable_edge_types", []))
    legacy = set(graph.graph.get("legacy_context_edge_types", []))
    supported = relationship_types & SUPPORTED_TRAVERSABLE_EDGES
    context = (relationship_types & KNOWN_BLOODHOUND_EDGES) - supported - unsupported
    context |= legacy

    object_counts: dict[str, int] = {}
    for _, data in graph.nodes(data=True):
        kind = data.get("kind", "unknown")
        object_counts[kind] = object_counts.get(kind, 0) + 1

    valid = _valid_edge_triples()
    invalid: list[InvalidEdgePair] = []
    seen_invalid: set[tuple[str, str, str, str, str]] = set()
    for source, target, data in graph.edges(data=True):
        source_kind = _KIND_TO_SCHEMA.get(graph.nodes[source].get("kind", ""))
        target_kind = _KIND_TO_SCHEMA.get(graph.nodes[target].get("kind", ""))
        if not source_kind or not target_kind:
            continue
        relations = data.get("relations") or {data.get("relation", "Unknown"): 5}
        for relation in relations:
            if relation not in KNOWN_BLOODHOUND_EDGES:
                continue
            triple = (source_kind, relation, target_kind)
            if triple in valid:
                continue
            key = (*triple, source, target)
            if key in seen_invalid:
                continue
            seen_invalid.add(key)
            invalid.append(
                InvalidEdgePair(
                    source_kind=source_kind,
                    relation=relation,
                    target_kind=target_kind,
                    source=source,
                    target=target,
                )
            )

    collection_list = collections or []
    return CompatibilityReport(
        objects=dict(sorted(object_counts.items())),
        relationship_types=sorted(relationship_types),
        supported_attack_edges=sorted(supported),
        known_context_edges=sorted(context),
        unsupported_attack_edges=sorted(unsupported),
        unknown_edges=sorted(unknown),
        invalid_edge_pairs=invalid,
        collections=[collection.to_dict() for collection in collection_list],
        collection_span_days=_collection_span_days(collection_list),
    )


def render_compatibility(report: CompatibilityReport) -> str:
    status = "COMPATIBLE" if report.compatible else "REVIEW REQUIRED"
    lines = [
        "BloodHound compatibility",
        "=" * 24,
        f"Status: {status}",
        f"BloodHound model: {report.bloodhound_schema}",
        f"SharpHound target: {report.sharphound_schema}",
        (
            "valid_edges snapshot: "
            f"{report.valid_edges_snapshot_date} ({report.valid_edges_snapshot_commit})"
        ),
        "",
        "Objects:",
    ]
    for kind, count in report.objects.items():
        lines.append(f"  {kind:<20} {count}")
    lines.extend(
        [
            "",
            f"Relationship types:       {len(report.relationship_types)}",
            f"Supported attack edges:   {len(report.supported_attack_edges)}",
            f"Known context edges:      {len(report.known_context_edges)}",
            f"Unsupported attack edges: {len(report.unsupported_attack_edges)}",
            f"Unknown edges:            {len(report.unknown_edges)}",
            f"Source/target warnings:  {len(report.invalid_edge_pairs)}",
        ]
    )
    if report.unsupported_attack_edges:
        lines.append("\nUnsupported attack edges (fail-closed):")
        lines.extend(f"  - {edge}" for edge in report.unsupported_attack_edges)
    if report.unknown_edges:
        lines.append("\nUnknown edges (context only):")
        lines.extend(f"  - {edge}" for edge in report.unknown_edges)
    if report.invalid_edge_pairs:
        lines.append("\nSchema pair mismatches (advisory):")
        for mismatch in report.invalid_edge_pairs[:20]:
            lines.append(
                "  - "
                f"{mismatch.source_kind} -[{mismatch.relation}]-> "
                f"{mismatch.target_kind} ({mismatch.source} -> {mismatch.target})"
            )
        if len(report.invalid_edge_pairs) > 20:
            lines.append(f"  ... and {len(report.invalid_edge_pairs) - 20} more")
    if report.collection_span_days is not None:
        lines.append(f"\nCollection span: {report.collection_span_days} days")
        if report.collection_span_days > 30:
            lines.append(
                "WARNING: merged paths may combine relationships collected "
                "more than 30 days apart."
            )
    return "\n".join(lines)

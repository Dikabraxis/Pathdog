"""Normalized triage findings for Pathdog reports and JSON export."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class Finding:
    severity: int
    category: str
    title: str
    node_id: str = ""
    node_name: str = ""
    node_kind: str = ""
    evidence: str = ""
    commands: list[str] = field(default_factory=list)
    confidence: str = "high"
    source: str = ""
    path_hops: int | None = None
    path_weight: int | None = None

    def to_dict(self) -> dict:
        return {
            "severity": self.severity,
            "category": self.category,
            "title": self.title,
            "node_id": self.node_id,
            "node_name": self.node_name,
            "node_kind": self.node_kind,
            "evidence": self.evidence,
            "commands": self.commands,
            "confidence": self.confidence,
            "source": self.source,
            "path_hops": self.path_hops,
            "path_weight": self.path_weight,
        }

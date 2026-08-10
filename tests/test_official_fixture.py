"""Oracle test for SpecterOps' pinned Version 6 ADCS ingestion fixture."""

import os
import unittest
from collections import Counter
from pathlib import Path

from pathdog.graph import build_graph, build_raw_graph
from pathdog.loader import load_zip_detailed

FIXTURE = os.environ.get("BLOODHOUND_ADCS_FIXTURE")


def relationship_counts(graph) -> Counter:
    counts: Counter = Counter()
    for _, _, data in graph.edges(data=True):
        counts.update((data.get("relations") or {data.get("relation"): 1}).keys())
    return counts


@unittest.skipUnless(FIXTURE and Path(FIXTURE).is_file(), "official fixture not provided")
class OfficialBloodHoundFixtureTests(unittest.TestCase):
    def test_version6_adcs_fixture_matches_bloodhound_oracle(self):
        loaded = load_zip_detailed(FIXTURE)
        raw = build_raw_graph(loaded.nodes, loaded.edges)
        graph = build_graph(loaded.nodes, loaded.edges)
        raw_counts = relationship_counts(raw)
        calculated = relationship_counts(graph)

        self.assertEqual(len(raw), 330)
        self.assertEqual(sum(raw_counts.values()), 2560)
        self.assertEqual(raw_counts["RemoteInteractiveLogonRight"], 1)
        self.assertEqual(raw_counts["OwnsRaw"], 315)
        self.assertEqual(raw_counts["WriteOwnerRaw"], 578)

        # These values are the analyzed.json oracle shipped with the same
        # BloodHound fixture, not expectations invented by Pathdog.
        self.assertEqual(calculated["EnterpriseCAFor"], 2)
        self.assertEqual(calculated["TrustedForNTAuth"], 1)
        self.assertEqual(calculated["EnrollOnBehalfOf"], 8)
        self.assertEqual(calculated["ADCSESC1"], 3)
        self.assertEqual(calculated["GoldenCert"], 1)
        self.assertEqual(calculated["DCSync"], 2)
        self.assertEqual(calculated["Owns"], 315)
        self.assertEqual(calculated["WriteOwner"], 578)


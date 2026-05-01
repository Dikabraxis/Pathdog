import json
import subprocess
import sys
import unittest
import zipfile
from pathlib import Path
from tempfile import TemporaryDirectory

from pathdog.graph import build_graph
from pathdog.loader import load_zip
from pathdog.commands import get_commands
from pathdog.pathfinder import find_paths
from pathdog.quickwins import collect_all
from pathdog.triage import collect_findings
from pathdog.weights import EDGE_WEIGHTS


def write_bh_zip(path: Path, files: dict[str, dict]) -> Path:
    with zipfile.ZipFile(path, "w") as zf:
        for name, data in files.items():
            zf.writestr(name, json.dumps(data))
    return path


def node(oid: str, name: str, **props):
    return {
        "ObjectIdentifier": oid,
        "Properties": {"name": name, **props},
    }


def base_files(extra_rels=None, extra_files=None):
    rels = extra_rels or []
    files = {
        "users.json": {
            "meta": {"type": "users"},
            "data": [
                node("U1", "alice@corp.local"),
                node("U2", "svc_sql@corp.local", hasspn=True),
            ],
        },
        "groups.json": {
            "meta": {"type": "groups"},
            "data": [node("DA", "DOMAIN ADMINS@corp.local", highvalue=True)],
        },
        "domains.json": {
            "meta": {"type": "domains"},
            "data": [node("D1", "corp.local")],
            "rels": rels,
        },
        "computers.json": {"meta": {"type": "computers"}, "data": []},
        "gpos.json": {"meta": {"type": "gpos"}, "data": []},
        "ous.json": {"meta": {"type": "ous"}, "data": []},
    }
    if extra_files:
        files.update(extra_files)
    return files


class CoreTests(unittest.TestCase):
    def test_loader_classifies_adcs_node_types(self):
        with TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            zpath = write_bh_zip(
                tmp_path / "adcs.zip",
                base_files(extra_files={
                    "certtemplates.json": {
                        "meta": {"type": "certtemplates"},
                        "data": [node("T1", "UserTemplate@corp.local")],
                    },
                    "enterprisecas.json": {
                        "meta": {"type": "enterprisecas"},
                        "data": [node("CA1", "CORP-CA@corp.local")],
                    },
                }),
            )
            nodes, _ = load_zip(str(zpath))
            kinds = {item["id"]: item["kind"] for item in nodes}
            self.assertEqual(kinds["T1"], "certtemplates")
            self.assertEqual(kinds["CA1"], "enterprisecas")

    def test_dcsync_requires_both_replication_rights(self):
        nodes = [
            {"id": "U1", "kind": "users", "props": {"name": "alice@corp.local"}},
            {"id": "D1", "kind": "domains", "props": {"name": "corp.local"}},
        ]
        G = build_graph(nodes, [{"src": "U1", "dst": "D1", "type": "GetChangesAll"}])
        self.assertNotIn("DCSync", G["U1"]["D1"]["relations"])
        self.assertEqual(find_paths(G, "U1", "D1"), [])

        G = build_graph(nodes, [
            {"src": "U1", "dst": "D1", "type": "GetChanges"},
            {"src": "U1", "dst": "D1", "type": "GetChangesAll"},
        ])
        self.assertIn("DCSync", G["U1"]["D1"]["relations"])
        paths = find_paths(G, "U1", "D1")
        self.assertTrue(paths)
        self.assertEqual(paths[0].edges[0]["relation"], "DCSync")

    def test_adcs_edge_becomes_quickwin_and_finding(self):
        with TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            zpath = write_bh_zip(
                tmp_path / "esc.zip",
                base_files(
                    extra_rels=[{"StartNode": "U1", "EndNode": "T1", "RelationshipType": "ADCSESC1"}],
                    extra_files={
                        "certtemplates.json": {
                            "meta": {"type": "certtemplates"},
                            "data": [node("T1", "UserTemplate@corp.local")],
                        },
                    },
                ),
            )
            nodes, edges = load_zip(str(zpath))
            G = build_graph(nodes, edges)
            quickwins = collect_all(G)
            findings = collect_findings(G, quickwins=quickwins)

            self.assertIn("ADCS ADCSESC1", quickwins)
            self.assertTrue(any(f.category == "ADCS ADCSESC1" for f in findings))
            self.assertTrue(any("certipy-ad req" in " ".join(f.commands) for f in findings))
            self.assertEqual(
                sum(1 for f in findings if f.category == "ADCS ADCSESC1"),
                1,
            )

    def test_cli_triage_runs_without_owned_user_and_exports_json(self):
        with TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            zpath = write_bh_zip(
                tmp_path / "triage.zip",
                base_files(extra_rels=[
                    {"StartNode": "U1", "EndNode": "D1", "RelationshipType": "GetChanges"},
                    {"StartNode": "U1", "EndNode": "D1", "RelationshipType": "GetChangesAll"},
                ]),
            )
            out_base = tmp_path / "report"
            json_path = tmp_path / "report.json"
            proc = subprocess.run(
                [
                    sys.executable,
                    "pathdog.py",
                    "-z",
                    str(zpath),
                    "--triage",
                    "-o",
                    str(out_base),
                    "--export-json",
                    str(json_path),
                ],
                cwd=Path(__file__).resolve().parents[1],
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(proc.returncode, 0, proc.stderr + proc.stdout)
            data = json.loads(json_path.read_text())
            self.assertTrue(data["findings"])
            self.assertTrue(any(f["category"] == "DCSync" for f in data["findings"]))

    def test_cli_node_visibility_exports_json(self):
        with TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            zpath = write_bh_zip(
                tmp_path / "node.zip",
                base_files(extra_rels=[
                    {"StartNode": "U1", "EndNode": "DA", "RelationshipType": "GenericAll"},
                ]),
            )
            out_base = tmp_path / "node_report"
            json_path = tmp_path / "node_report.json"
            proc = subprocess.run(
                [
                    sys.executable,
                    "pathdog.py",
                    "-z",
                    str(zpath),
                    "--node",
                    "U1",
                    "-o",
                    str(out_base),
                    "--export-json",
                    str(json_path),
                ],
                cwd=Path(__file__).resolve().parents[1],
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(proc.returncode, 0, proc.stderr + proc.stdout)
            data = json.loads(json_path.read_text())
            self.assertEqual(data["node_visibility"]["node"]["id"], "U1")
            self.assertTrue(data["node_visibility"]["outbound_paths"])

    def test_cli_owned_user_does_not_include_triage_by_default(self):
        with TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            zpath = write_bh_zip(
                tmp_path / "owned.zip",
                base_files(extra_rels=[
                    {"StartNode": "U1", "EndNode": "DA", "RelationshipType": "GenericAll"},
                ]),
            )
            json_path = tmp_path / "owned.json"
            proc = subprocess.run(
                [
                    sys.executable,
                    "pathdog.py",
                    "-z",
                    str(zpath),
                    "-u",
                    "alice@corp.local",
                    "--export-json",
                    str(json_path),
                ],
                cwd=Path(__file__).resolve().parents[1],
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(proc.returncode, 0, proc.stderr + proc.stdout)
            data = json.loads(json_path.read_text())
            self.assertTrue(data["owned_results"][0]["paths"])
            self.assertEqual(data["findings"], [])
            self.assertEqual(data["quickwins"], {})

    def test_cli_owned_user_with_triage_includes_findings(self):
        with TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            zpath = write_bh_zip(
                tmp_path / "owned_triage.zip",
                base_files(extra_rels=[
                    {"StartNode": "U1", "EndNode": "DA", "RelationshipType": "GenericAll"},
                ]),
            )
            json_path = tmp_path / "owned_triage.json"
            proc = subprocess.run(
                [
                    sys.executable,
                    "pathdog.py",
                    "-z",
                    str(zpath),
                    "-u",
                    "alice@corp.local",
                    "--triage",
                    "--export-json",
                    str(json_path),
                ],
                cwd=Path(__file__).resolve().parents[1],
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(proc.returncode, 0, proc.stderr + proc.stdout)
            data = json.loads(json_path.read_text())
            self.assertTrue(data["owned_results"][0]["paths"])
            self.assertTrue(data["findings"])
            self.assertTrue(data["quickwins"])

    def test_every_weighted_relation_has_command_guidance(self):
        structural = {"MemberOf", "Contains"}
        for rel in EDGE_WEIGHTS:
            with self.subTest(rel=rel):
                cmd, _ = get_commands(
                    rel,
                    "SRC",
                    "DST",
                    "alice@corp.local",
                    "target.corp.local",
                    "users",
                    "computers",
                    "alice@corp.local",
                )
                self.assertTrue(cmd.description)
                if rel not in structural:
                    self.assertTrue(cmd.commands, rel)

    def test_has_session_commands_target_source_host(self):
        cmd, next_actor = get_commands(
            "HasSession",
            "C1",
            "DAUSER",
            "WS01.corp.local",
            "admin@corp.local",
            "computers",
            "users",
            "alice@corp.local",
        )
        self.assertIn("@WS01.corp.local", cmd.commands[0])
        self.assertNotIn("@admin@corp.local", cmd.commands[0])
        self.assertEqual(next_actor, "admin@corp.local")

    def test_dcfor_commands_target_source_dc(self):
        cmd, _ = get_commands(
            "DCFor",
            "DC1",
            "D1",
            "DC01.corp.local",
            "corp.local",
            "computers",
            "domains",
            "alice@corp.local",
        )
        self.assertIn("@DC01.corp.local", cmd.commands[0])

    def test_computer_takeover_edges_switch_to_machine_identity(self):
        for rel in ("GenericWrite", "GenericAll", "AllExtendedRights"):
            with self.subTest(rel=rel):
                _, next_actor = get_commands(
                    rel,
                    "U1",
                    "C1",
                    "alice@corp.local",
                    "WS01.corp.local",
                    "users",
                    "computers",
                    "alice@corp.local",
                )
                self.assertEqual(next_actor, "WS01$@corp.local")

    def test_delegation_edges_use_target_domain_for_administrator(self):
        for rel in ("AllowedToDelegate", "AllowedToAct", "WriteAccountRestrictions"):
            with self.subTest(rel=rel):
                _, next_actor = get_commands(
                    rel,
                    "U1",
                    "C1",
                    "alice@corp.local",
                    "APP01.child.corp.local",
                    "users",
                    "computers",
                    "alice@corp.local",
                )
                self.assertEqual(next_actor, "Administrator@child.corp.local")


if __name__ == "__main__":
    unittest.main()

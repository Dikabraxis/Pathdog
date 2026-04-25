#!/usr/bin/env python3
"""pathdog — BloodHound attack path analyzer CLI."""

import argparse
import os
import sys
from datetime import datetime

from pathdog.loader import load_zip
from pathdog.graph import build_graph, resolve_target, prune_to_target, graph_stats
from pathdog.pathfinder import find_paths, suggest_similar_nodes
from pathdog.report import (
    render_markdown_multi, render_html_multi, print_paths_console,
)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pathdog",
        description="Analyze BloodHound ZIP exports to find attack paths to Domain Admin.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
examples:
  pathdog -z corp.zip -u john.doe@corp.local
  pathdog -z dump1.zip dump2.zip -u john@corp.local svc_backup@corp.local
  pathdog -z dump1.zip dump2.zip -u owned_users.txt -k 5 -f html -v
  pathdog -z corp.zip --list users
        """,
    )
    p.add_argument("-z", "--zip", required=True, metavar="FILE", nargs="+",
                   dest="zips", help="BloodHound ZIP export(s), e.g. -z a.zip b.zip")
    p.add_argument("-u", "--user", metavar="USER", nargs="+", default=[],
                   dest="users",
                   help="Owned user(s) or a .txt file with one user per line")
    p.add_argument("-t", "--target", default=None, metavar="TARGET",
                   help="Target node — default: auto-detect DOMAIN ADMINS")
    p.add_argument("-k", "--paths", type=int, default=3, metavar="K",
                   help="Number of paths to find per user (default: 3)")
    p.add_argument("-o", "--output", default="pathdog_report", metavar="BASENAME",
                   help="Output file base name (default: pathdog_report)")
    p.add_argument("-f", "--format", choices=["md", "html", "both"], default="both",
                   dest="fmt", help="Output format (default: both)")
    p.add_argument("-l", "--list", metavar="KIND", nargs="?", const="all",
                   dest="list_kind",
                   help="List nodes and exit. KIND: users, computers, groups, domains, all")
    p.add_argument("-v", "--verbose", action="store_true",
                   help="Show graph statistics")
    return p


def _expand_users(raw: list[str]) -> tuple[list[str], int]:
    """Expand .txt files into user lists. Returns (users, exit_code)."""
    users: list[str] = []
    for entry in raw:
        if entry.lower().endswith(".txt"):
            try:
                with open(entry, encoding="utf-8") as fh:
                    from_file = [
                        l.strip() for l in fh
                        if l.strip() and not l.startswith("#")
                    ]
                print(f"[*] Loaded {len(from_file)} user(s) from {entry}")
                users.extend(from_file)
            except OSError as exc:
                print(f"[!] Cannot read user file '{entry}': {exc}", file=sys.stderr)
                return [], 1
        else:
            users.append(entry)
    return users, 0


def _load_graph(zips: list[str]) -> tuple | None:
    """Load and merge all ZIPs. Returns (nodes, edges) or None on error."""
    all_nodes: list[dict] = []
    all_edges: list[dict] = []
    for zip_path in zips:
        print(f"[*] Loading {zip_path} ...")
        try:
            nodes, edges = load_zip(zip_path)
        except ValueError as exc:
            print(f"[!] {exc}", file=sys.stderr)
            return None
        print(f"    → {len(nodes)} nodes, {len(edges)} edges")
        all_nodes.extend(nodes)
        all_edges.extend(edges)
    if len(zips) > 1:
        print(f"[*] Merged: {len(all_nodes)} nodes, {len(all_edges)} edges (before dedup)")
    return all_nodes, all_edges


def _resolve_source(G, user: str):
    """Find user node; return (node_id, exact_match: bool)."""
    if user in G:
        return user, True
    user_lower = user.lower()
    for nid in G.nodes:
        if user_lower == nid.lower():
            return nid, True
        name = G.nodes[nid].get("name", "")
        if user_lower == name.lower():
            return nid, True
    for nid in G.nodes:
        if user_lower in nid.lower():
            return nid, False
        name = G.nodes[nid].get("name", "")
        if name and user_lower in name.lower():
            return nid, False
    return None, False


def _do_list(G, kind: str) -> None:
    """Print nodes filtered by kind and exit."""
    kinds = {"all", "users", "computers", "groups", "domains", "gpos", "ous"}
    if kind not in kinds:
        print(f"[!] Unknown kind '{kind}'. Choose from: {', '.join(sorted(kinds))}",
              file=sys.stderr)
        sys.exit(1)

    print(f"\n{'Node ID':<60} {'Kind':<12} Name")
    print("─" * 100)
    count = 0
    for nid in sorted(G.nodes):
        node_kind = G.nodes[nid].get("kind", "unknown")
        if kind != "all" and node_kind != kind:
            continue
        name = G.nodes[nid].get("name", "")
        display_id = nid if len(nid) <= 58 else nid[:55] + "..."
        print(f"{display_id:<60} {node_kind:<12} {name}")
        count += 1
    print(f"\n{count} node(s) listed.")


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    # ── Load & merge all ZIPs ─────────────────────────────────────────────────
    result = _load_graph(args.zips)
    if result is None:
        return 1
    all_nodes, all_edges = result

    print(f"[*] Building graph ...")
    G = build_graph(all_nodes, all_edges)
    print(f"[*] Graph: {G.number_of_nodes()} unique nodes, {G.number_of_edges()} unique edges")

    # ── --list mode (no -u required) ──────────────────────────────────────────
    if args.list_kind:
        _do_list(G, args.list_kind)
        return 0

    # ── Validate -u is provided for path-finding ──────────────────────────────
    if not args.users:
        parser.error("argument -u/--user is required unless --list is used")

    # ── Expand user list ──────────────────────────────────────────────────────
    users, rc = _expand_users(args.users)
    if rc:
        return rc
    if not users:
        print("[!] No owned users provided.", file=sys.stderr)
        return 1

    # ── Resolve target ────────────────────────────────────────────────────────
    target = resolve_target(G, args.target)
    if not target:
        hint = args.target or "DOMAIN ADMINS"
        print(
            f"[!] Could not locate target node matching '{hint}'.\n"
            "    Try -t with the exact name or SID, or use --list to browse nodes.",
            file=sys.stderr,
        )
        return 1
    print(f"[*] Target node: {target}")

    # ── Prune graph ───────────────────────────────────────────────────────────
    print(f"[*] Pruning graph to ancestors of target ...")
    pruned = prune_to_target(G, target)
    stats = graph_stats(G, pruned)
    print(f"[*] Pruned: {stats['pruned_nodes']} nodes, {stats['pruned_edges']} edges "
          f"({stats['reduction_pct']}% reduction)")

    if args.verbose:
        print(
            f"[v] Full stats — total: {stats['total_nodes']} nodes / "
            f"{stats['total_edges']} edges | "
            f"pruned: {stats['pruned_nodes']} / {stats['pruned_edges']}"
        )

    # ── Resolve owned users ───────────────────────────────────────────────────
    sources: list[str] = []
    for user in users:
        source, exact = _resolve_source(G, user)
        if not source:
            print(f"[!] User '{user}' not found in graph.", file=sys.stderr)
            suggestions = suggest_similar_nodes(G, user, top_n=3)
            if suggestions:
                print("    Did you mean one of:", file=sys.stderr)
                for s in suggestions:
                    print(f"      - {s}", file=sys.stderr)
            continue
        if not exact:
            print(f"[~] Fuzzy match for '{user}' → '{source}'")
        print(f"[*] Owned user: {source}")
        sources.append(source)

    if not sources:
        print("[!] No valid owned users found. Aborting.", file=sys.stderr)
        return 1

    # ── Find paths ────────────────────────────────────────────────────────────
    all_results: list[tuple[str, list]] = []
    any_path_found = False

    for source in sources:
        if source not in pruned:
            src_display = G.nodes[source].get("name", source)
            print(f"\n[!] No path from '{src_display}' — not connected to DA subgraph.")
            all_results.append((source, []))
            continue

        print(f"[*] Computing up to {args.paths} path(s) from {source} ...")
        try:
            paths = find_paths(pruned, source, target, k=args.paths)
        except ValueError as exc:
            print(f"[!] {exc}", file=sys.stderr)
            all_results.append((source, []))
            continue

        if paths:
            any_path_found = True
        all_results.append((source, paths))

    # ── Console output ────────────────────────────────────────────────────────
    for source, paths in all_results:
        if len(sources) > 1:
            src_label = G.nodes[source].get("name", source)
            print(f"\n{'═' * 60}")
            print(f"  Owned user: {src_label}")
            print(f"{'═' * 60}")
        print_paths_console(paths, G, source, target)

    # ── Write reports ─────────────────────────────────────────────────────────
    written: list[str] = []
    report_stats = stats if args.verbose else None

    base = args.output
    extensions = [e for e in (".md", ".html") if args.fmt in (e[1:], "both")]
    if any(os.path.exists(f"{base}{ext}") for ext in extensions):
        base = f"{base}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"

    if args.fmt in ("md", "both"):
        md_path = f"{base}.md"
        with open(md_path, "w", encoding="utf-8") as fh:
            fh.write(render_markdown_multi(all_results, G, target, report_stats))
        written.append(md_path)

    if args.fmt in ("html", "both"):
        html_path = f"{base}.html"
        with open(html_path, "w", encoding="utf-8") as fh:
            fh.write(render_html_multi(all_results, G, target, report_stats))
        written.append(html_path)

    if written:
        print(f"\n[+] Report(s) written: {', '.join(written)}")

    # Exit 0 = paths found, 2 = ran OK but no paths
    return 0 if any_path_found else 2


if __name__ == "__main__":
    sys.exit(main())

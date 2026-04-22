#!/usr/bin/env python3
"""pathdog — BloodHound attack path analyzer CLI."""

import argparse
import sys

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
        """,
    )
    p.add_argument("-z", "--zip", required=True, metavar="FILE", nargs="+",
                   dest="zips", help="BloodHound ZIP export(s), e.g. -z a.zip b.zip")
    p.add_argument("-u", "--user", required=True, metavar="USER", nargs="+",
                   dest="users", help="Owned user(s) or a .txt file with one user per line")
    p.add_argument("-t", "--target", default=None, metavar="TARGET",
                   help="Target node — default: auto-detect DOMAIN ADMINS")
    p.add_argument("-k", "--paths", type=int, default=3, metavar="K",
                   help="Number of paths to find per user (default: 3)")
    p.add_argument("-o", "--output", default="pathdog_report", metavar="BASENAME",
                   help="Output file base name (default: pathdog_report)")
    p.add_argument("-f", "--format", choices=["md", "html", "both"], default="both",
                   dest="fmt", help="Output format (default: both)")
    p.add_argument("-v", "--verbose", action="store_true",
                   help="Show graph statistics")
    return p


def resolve_source(G, user: str):
    """Find the user node; return (node_id, exact_match: bool)."""
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


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    # ── Expand user list (support .txt file) ──────────────────────────────────
    expanded_users: list[str] = []
    for entry in args.users:
        if entry.lower().endswith(".txt"):
            try:
                with open(entry, encoding="utf-8") as fh:
                    file_users = [l.strip() for l in fh if l.strip() and not l.startswith("#")]
                print(f"[*] Loaded {len(file_users)} user(s) from {entry}")
                expanded_users.extend(file_users)
            except OSError as exc:
                print(f"[!] Cannot read user file '{entry}': {exc}", file=sys.stderr)
                return 1
        else:
            expanded_users.append(entry)
    args.users = expanded_users

    if not args.users:
        print("[!] No owned users provided.", file=sys.stderr)
        return 1

    # ── Load & merge all ZIPs ─────────────────────────────────────────────────
    all_nodes: list[dict] = []
    all_edges: list[dict] = []

    for zip_path in args.zips:
        print(f"[*] Loading {zip_path} ...")
        try:
            nodes, edges = load_zip(zip_path)
        except ValueError as exc:
            print(f"[!] {exc}", file=sys.stderr)
            return 1
        print(f"    → {len(nodes)} nodes, {len(edges)} edges")
        all_nodes.extend(nodes)
        all_edges.extend(edges)

    if len(args.zips) > 1:
        print(f"[*] Merged: {len(all_nodes)} nodes, {len(all_edges)} edges (before dedup)")

    # ── Build graph (deduplication happens here) ──────────────────────────────
    G = build_graph(all_nodes, all_edges)
    print(f"[*] Graph: {G.number_of_nodes()} unique nodes, {G.number_of_edges()} unique edges")

    # ── Resolve target ────────────────────────────────────────────────────────
    target = resolve_target(G, args.target)
    if not target:
        hint = args.target or "DOMAIN ADMINS"
        print(
            f"[!] Could not locate target node matching '{hint}'.\n"
            "    Try specifying -t with the exact node name or SID.",
            file=sys.stderr,
        )
        return 1
    print(f"[*] Target node: {target}")

    # ── Prune once for all users ──────────────────────────────────────────────
    pruned = prune_to_target(G, target)
    stats = graph_stats(G, pruned)

    if args.verbose:
        print(
            f"[v] Graph stats — total: {stats['total_nodes']} nodes / "
            f"{stats['total_edges']} edges | "
            f"pruned: {stats['pruned_nodes']} nodes / "
            f"{stats['pruned_edges']} edges | "
            f"reduction: {stats['reduction_pct']}%"
        )

    # ── Resolve all owned users ───────────────────────────────────────────────
    sources: list[str] = []
    for user in args.users:
        source, exact = resolve_source(G, user)
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

    # ── Find paths for each owned user ────────────────────────────────────────
    # Collect all results: list of (source, paths)
    all_results: list[tuple[str, list]] = []

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

    if args.fmt in ("md", "both"):
        md_path = f"{args.output}.md"
        with open(md_path, "w", encoding="utf-8") as fh:
            fh.write(render_markdown_multi(all_results, G, target, report_stats))
        written.append(md_path)

    if args.fmt in ("html", "both"):
        html_path = f"{args.output}.html"
        with open(html_path, "w", encoding="utf-8") as fh:
            fh.write(render_html_multi(all_results, G, target, report_stats))
        written.append(html_path)

    if written:
        print(f"\n[+] Report(s) written: {', '.join(written)}")

    return 0


if __name__ == "__main__":
    sys.exit(main())

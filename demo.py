#!/usr/bin/env python3
"""
VS Code demo runner for the BigID x Sentinel Graph queries.

Usage:
    python3 demo.py            # interactive menu
    python3 demo.py 1          # run query #1
    python3 demo.py all        # run all 5 in sequence

Requires: Azure CLI (`az`) logged in as a user with Log Analytics Reader
on the workspace. No Python dependencies beyond the stdlib.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

WORKSPACE_ID = os.environ.get(
    "BIGID_GRAPH_WORKSPACE_ID", "77429a58-865a-4764-8429-aaacdfe3cb73"
)

QUERIES = [
    ("01", "Sensitive Data Blast Radius",
     "Top identities ranked by reachable regulated assets in <= 2 hops"),
    ("02", "External Exposure Paths",
     "Shortest paths from external parties to PII/PHI/PCI/Financial"),
    ("03", "Orphan Cluster Detection",
     "Clusters of orphaned sensitive assets sharing data source + last accessor"),
    ("04", "Threat Lateral Movement",
     "Paths from malicious source IPs through threats onto regulated data"),
    ("05", "Cross-Source Leakage",
     "Owners with the same regulated classification across 3+ data sources"),
]

ROOT = Path(__file__).parent
QDIR = ROOT / "graph-queries"


def find_query(num: str) -> Path:
    matches = sorted(QDIR.glob(f"{num}-*.kql"))
    if not matches:
        sys.exit(f"❌ No query found matching '{num}-*.kql' in {QDIR}")
    return matches[0]


def run(num: str) -> None:
    qpath = find_query(num)
    title = next((t for n, t, _ in QUERIES if n == num), qpath.stem)

    print()
    print("=" * 78)
    print(f"▶ Query {num}: {title}")
    print(f"  File: {qpath.relative_to(ROOT)}")
    print("=" * 78)

    kql = qpath.read_text()
    cmd = [
        "az", "monitor", "log-analytics", "query",
        "--workspace", WORKSPACE_ID,
        "--analytics-query", kql,
        "-o", "json",
    ]
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        print("❌ Query failed:")
        print(result.stderr)
        return

    try:
        rows = json.loads(result.stdout) if result.stdout.strip() else []
    except json.JSONDecodeError:
        print(result.stdout)
        return

    if not rows:
        print("✅ Query ran. Returned 0 rows.")
        return

    print(f"✅ {len(rows)} row(s)\n")
    cols = list(rows[0].keys())

    def cell(v):
        if isinstance(v, (list, dict)):
            s = json.dumps(v, ensure_ascii=False)
        else:
            s = "" if v is None else str(v)
        return s if len(s) <= 60 else s[:57] + "…"

    widths = {c: max(len(c), max(len(cell(r.get(c))) for r in rows)) for c in cols}
    widths = {c: min(w, 60) for c, w in widths.items()}

    header = " | ".join(c.ljust(widths[c]) for c in cols)
    print(header)
    print("-+-".join("-" * widths[c] for c in cols))
    for r in rows[:25]:
        print(" | ".join(cell(r.get(c)).ljust(widths[c]) for c in cols))
    if len(rows) > 25:
        print(f"... ({len(rows) - 25} more rows)")


def menu() -> None:
    print("\nBigID x Sentinel Graph — VS Code Demo")
    print("Workspace:", WORKSPACE_ID)
    print()
    for n, t, d in QUERIES:
        print(f"  {n}. {t}")
        print(f"      {d}")
    print("  all. Run all five in sequence")
    print("    q. Quit")
    while True:
        choice = input("\ngraph-demo> ").strip().lower()
        if choice in {"q", "quit", "exit"}:
            return
        if choice == "all":
            for n, _, _ in QUERIES:
                run(n)
            continue
        if choice.isdigit():
            choice = choice.zfill(2)
        if any(choice == n for n, _, _ in QUERIES):
            run(choice)
        else:
            print("Pick 1-5, 'all', or 'q'.")


if __name__ == "__main__":
    if len(sys.argv) == 1:
        menu()
    elif sys.argv[1] == "all":
        for n, _, _ in QUERIES:
            run(n)
    else:
        arg = sys.argv[1]
        if arg.isdigit():
            arg = arg.zfill(2)
        run(arg)

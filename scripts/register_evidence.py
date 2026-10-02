"""Chain of custody of a case folder: SHA-256 before analysis, re-hash after (EF-05, task 3.2).

Run by an analyst INSIDE the container (evidence is mounted read-only there):
  docker compose exec forensic python scripts/register_evidence.py WS-042 --analyst "Nom Prénom"
  docker compose exec forensic python scripts/register_evidence.py WS-042 --analyst "Nom Prénom" --after
Every hash is journaled in /output/audit.jsonl with the analyst's name; a manifest is written to
/output/manifests/. Copy the printed manifest SHA-256 and journal head hash OFF the PC (custody
sheet). Exit code: 0 = ok, 1 = a file changed / is missing (after) or changed (before), 2 = usage.
"""
from __future__ import annotations

import argparse
import sys

from forensic_mcp import custody
from forensic_mcp.config import load_config


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("case", help="host folder under the evidence root, e.g. WS-042")
    ap.add_argument("--analyst", required=True, help="name of the person running the check")
    ap.add_argument("--after", action="store_true",
                    help="re-hash registered files (end of analysis) instead of registering")
    a = ap.parse_args(argv)
    cfg = load_config()
    try:
        r = (custody.verify_case if a.after else custody.register_case)(cfg, a.case, a.analyst)
    except (ValueError, OSError) as exc:
        print(f"refused: {exc}", file=sys.stderr)
        return 2
    print(f"case {r['case']} — stage {r['stage']} — {r['file_count']} file(s)")
    for key in ("changed", "missing", "not_registered"):
        for path in r.get(key, []):
            print(f"  {key.upper()}: {path}")
    print(f"manifest        {r['manifest']}")
    print(f"manifest sha256 {r['manifest_sha256']}")
    print(f"journal head    {r['journal_head_hash']}")
    print("RESULT: OK" if r["ok"] else "RESULT: NOT OK")
    return 0 if r["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())

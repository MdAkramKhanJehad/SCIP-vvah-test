#!/usr/bin/env python3
"""Rebuild manifest from the pinned dataset; source-only smoke metadata is separate."""

import hashlib
import json
import pathlib

ROOT = pathlib.Path(__file__).resolve().parents[1]


def main():
    groups = {}
    for line in (ROOT / "datasets/VulnGym/data/entries.jsonl").read_text().splitlines():
        e = json.loads(line)
        key = (e["repo_url"], e["commit"])
        g = groups.setdefault(
            key,
            {"repo_url": key[0], "commit": key[1], "entry_ids": [], "report_ids": []},
        )
        g["entry_ids"].append(e["entry_id"])
        g["report_ids"].append(e["report_id"])
    targets = []
    for key, g in sorted(groups.items()):
        g["target_id"] = hashlib.sha256(("\n".join(key)).encode()).hexdigest()[:16]
        g["report_ids"] = sorted(set(g["report_ids"]))
        targets.append(g)
    manifest = {
        "dataset_commit": json.loads(
            (ROOT / "configs/upstream-revisions.json").read_text()
        )["dataset"]["commit"],
        "selection_rule": "lexicographically smallest (repo_url, vulnerable commit), independent of annotations",
        "smoke_target_id": targets[0]["target_id"],
        "targets": targets,
    }
    (ROOT / "datasets/manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")


if __name__ == "__main__":
    main()


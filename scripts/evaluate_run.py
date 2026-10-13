#!/usr/bin/env python3
"""Official matching on the selected commit subset; failed scans have no recall score."""

import argparse
import importlib.util
import json
import pathlib

ROOT = pathlib.Path(__file__).resolve().parents[1]


def evaluate(run):
    status = json.loads((run / "status.json").read_text())
    t = json.loads((run / "target.json").read_text())
    entries = [
        json.loads(l)
        for l in (ROOT / "datasets/VulnGym/data/entries.jsonl").read_text().splitlines()
    ]
    subset = [
        e
        for e in entries
        if (e["repo_url"], e["commit"]) == (t["repo_url"], t["commit"])
    ]
    (run / "evaluation-subset.jsonl").write_text(
        "".join(json.dumps(e) + "\n" for e in subset)
    )
    # Supplied evaluator int() cannot handle SCHEMA.md's ranges; do not silently coerce.
    unsupported = [
        e["entry_id"]
        for e in subset
        if any(
            not isinstance(e[k]["line"], int)
            for k in ("entry_point", "critical_operation")
        )
    ]
    output = {
        "scan_status": status["status"],
        "scope": "selected repository/commit subset",
        "selected_entries": len(subset),
        "selected_advisories": len({e["report_id"] for e in subset}),
        "unsupported_range_entry_ids": unsupported,
        "official_result": None,
    }
    path = ROOT / "datasets/VulnGym/examples/evaluate.py"
    spec = importlib.util.spec_from_file_location("official", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    findings = [
        json.loads(l) for l in (run / "converted.jsonl").read_text().splitlines() if l
    ]
    matched = module.evaluate(subset, findings, 5)
    if status["status"] == "completed" and not unsupported:
        output["official_result"] = matched
    else:
        matched.pop("recall", None)
        output["pipeline_check_only"] = matched
        output["recall_unavailable_reason"] = (
            "scan incomplete or subset contains unsupported line ranges"
        )

    (run / "evaluation.json").write_text(json.dumps(output, indent=2) + "\n")
    return output


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("run", type=pathlib.Path)
    a = p.parse_args()
    evaluate(a.run)


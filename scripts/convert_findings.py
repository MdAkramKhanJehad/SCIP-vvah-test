#!/usr/bin/env python3
"""Convert only explicit model-produced source/sink refs; annotations never read."""

import argparse
import json
import pathlib
import re


def endpoint(ref):
    m = re.fullmatch(r"([^:\n<>]+):([1-9][0-9]*)", ref or "")
    if not m:
        raise ValueError("missing or ambiguous file:line evidence")

    path = pathlib.PurePosixPath(m[1].replace("\\", "/"))
    if path.is_absolute() or ".." in path.parts:
        raise ValueError("non-relative location")

    return {"file": str(path), "line": int(m[2])}


def convert(raw, target):
    rows = []
    errors = []
    if raw.get("schema_version") != "1.0" or not isinstance(raw.get("findings"), list):
        raise ValueError("unsupported or malformed FinalReport schema")

    for i, ranked in enumerate(raw["findings"]):
        f = ranked.get("finding", {})
        try:
            if f.get("backfilled_refs"):
                raise ValueError(
                    "upstream AST-backfilled refs excluded from model-evidence mapping"
                )

            if f.get("origin") == "detector":
                raise ValueError("deterministic detector origin excluded")

            rows.append(
                {
                    "finding_id": f.get("case_id") or str(i),
                    "repo_url": target["repo_url"],
                    "commit": target["commit"],
                    "entry_point": endpoint(f.get("source_ref")),
                    "critical_operation": endpoint(f.get("sink_ref")),
                    "note": "source_ref treated as reachable entry; semantic equivalence not guaranteed",
                }
            )
        except ValueError as e:
            errors.append(
                {
                    "index": i,
                    "finding_id": f.get("case_id"),
                    "error": str(e),
                    "missing_evidence": True,
                }
            )
    return rows, errors


def main():
    p = argparse.ArgumentParser()
    p.add_argument("raw")
    p.add_argument("target")
    p.add_argument("output")
    p.add_argument("errors")
    a = p.parse_args()
    rows, errors = convert(
        json.loads(pathlib.Path(a.raw).read_text()),
        json.loads(pathlib.Path(a.target).read_text()),
    )
    pathlib.Path(a.output).write_text("".join(json.dumps(x) + "\n" for x in rows))
    pathlib.Path(a.errors).write_text("".join(json.dumps(x) + "\n" for x in errors))


if __name__ == "__main__":
    main()


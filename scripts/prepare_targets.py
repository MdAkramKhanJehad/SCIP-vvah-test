#!/usr/bin/env python3
"""Fetch exact commits, export history-free sources; never pass annotations to scans."""

import argparse
import json
import pathlib
import shutil
import subprocess
import tarfile
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[1]


def run(*args):
    return subprocess.run(args, check=True, cwd=ROOT)


def prepare(t):
    dest = ROOT / "targets" / t["target_id"]
    marker = ROOT / "targets" / (t["target_id"] + ".json")
    if dest.exists():
        if not marker.exists() or json.loads(marker.read_text()) != t:
            raise RuntimeError(
                "Existing target lacks matching provenance: " + str(dest)
            )

        return

    cache = ROOT / "targets/.git-cache" / (t["target_id"] + ".git")
    cache.parent.mkdir(parents=True, exist_ok=True)
    if not cache.exists():
        run("git", "init", "--bare", str(cache))
        run("git", "--git-dir", str(cache), "remote", "add", "origin", t["repo_url"])

    run("git", "--git-dir", str(cache), "fetch", "--depth=1", "origin", t["commit"])
    sha = subprocess.check_output(
        ["git", "--git-dir", str(cache), "rev-parse", "FETCH_HEAD"], text=True
    ).strip()
    if sha != t["commit"]:
        raise RuntimeError("Commit mismatch")

    with tempfile.TemporaryFile() as f:
        subprocess.run(
            ["git", "--git-dir", str(cache), "archive", sha], stdout=f, check=True
        )
        f.seek(0)
        dest.mkdir()
        with tarfile.open(fileobj=f) as archive:
            archive.extractall(dest, filter="data")
    marker.write_text(json.dumps(t, indent=2) + "\n")
    shutil.rmtree(cache)


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--limit", required=True, type=int)
    p.add_argument("--offset", default=0, type=int)
    a = p.parse_args()
    if not 1 <= a.limit <= 166 or a.offset < 0:
        p.error("positive explicit limit <=166 and nonnegative offset required")

    manifest = json.loads((ROOT / "datasets/manifest.json").read_text())
    for g in manifest["targets"][a.offset : a.offset + a.limit]:
        t = {k: g[k] for k in ("target_id", "repo_url", "commit")}
        prepare(t)
        print(t["target_id"], flush=True)


if __name__ == "__main__":
    main()


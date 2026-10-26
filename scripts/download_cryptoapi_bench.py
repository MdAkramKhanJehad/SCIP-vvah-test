#!/usr/bin/env python3
"""Download a pinned CryptoAPI-Bench snapshot without retaining Git history."""

import argparse
import json
import shutil
import subprocess
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
URL = "https://github.com/CryptoAPI-Bench/CryptoAPI-Bench.git"
REVISION = "e6b6b50fef6970151300c1ac2de62e188ba6de19"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--revision", default=REVISION)
    parser.add_argument("--destination", type=Path, default=ROOT / "datasets/CryptoAPI-Bench")
    args = parser.parse_args()
    destination = args.destination.resolve()
    if destination.exists():
        marker = destination / ".upstream.json"
        if not marker.is_file() or json.loads(marker.read_text())["requested_revision"] != args.revision:
            parser.error(f"Refusing to replace existing dataset: {destination}")

        print(f"Already downloaded: {destination}")
        return

    destination.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix=".cryptoapi-", dir=destination.parent) as temporary:
        checkout = Path(temporary) / "checkout"
        subprocess.run(["git", "init", "--quiet", str(checkout)], check=True)
        subprocess.run(["git", "-C", str(checkout), "fetch", "--depth=1", URL, args.revision], check=True)
        subprocess.run(["git", "-C", str(checkout), "checkout", "--quiet", "--detach", "FETCH_HEAD"], check=True)
        commit = subprocess.check_output(["git", "-C", str(checkout), "rev-parse", "HEAD"], text=True).strip()
        snapshot = Path(temporary) / "snapshot"
        shutil.copytree(checkout, snapshot, ignore=shutil.ignore_patterns(".git"))
        (snapshot / ".upstream.json").write_text(json.dumps({
            "repo_url": URL, "commit": commit, "requested_revision": args.revision,
        }, indent=2) + "\n", encoding="utf-8")
        snapshot.rename(destination)

    print(f"Downloaded {destination}\nCommit: {commit}")


if __name__ == "__main__":
    main()

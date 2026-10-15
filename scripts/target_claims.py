#!/usr/bin/env python3
"""Atomic shared-drive claims. Abandoned claims require manual recovery."""

import datetime
import hashlib
import json
import os
import pathlib
import socket
import uuid


def utc_now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def atomic_json(path, data):
    temporary = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
    try:
        temporary.write_text(json.dumps(data, indent=2) + "\n")
        temporary.replace(path)
    finally:
        temporary.unlink(missing_ok=True)


def target_key(target):
    repository = target["repo_url"].rstrip("/").removesuffix(".git")
    identity = f"{repository}\n{target['commit']}"
    return hashlib.sha256(identity.encode()).hexdigest()


class ClaimBusy(Exception):
    pass


class TargetClaim:
    def __init__(self, runs, target, experiment):
        key = target_key(target)
        self.directory = pathlib.Path(runs) / ".claims" / key
        self.result = pathlib.Path(runs) / ".target-status" / key / f"{experiment}.json"
        self.owner = {
            "claim_id": uuid.uuid4().hex,
            "hostname": socket.gethostname(),
            "pid": os.getpid(),
            "started_at": utc_now(),
            "target": target,
            "experiment": experiment,
            "status": "running",
        }
        self.finished = False

    def __enter__(self):
        self.directory.parent.mkdir(parents=True, exist_ok=True)
        try:
            self.directory.mkdir()
        except FileExistsError:
            raise ClaimBusy(str(self.directory)) from None

        try:
            atomic_json(self.directory / "owner.json", self.owner)
        except BaseException:
            self.directory.rmdir()
            raise

        return self

    def update(self, **fields):
        self.owner.update(fields)
        atomic_json(self.directory / "owner.json", self.owner)

    def previous(self):
        if not self.result.exists():
            return None

        return json.loads(self.result.read_text())

    def finish(self, status, reason=None):
        record = dict(self.owner, status=status, reason=reason, finished_at=utc_now())
        self.result.parent.mkdir(parents=True, exist_ok=True)
        atomic_json(self.result, record)
        self.finished = True

    def __exit__(self, error_type, error, traceback):
        if not self.finished and error_type is not None:
            status = "interrupted" if issubclass(error_type, KeyboardInterrupt) else "failed"
            # A failed state write leaves the claim blocked for manual inspection.
            self.finish(status, str(error) or error_type.__name__)

        path = self.directory / "owner.json"
        if json.loads(path.read_text())["claim_id"] != self.owner["claim_id"]:
            raise RuntimeError(f"Claim ownership changed: {self.directory}")

        path.unlink()
        self.directory.rmdir()

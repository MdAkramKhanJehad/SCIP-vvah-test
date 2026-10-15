#!/usr/bin/env python3
"""Scheduler tests use synthetic targets and never contact a model or GitHub."""

import contextlib
import io
import json
import multiprocessing
import os
import pathlib
import shutil
import tempfile
import unittest
from unittest import mock

import prepare_targets
import run_baseline
from target_claims import ClaimBusy, TargetClaim, target_key

ROOT = run_baseline.ROOT


def fake_scan(target, settings, overlay, claim=None):
    # Exclusive creation makes an accidental duplicate scan fail the test.
    path = run_baseline.ROOT / (target["target_id"] + ".executed")
    with path.open("x") as output:
        output.write(str(os.getpid()))

    return "completed"


def competing_worker(workspace, targets, ready, start, overlap, results):
    run_baseline.ROOT = pathlib.Path(workspace)
    first_scan = True

    def scan(target, settings, overlay, claim=None):
        nonlocal first_scan
        result = fake_scan(target, settings, overlay, claim)
        if first_scan:
            first_scan = False
            overlap.wait(timeout=20)

        return result

    with mock.patch.object(run_baseline, "run_target", side_effect=scan), contextlib.redirect_stdout(io.StringIO()):
        ready.put(True)
        if not start.wait(20):
            raise RuntimeError("Worker start timed out")

        outcomes = run_baseline.process_targets(targets, None, None, {})
        results.put(outcomes)


class SharedRunner(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(dir=os.environ.get("SCIP_TEST_SHARED_TMP"))
        self.addCleanup(self.temporary.cleanup)
        self.root = pathlib.Path(self.temporary.name)
        self.runs = self.root / "runs"
        (self.root / "configs").mkdir()
        shutil.copy2(ROOT / "configs/baseline.local.yaml", self.root / "configs/baseline.local.yaml")
        self.targets = [
            {"target_id": f"fixture-{index}", "repo_url": "https://example.com/repository", "commit": f"{index:040x}"}
            for index in range(8)
        ]
        for target in self.targets:
            (self.root / "targets" / target["target_id"]).mkdir(parents=True)

        self.patch = mock.patch.object(run_baseline, "ROOT", self.root)
        self.patch.start()
        self.addCleanup(self.patch.stop)

    def process(self, targets=None, **options):
        with mock.patch.object(run_baseline, "run_target", side_effect=fake_scan), contextlib.redirect_stdout(io.StringIO()):
            return run_baseline.process_targets(targets or self.targets, None, None, {}, **options)

    def test_same_commit_claim_excludes_other_experiments(self):
        target = self.targets[0]
        with TargetClaim(self.runs, target, "first") as claim:
            owner = json.loads((claim.directory / "owner.json").read_text())
            self.assertEqual(owner["pid"], os.getpid())
            self.assertEqual(owner["status"], "running")
            with self.assertRaises(ClaimBusy):
                with TargetClaim(self.runs, target, "second"):
                    self.fail("Duplicate claim")

            with TargetClaim(self.runs, self.targets[1], "first"):
                pass

        self.assertFalse(claim.directory.exists())
        self.assertEqual(target_key(target), target_key(dict(target, repo_url=target["repo_url"] + ".git/")))

    def test_running_target_is_skipped_and_worker_continues(self):
        with TargetClaim(self.runs, self.targets[0], "other"):
            outcomes = self.process()

        self.assertEqual(outcomes[0]["status"], "skipped_running")
        self.assertEqual([item["status"] for item in outcomes[1:]], ["completed"] * 7)

    def test_completed_targets_are_not_scanned_again(self):
        self.process()
        outcomes = self.process()
        self.assertEqual([item["status"] for item in outcomes], ["skipped_completed"] * 8)
        self.assertEqual(len(list(self.runs.glob(".target-status/*/*.json"))), 8)

    def test_historical_completed_run_is_recognized(self):
        directory = self.runs / "historical"
        directory.mkdir(parents=True)
        settings = run_baseline.DEFAULT_SETTINGS
        revision_path = pathlib.Path(settings["model_dir"]) / "MODEL_REVISION.txt"
        revision = revision_path.read_text().strip() if revision_path.exists() else None
        for filename, data in {
            "status.json": {"status": "completed"},
            "target.json": self.targets[0],
            "model-config.json": settings,
            "revisions.json": {"model": revision},
        }.items():
            (directory / filename).write_text(json.dumps(data))

        shutil.copy2(ROOT / "configs/baseline.local.yaml", directory / "baseline.local.yaml")
        shutil.copy2(run_baseline.PROFILE, directory / "upstream-profile.yaml")
        self.assertEqual(self.process(self.targets[:1])[0]["status"], "skipped_completed")
        (directory / "upstream-profile.yaml").write_text("different profile")
        self.assertEqual(self.process(self.targets[:1])[0]["status"], "completed")

    def test_missing_source_is_prepared_while_claim_is_held(self):
        target = self.targets[0]
        source = self.root / "targets" / target["target_id"]
        shutil.rmtree(source)

        def prepare(entry):
            self.assertEqual(entry, target)
            self.assertTrue((self.runs / ".claims" / target_key(target) / "owner.json").is_file())
            source.mkdir()

        with mock.patch.object(prepare_targets, "prepare", side_effect=prepare) as fetch:
            self.assertEqual(self.process(self.targets[:1], prepare_missing=True)[0]["status"], "completed")

        fetch.assert_called_once()

    def test_failure_continues_and_requires_explicit_retry(self):
        with mock.patch.object(run_baseline, "run_target", side_effect=[RuntimeError("fixture failure"), "completed"]), contextlib.redirect_stdout(io.StringIO()):
            first = run_baseline.process_targets(self.targets[:2], None, None, {})

        self.assertEqual([item["status"] for item in first], ["failed", "completed"])
        self.assertEqual(self.process(self.targets[:1])[0]["status"], "skipped_failed")
        self.assertEqual(self.process(self.targets[:1], retry_failed=True)[0]["status"], "completed")

    def test_interruption_records_state_and_releases_claim(self):
        claim = TargetClaim(self.runs, self.targets[0], "experiment")
        with self.assertRaises(KeyboardInterrupt):
            with claim:
                raise KeyboardInterrupt("fixture interruption")

        self.assertFalse(claim.directory.exists())
        self.assertEqual(claim.previous()["status"], "interrupted")

    def test_abandoned_claim_is_never_automatically_stolen(self):
        claim = TargetClaim(self.runs, self.targets[0], "experiment")
        claim.directory.mkdir(parents=True)
        with self.assertRaises(ClaimBusy):
            with claim:
                self.fail("Abandoned claim stolen")

        self.assertTrue(claim.directory.exists())

    def test_configuration_changes_create_distinct_attempt_records(self):
        first = run_baseline.experiment_key(run_baseline.DEFAULT_SETTINGS, None, {})
        changed = dict(run_baseline.DEFAULT_SETTINGS, model_name="different-model")
        second = run_baseline.experiment_key(changed, None, {})
        self.assertNotEqual(first, second)
        with TargetClaim(self.runs, self.targets[0], first) as claim:
            claim.finish("completed")

        with TargetClaim(self.runs, self.targets[0], second) as claim:
            self.assertIsNone(claim.previous())

    def test_two_processes_execute_each_commit_once_and_exit(self):
        context = multiprocessing.get_context("spawn")
        ready = context.Queue()
        results = context.Queue()
        start = context.Event()
        overlap = context.Barrier(2)
        workers = [context.Process(target=competing_worker, args=(str(self.root), self.targets, ready, start, overlap, results)) for _ in range(2)]
        try:
            for worker in workers:
                worker.start()

            for worker in workers:
                ready.get(timeout=30)

            start.set()
            outcomes = [results.get(timeout=30) for _ in workers]
            for worker in workers:
                worker.join(timeout=30)
                self.assertEqual(worker.exitcode, 0)

        finally:
            for worker in workers:
                if worker.is_alive():
                    worker.kill()
                    worker.join()

            ready.close()
            results.close()

        self.assertTrue(all(any(item["status"] == "completed" for item in batch) for batch in outcomes))
        completed = [item["target_id"] for batch in outcomes for item in batch if item["status"] == "completed"]
        self.assertCountEqual(completed, [item["target_id"] for item in self.targets])
        self.assertEqual(len(list(self.root.glob("*.executed"))), 8)
        self.assertEqual(list(self.runs.glob(".claims/*")), [])

    def test_per_host_lock_rejects_second_local_runner(self):
        self.runs.mkdir()
        key = run_baseline.hashlib.sha256(run_baseline.socket.gethostname().encode()).hexdigest()
        hosts = self.runs / ".host-locks"
        hosts.mkdir()
        with (hosts / f"{key}.lock").open("a") as owner:
            run_baseline.fcntl.flock(owner, run_baseline.fcntl.LOCK_EX)
            with mock.patch("sys.argv", ["run_baseline.py", "--limit", "1"]):
                with self.assertRaisesRegex(SystemExit, "this host"):
                    run_baseline.cli()

    def test_legacy_exclusive_runner_is_fenced(self):
        self.runs.mkdir()
        with (self.runs / ".runner.lock").open("a") as owner:
            run_baseline.fcntl.flock(owner, run_baseline.fcntl.LOCK_EX)
            with mock.patch("sys.argv", ["run_baseline.py", "--limit", "1"]):
                with self.assertRaisesRegex(SystemExit, "older runner"):
                    run_baseline.cli()

    def test_new_runners_on_different_hosts_can_hold_locks_together(self):
        def first_main():
            with mock.patch.object(run_baseline.socket, "gethostname", return_value="second-host"), \
                    mock.patch.object(run_baseline, "main", return_value=0):
                return run_baseline.cli()

        with mock.patch("sys.argv", ["run_baseline.py", "--limit", "1"]), \
                mock.patch.object(run_baseline, "main", side_effect=first_main):
            self.assertEqual(run_baseline.cli(), 0)

    def test_status_reports_incomplete_claim_without_starting_work(self):
        claim = TargetClaim(self.runs, self.targets[0], "experiment")
        claim.directory.mkdir(parents=True)
        output = io.StringIO()
        with mock.patch("sys.argv", ["run_baseline.py", "--status"]), contextlib.redirect_stdout(output):
            self.assertEqual(run_baseline.cli(), 0)

        self.assertEqual(json.loads(output.getvalue())["active_claims"][0]["status"], "unavailable")

    def test_preparation_failure_never_publishes_partial_source(self):
        target = self.targets[0]
        shutil.rmtree(self.root / "targets" / target["target_id"])
        with mock.patch.object(prepare_targets, "ROOT", self.root), \
                mock.patch.object(prepare_targets, "run"), \
                mock.patch.object(prepare_targets.subprocess, "check_output", return_value=target["commit"]), \
                mock.patch.object(prepare_targets.subprocess, "run"), \
                mock.patch.object(prepare_targets.tarfile, "open", side_effect=ValueError("bad archive")):
            with self.assertRaisesRegex(ValueError, "bad archive"):
                prepare_targets.prepare(target)

        self.assertFalse((self.root / "targets" / target["target_id"]).exists())
        self.assertFalse((self.root / "targets" / (target["target_id"] + ".json")).exists())


if __name__ == "__main__":
    unittest.main()

import contextlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import secnews
from tools import private_logs, state_cache


class PrivateLogTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.cwd = contextlib.chdir(self.root)
        self.cwd.__enter__()
        self.addCleanup(self.cwd.__exit__, None, None, None)
        self.state = self.root / "state" / "seen.json"
        self.state.parent.mkdir()
        self.state.write_text('{"seen": {"airport": 123}}')
        self.token, self.secret = "unit-token-for-encryption", "unit-api-secret-value"
        self.environment = {"GITHUB_ACTIONS": "true", "GITHUB_RUN_ID": "123", "GITHUB_RUN_ATTEMPT": "1",
                            "SECNEWS_STATE": str(self.state), "TELEGRAM_BOT_TOKEN": self.token,
                            "GEMINI_API_KEY": self.secret, "SECNEWS_VERBOSE": "", "SECNEWS_ONLY_CHATS": ""}
        patch = mock.patch.dict(os.environ, self.environment)
        patch.start()
        self.addCleanup(patch.stop)

    def run_hosted(self, main, **kwargs):
        stdout, stderr = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            code = private_logs.execute(main, **kwargs)
        return code, stdout.getvalue(), stderr.getvalue()

    def test_metrics_pass_but_dynamic_titles_urls_ids_and_responses_never_do(self):
        expected = ["8 recipient(s)", "collection: 24 feeds, 2000 items in 7.3s",
                    "publication dates: 4 cached, 0 fetched, 2 deferred by budget", "sent 1 of 220 new items"]
        for line in expected:
            self.assertEqual(private_logs.public_line(line), line)
        lines = ["Airport reservation details", "https://airport.example/private?token=abc",
                 "42 [private] passenger", "::notice::private-data", "Traceback (most recent call last):"]
        for line in lines:
            self.assertIsNone(private_logs.public_line(line))
        self.assertEqual(private_logs.public_line("warning: translation failed for 'Airport private title': HTTP 503"),
                         "warning: translation (HTTP 503)")
        self.assertEqual(private_logs.public_line("summaries from article pages: 0 of 1 (1 failed, https://airport.example/private)"),
                         "summaries from article pages: 0 of 1")

    def test_verbose_failure_traceback_and_held_details_are_private_and_redacted(self):
        os.environ["SECNEWS_VERBOSE"] = "1"
        original = self.state.read_bytes()
        def broken():
            print("collection: 24 feeds, 2000 items in 7.3s", file=sys.stderr)
            print("Airport private title https://airport.example/private", file=sys.stdout)
            print(f"warning: translation failed for 'Airport private title': {self.secret}", file=sys.stderr)
            raise ValueError(f"private-exception-body {self.secret}")
        code, stdout, stderr = self.run_hosted(broken, drain=lambda: print("held private detail"))
        public = stdout + stderr
        self.assertEqual(code, 1)
        for value in (self.secret, self.token, "Airport private title", "airport.example", "Traceback", "held private detail"):
            self.assertNotIn(value, public)
        self.assertIn("collection: 24 feeds, 2000 items in 7.3s", stderr)
        self.assertIn("ValueError", stderr)
        self.assertEqual(self.state.read_bytes(), original)
        archive = next(Path(".diagnostics-cache").glob("*.enc"))
        state_cache.restore(archive, self.root / "opened", self.token)
        report = json.loads((self.root / "opened/diagnostics.json").read_text())
        self.assertIn("private-exception-body", report["log"])
        self.assertIn("held private detail", report["log"])
        self.assertNotIn(self.secret, report["log"])
        self.assertIn("[REDACTED]", report["log"])

    def test_successful_warning_uses_state_journal_without_new_artifact_or_news_mutation(self):
        original = self.state.read_bytes()
        code, _, public = self.run_hosted(lambda: print("warning: source 7 failed: https://airport.example/private", file=sys.stderr))
        self.assertEqual(code, 0)
        self.assertEqual(self.state.read_bytes(), original)
        journal = json.loads(self.state.with_name("private-diagnostics.json").read_text())
        self.assertIn("airport.example", journal["runs"][0]["log"])
        self.assertNotIn("airport.example", public)
        self.assertFalse(Path(".diagnostics-cache").exists())

    def test_healthy_summary_needs_no_private_journal(self):
        code, _, _ = self.run_hosted(lambda: print("8 recipient(s)", file=sys.stderr))
        self.assertEqual(code, 0)
        self.assertFalse(self.state.with_name("private-diagnostics.json").exists())

    def test_backup_control_output_and_chat_details_are_kept_functional(self):
        code, stdout, _ = self.run_hosted(lambda: print("changed"), label="backup")
        self.assertEqual((code, stdout), (0, "changed\n"))
        def chats():
            print("최근 봇에 메시지를 보낸 채팅 1개")
            print("42 [private] private-passenger-name")
        code, public, _ = self.run_hosted(chats, label="chats")
        self.assertEqual(code, 0)
        self.assertEqual(public, "telegram chats: 1\n")
        state_cache.restore(next(Path(".diagnostics-cache").glob("*.enc")), self.root / "chat-report", self.token)
        self.assertIn("private-passenger-name", (self.root / "chat-report/diagnostics.json").read_text())

    def test_admin_test_diagnostics_do_not_change_production_journal(self):
        journal = self.state.with_name("private-diagnostics.json")
        journal.write_text('{"v": 1, "runs": []}')
        before = journal.read_bytes()
        os.environ["SECNEWS_ONLY_CHATS"] = "42"
        self.run_hosted(lambda: print("warning: operation failed", file=sys.stderr))
        self.assertEqual(journal.read_bytes(), before)
        self.assertTrue(list(Path(".diagnostics-cache").glob("*.enc")))

    def test_diagnostics_are_bounded_and_exported_by_read_only_review(self):
        for i in range(private_logs.KEEP_RUNS + 2):
            os.environ["GITHUB_RUN_ID"] = str(i + 100)
            self.run_hosted(lambda: print("warning: operation " + "x" * (private_logs.MAX_LOG * 2), file=sys.stderr))
        journal = json.loads(self.state.with_name("private-diagnostics.json").read_text())
        self.assertEqual(len(journal["runs"]), private_logs.KEEP_RUNS)
        self.assertTrue(all(len(r["log"]) <= private_logs.MAX_LOG for r in journal["runs"]))
        repo = Path(secnews.__file__).parent
        command = [sys.executable, str(repo / "secnews.py"), "--write-review", "--config", str(repo / "tests/test_feeds.json")]
        result = subprocess.run(command, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        report = json.loads(next((self.state.parent / "reviews").glob("*.json")).read_text())
        self.assertEqual(report["diagnostics"], journal)
        self.assertNotIn("x" * 100, result.stdout + result.stderr)

    def test_real_cli_startup_error_is_filtered_and_preserves_exit_failure(self):
        config = self.root / "private-configuration.json"
        config.write_text("private-invalid-json")
        result = subprocess.run([sys.executable, str(Path(secnews.__file__)), "--config", str(config)],
                                capture_output=True, text=True)
        self.assertEqual(result.returncode, 1)
        self.assertNotIn(str(config), result.stdout + result.stderr)
        self.assertNotIn("Traceback", result.stdout + result.stderr)
        self.assertIn("JSONDecodeError", result.stderr)
        self.assertTrue(list(Path(".diagnostics-cache").glob("*.enc")))

    def test_failed_encryption_never_prints_private_detail_or_uploads_plaintext(self):
        os.environ["TELEGRAM_BOT_TOKEN"] = ""
        def broken():
            raise ValueError("private-invalid-response")
        code, stdout, stderr = self.run_hosted(broken)
        self.assertEqual(code, 1)
        self.assertNotIn("private-invalid-response", stdout + stderr)
        self.assertIn("private diagnostic storage failed", stderr)
        self.assertFalse(list(Path(".diagnostics-cache").glob("*")))

    def test_local_console_behavior_stays_available(self):
        os.environ["GITHUB_ACTIONS"] = ""
        code, stdout, _ = self.run_hosted(lambda: print("local-only detail"))
        self.assertEqual(code, None)
        self.assertIn("local-only detail", stdout)

    def test_diagnostic_failure_cannot_turn_successful_delivery_into_failed_run(self):
        def drain():
            raise ValueError("private-drain-error")
        with mock.patch.object(private_logs, "save_diagnostics", side_effect=OSError("private-storage-error")):
            code, stdout, stderr = self.run_hosted(lambda: print("sent 1 of 10 new items"), drain=drain)
        self.assertEqual(code, 0)
        self.assertIn("sent 1 of 10 new items", stdout)
        self.assertIn("private diagnostic storage failed", stderr)
        self.assertNotIn("private-drain-error", stdout + stderr)
        self.assertNotIn("private-storage-error", stdout + stderr)


if __name__ == "__main__":
    unittest.main()

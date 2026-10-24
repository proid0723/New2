import io
import json
import os
import stat
import subprocess
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import secnews
from tools import state_cache


class StateCacheTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.state = self.root / "runtime"
        self.state.mkdir()
        self.archive = self.root / "ciphertext" / "state.enc"
        self.token = "unit-test-token"

    def test_complete_state_migrates_without_resetting_news_budget_or_subscribers(self):
        seen = {"seen": {"https://airport.example/article": 123}, "last_digest": 123,
                "decisions": {"https://airport.example/article": ["sent", 123, "Airport opens terminal"]},
                "prejudged": {"for": "2026-10-24 11", "items": {}}, "stats": {"sent": 7}}
        (self.state / "seen.json").write_text(json.dumps(seen))
        (self.state / "article-dates.json").write_text('{"https://airport.example/article": {"date": "2026-10-24"}}')
        budget = secnews.GeminiBudget(self.state / "gemini_usage.json", [("model-a", 5)])
        budget.take()
        secnews.save_subscribers(self.state / "subscribers.json", {"ids": ["42"]}, secnews.subscriber_key(self.token))
        (self.state / "reviews").mkdir()
        (self.state / "reviews" / "week.json").write_text('{"review": "Airport opens terminal"}')
        (self.state / "seen.lock").touch()
        original = {p.relative_to(self.state).as_posix(): p.read_bytes() for p in self.state.rglob("*") if p.is_file()}
        self.assertEqual(state_cache.seal(self.state, self.archive, self.token), len(original))
        raw = self.archive.read_bytes()
        self.assertNotIn(b"airport.example", raw)
        self.assertNotIn(b"Airport opens terminal", raw)
        self.assertNotIn(b"seen.json", raw)
        restored = self.root / "restored"
        self.assertEqual(state_cache.restore(self.archive, restored, self.token), len(original))
        self.assertEqual({p.relative_to(restored).as_posix(): p.read_bytes() for p in restored.rglob("*") if p.is_file()}, original)
        self.assertEqual(secnews.load_state(restored / "seen.json"), seen)
        self.assertEqual(secnews.GeminiBudget(restored / "gemini_usage.json", budget.models).used, {"model-a": 1})
        self.assertEqual(secnews.load_subscribers(restored / "subscribers.json", secnews.subscriber_key(self.token))["ids"], ["42"])
        self.assertEqual(stat.S_IMODE((restored / "seen.json").stat().st_mode), 0o600)

    def test_every_seal_uses_a_fresh_nonce(self):
        (self.state / "seen.json").write_text('{"seen": {}}')
        state_cache.seal(self.state, self.archive, self.token)
        first = self.archive.read_bytes()
        state_cache.seal(self.state, self.archive, self.token)
        self.assertNotEqual(first, self.archive.read_bytes())

    def test_wrong_key_and_modified_ciphertext_fail_without_creating_empty_state(self):
        (self.state / "seen.json").write_text('{"seen": {"airport": 123}}')
        state_cache.seal(self.state, self.archive, self.token)
        good = self.archive.read_bytes()
        for token, raw in (("wrong-key", good), (self.token, good[:-1] + bytes([good[-1] ^ 1]))):
            with self.subTest(token=token):
                self.archive.write_bytes(raw)
                output = self.root / "not-created"
                with self.assertRaises(state_cache.StateCacheError):
                    state_cache.restore(self.archive, output, token)
                self.assertFalse(output.exists())

    def test_invalid_or_truncated_envelopes_and_missing_key_are_rejected(self):
        for raw in (b'{"seen": {}}', state_cache.HEADER, state_cache.HEADER + b"x" * 27):
            self.archive.parent.mkdir(exist_ok=True)
            self.archive.write_bytes(raw)
            with self.assertRaises(state_cache.StateCacheError):
                state_cache.restore(self.archive, self.root / "missing", self.token)
        with self.assertRaises(state_cache.StateCacheError):
            state_cache.seal(self.state, self.archive, "")

    def encrypted_zip(self, entries):
        packed = io.BytesIO()
        with zipfile.ZipFile(packed, "w") as output:
            for name, data in entries:
                output.writestr(name, data)
        nonce = os.urandom(12)
        self.archive.parent.mkdir(exist_ok=True)
        self.archive.write_bytes(state_cache.HEADER + nonce + state_cache.AESGCM(state_cache.cache_key(self.token))
                                 .encrypt(nonce, packed.getvalue(), state_cache.HEADER))

    def test_authenticated_archive_still_rejects_traversal_symlinks_and_duplicate_paths(self):
        symlink = zipfile.ZipInfo("link")
        symlink.create_system = 3
        symlink.external_attr = (stat.S_IFLNK | 0o777) << 16
        for entries in ([('valid.json', b'{}'), ('../outside', b'bad')], [('/absolute', b'bad')],
                        [('a\\b', b'bad')], [(symlink, b'../outside')], [('same', b'a'), ('same', b'b')]):
            with self.subTest(entries=str(entries)):
                import warnings
                with warnings.catch_warnings():
                    warnings.simplefilter("ignore", UserWarning)
                    self.encrypted_zip(entries)
                with self.assertRaises(state_cache.StateCacheError):
                    state_cache.restore(self.archive, self.root / "not-created", self.token)
                self.assertFalse((self.root / "not-created").exists())
                self.assertFalse((self.root / "outside").exists())

    def test_existing_state_and_last_good_archive_are_preserved_on_failure(self):
        (self.state / "seen.json").write_text("unchanged")
        state_cache.seal(self.state, self.archive, self.token)
        previous = self.archive.read_bytes()
        with self.assertRaises(state_cache.StateCacheError):
            state_cache.restore(self.archive, self.state, self.token)
        self.assertEqual((self.state / "seen.json").read_text(), "unchanged")
        (self.state / "link").symlink_to(self.root / "outside")
        with self.assertRaises(state_cache.StateCacheError):
            state_cache.seal(self.state, self.archive, self.token)
        self.assertEqual(self.archive.read_bytes(), previous)

    def test_cli_uses_environment_key_and_never_falls_back_to_plaintext(self):
        (self.state / "seen.json").write_text("Airport opens terminal")
        script = Path(state_cache.__file__)
        command = [sys.executable, str(script), "seal", "--state", str(self.state), "--archive", str(self.archive)]
        env = dict(os.environ, TELEGRAM_BOT_TOKEN=self.token)
        result = subprocess.run(command, env=env, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0)
        self.assertNotIn(self.token, result.stdout + result.stderr)
        env["TELEGRAM_BOT_TOKEN"] = ""
        result = subprocess.run(command, env=env, capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn("Airport opens terminal", result.stdout + result.stderr)


if __name__ == "__main__":
    unittest.main()

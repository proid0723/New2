import contextlib
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import secnews


def update(number, text, who=42):
    return {"update_id": number, "message": {"text": text, "chat": {"id": who, "first_name": "Example"}}}


class SecurityFixTests(unittest.TestCase):
    def test_required_approval_rejects_missing_or_malformed_admin_before_api_or_state_mutation(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            config = root / "feeds.json"
            config.write_text(json.dumps({"feeds": [], "require_approval": True, "translate_to_korean": False}))
            for admin in ("", "99,100", "not-an-id"):
                with self.subTest(admin=admin), mock.patch.dict(os.environ, {
                    "TELEGRAM_BOT_TOKEN": "unit-token", "SECNEWS_STATE": str(root / "seen.json"),
                    "SECNEWS_ADMIN_CHAT": admin, "SECNEWS_ONLY_CHATS": "", "SECNEWS_TEST_USAGE_DIR": "",
                    "SECNEWS_TEST_USAGE_EVENT": "", "SECNEWS_OFFLINE": "1"}), \
                     mock.patch.object(secnews, "fetch_updates") as fetch:
                    with self.assertRaisesRegex(RuntimeError, "administrator"):
                        secnews.main(["--config", str(config)])
                    fetch.assert_not_called()
                    self.assertFalse((root / "subscribers.json").exists())

    def test_request_toggle_burst_is_deduplicated_and_cooldown_survives_runs(self):
        sent = []
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "subscribers.json"
            key = secnews.subscriber_key("unit-token")
            send = lambda cid, text, *args: sent.append(cid)
            burst = [update(i + 1, "/start" if i % 2 == 0 else "/stop") for i in range(41)]
            secnews.sync_subscribers(path, burst, key=key, admin="99", send=send, now=1000)
            self.assertEqual(sent, ["42", "99"])
            secnews.sync_subscribers(path, [update(42, "/stop"), update(43, "/start")],
                                     key=key, admin="99", send=send, now=1100)
            self.assertEqual(sent, ["42", "99"])
            secnews.sync_subscribers(path, [update(44, "/stop"), update(45, "/start")],
                                     key=key, admin="99", send=send, now=3000)
            self.assertEqual(sent, ["42", "99", "42", "99"])

    def test_notification_cap_queues_remaining_requests_and_retries_failed_delivery(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "subscribers.json"
            key = secnews.subscriber_key("unit-token")
            sent = []
            send = lambda cid, text, *args: sent.append(cid)
            secnews.sync_subscribers(path, [update(i, "/start", i) for i in range(1, 16)], key=key,
                                     admin="99", send=send, now=1000)
            self.assertEqual(sent.count("99"), 10)
            sent.clear()
            secnews.sync_subscribers(path, [], key=key, admin="99", send=send, now=1100)
            self.assertEqual(sent.count("99"), 5)
            def failing(cid, text, *args):
                if cid == "99": raise secnews.TelegramError("offline failure")
            secnews.sync_subscribers(path, [update(20, "/start", 20)], key=key,
                                     admin="99", send=failing, now=1200)
            sent.clear()
            secnews.sync_subscribers(path, [], key=key, admin="99", send=send, now=1300)
            self.assertEqual(sent, ["20", "99"])

    def test_wrong_keys_corruption_and_incompatible_backup_never_reset_membership(self):
        with tempfile.TemporaryDirectory() as temp:
            current, backup = Path(temp) / "subscribers.json", Path(temp) / "backup.json"
            key = secnews.subscriber_key("unit-token")
            other = secnews.subscriber_key("other-unit-token")
            secnews.save_subscribers(current, {"ids": ["42"]}, key)
            backup.write_bytes(current.read_bytes())
            original, saved = current.read_bytes(), backup.read_bytes()
            with self.assertRaises(secnews.SubscriberStateError):
                secnews.sync_subscribers(current, [], key=other, admin="99")
            self.assertEqual(current.read_bytes(), original)
            secnews.save_subscribers(current, {"ids": []}, other)
            with self.assertRaises(secnews.SubscriberStateError):
                secnews.backup_subscribers(current, backup, other)
            self.assertEqual(backup.read_bytes(), saved)
            current.write_text("invalid-json")
            with self.assertRaises(secnews.SubscriberStateError):
                secnews.add_subscribers(current, ["43"], key)
            self.assertEqual(current.read_text(), "invalid-json")

    def test_invalid_ai_types_indices_categories_and_cached_flags_are_rejected(self):
        good = {"i": 0, "relevant": True, "focus": False, "urgent": False, "already_sent": False}
        item = {"title": "Airport notice", "summary": "", "score": 1}
        invalid = [dict(good, urgent="false"), dict(good, focus=0), dict(good, relevant=None),
                   dict(good, i=False), dict(good, dup_of=0), dict(good, sector="unknown")]
        for verdict in invalid:
            with self.subTest(verdict=verdict), mock.patch.object(secnews, "gemini_json", return_value=[verdict]):
                with self.assertRaises(ValueError):
                    secnews.gemini_classify([item], "k", "model", [], [])
        classifier = secnews.GeminiClassifier("k", {})
        classifier.cache = {"Airport notice": [dict(good, urgent="false"), "model"]}
        with mock.patch.object(secnews, "gemini_classify", return_value=[good]) as classify:
            kept = classifier([dict(item)])
        classify.assert_called_once()
        self.assertEqual(kept[0]["score"], 1)

    def test_oversized_original_and_translated_titles_cannot_stop_other_articles(self):
        item = {"title": "공항 보안 점검 안내 " * 600, "source": "Example", "summary": "", "score": 1,
                "link": "https://airport.example/a", "date": None}
        for style in ("plain", "quote"):
            with self.subTest(style=style), mock.patch.object(secnews, "ITEM_STYLE", style):
                other = dict(item, title="Airport update", display_title="Airport update", link="https://airport.example/b")
                item["display_title"] = "🛫" * 5000
                messages = secnews.build_messages([item, other])
                self.assertTrue(all(secnews.visible_len(m) <= 3896 for m in messages))
                self.assertIn("Airport update", "\n".join(messages))
                self.assertIn("https://airport.example/a", "\n".join(messages))
                self.assertNotIn("\ud83d", "\n".join(messages))

    def test_dtd_is_rejected_before_entity_expansion(self):
        raw = b'<!DOCTYPE rss [<!ENTITY x "large">]><rss><channel><item><title>&x;</title></item></channel></rss>'
        with self.assertRaisesRegex(ValueError, "DTD"):
            secnews.parse_feed(raw, "Example")

    def test_collection_verification_uses_no_ai_or_production_state(self):
        from tools import verify_collection
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "feeds.json").write_text(json.dumps({"feeds": [{"name": "Example", "url": "https://airport.example/rss"}]}))
            def collect(config, failed, counts):
                self.assertEqual(config["article_date_budget_seconds"], 0)
                counts["0"] = 1
                return [{"title": "Airport update"}]
            with mock.patch.object(sys, "argv", ["verify_collection", str(root)]), \
                 mock.patch.object(secnews, "collect", side_effect=collect), \
                 mock.patch.object(secnews, "gemini_json") as ai, \
                 mock.patch.object(secnews, "telegram_send") as send:
                self.assertEqual(verify_collection.main(), 0)
            ai.assert_not_called()
            send.assert_not_called()
            report = json.loads((root / "reports/summary-diagnostic-result.json").read_text())
            self.assertEqual(report["successful_feeds"], 1)
            self.assertFalse(report["production_state_written"])


if __name__ == "__main__":
    unittest.main()

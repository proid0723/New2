from datetime import datetime, timedelta
from email.utils import format_datetime
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

import secnews


def reject(index=0):
    return {"i": index, "relevant": False, "focus": False, "urgent": False, "already_sent": False}


class NoNewsModelTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.path = Path(temp.name) / "seen.json"
        self.top = datetime(2026, 10, 24, 18, tzinfo=secnews.KST)
        secnews.save_state(self.path, {}, self.top - timedelta(hours=1))
        self.config = {"feeds": [{"name": "Example", "url": "https://airport.example/rss"}],
                       "keywords": {"high": ["airport"]}, "min_score": 1, "digest_on_the_hour": True,
                       "instant_alerts": False, "no_news_notice": "all"}
        self.messages, self.alerts = [], []

    def feed(self, *titles):
        stamp = format_datetime(self.top - timedelta(minutes=40))
        return ("<rss><channel>" + "".join(f"<item><title>{t}</title><link>https://airport.example/{i}</link>"
                f"<pubDate>{stamp}</pubDate></item>" for i, t in enumerate(titles)) + "</channel></rss>").encode()

    def run_digest(self, raw, classify=None, now=None):
        return secnews.run(self.config, self.path,
                           lambda text, silent=False: self.messages.append((text, silent)) or True,
                           now=now or self.top, fetcher=lambda _: raw, classify=classify, alert=self.alerts.append)

    def test_all_actual_rejection_models_are_shown_without_unrelated_stale_results(self):
        models = iter(["gemini-2.5-flash", "gemini-3.6-flash"])
        classify = secnews.GeminiClassifier("unit-key", self.config, chunk=1)
        classify.results["stale"] = [reject(), "gemini-3.8-flash"]
        def answer(*args):
            secnews.gemini_json.last_model = next(models)
            return [reject()]
        with mock.patch.object(secnews.gemini_json, "last_model", "unrelated-model", create=True), \
             mock.patch.object(secnews, "gemini_classify", side_effect=answer):
            self.run_digest(self.feed("Airport alpha", "Airport beta"), classify)
        text, silent = self.messages[0]
        self.assertTrue(silent)
        self.assertIn("Gemini 2.5 Flash", text)
        self.assertIn("Gemini 3.6 Flash", text)
        self.assertNotIn("3.8", text)
        self.assertNotIn("stale", classify.results)

    def test_cached_and_fresh_judgements_both_appear_without_requerying_cached_items(self):
        classify = secnews.GeminiClassifier("unit-key", self.config)
        with mock.patch.object(secnews.gemini_json, "last_model", "gemini-2.5-flash", create=True), \
             mock.patch.object(secnews, "gemini_classify", return_value=[reject()]):
            self.run_digest(self.feed("Airport alpha"), classify, self.top - timedelta(minutes=30))
        self.assertEqual(self.messages, [])
        with mock.patch.object(secnews.gemini_json, "last_model", "gemini-3.5-flash-lite", create=True), \
             mock.patch.object(secnews, "gemini_classify", return_value=[reject()]) as request:
            self.run_digest(self.feed("Airport alpha", "Airport beta"), secnews.GeminiClassifier("unit-key", self.config))
        self.assertEqual([it["title"] for it in request.call_args.args[0]], ["Airport beta"])
        text, silent = self.messages[0]
        self.assertIn("Gemini 2.5 Flash", text)
        self.assertIn("Gemini 3.5 Flash Lite", text)
        self.assertIn("사전 판단 재사용 포함", text)
        self.assertTrue(silent)

    def test_prefiltered_or_missing_news_does_not_credit_the_previous_global_model(self):
        with mock.patch.object(secnews.gemini_json, "last_model", "gemini-3.8-flash", create=True), \
             mock.patch.object(secnews, "gemini_classify") as request:
            self.run_digest(self.feed("Routine notice"), secnews.GeminiClassifier("unit-key", self.config))
            text = self.messages[-1][0]
            self.assertIn("AI 판단 없음", text)
            self.assertIn("기본 필터에서 제외", text)
            self.assertNotIn("3.8", text)
            self.run_digest(self.feed(), secnews.GeminiClassifier("unit-key", self.config), self.top + timedelta(hours=1))
            self.assertIn("AI 판단 없음 · 새 기사 없음", self.messages[-1][0])
            request.assert_not_called()

    def test_admin_only_mode_includes_the_same_model_details(self):
        self.config["no_news_notice"] = "admin"
        with mock.patch.object(secnews.gemini_json, "last_model", "gemini-3.6-flash", create=True), \
             mock.patch.object(secnews, "gemini_classify", return_value=[reject()]):
            self.run_digest(self.feed("Airport alpha"), secnews.GeminiClassifier("unit-key", self.config))
        self.assertEqual(self.messages, [])
        self.assertIn("Gemini 3.6 Flash", self.alerts[0])

    def test_model_failure_still_defers_instead_of_sending_a_no_news_verdict(self):
        with mock.patch.object(secnews, "gemini_classify", side_effect=TimeoutError("offline")):
            self.run_digest(self.feed("Airport alpha"), secnews.GeminiClassifier("unit-key", self.config))
        self.assertEqual(self.messages, [])
        self.assertTrue(self.alerts[0].startswith("⏳"))


if __name__ == "__main__":
    unittest.main()

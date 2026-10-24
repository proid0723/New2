from datetime import datetime, timedelta
from email.utils import format_datetime
from pathlib import Path
import tempfile
import unittest
from unittest import mock

import secnews


class DigestFreshnessTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.path = Path(temp.name) / "seen.json"
        self.config = {"feeds": [{"name": "Example", "url": "https://airport.example/rss"}],
                       "keywords": {"high": ["airport"]}, "min_score": 1, "quiet_hours": [22, 6],
                       "digest_on_the_hour": True, "instant_alerts": False, "digest_max_age_hours": 3,
                       "max_age_hours": 48, "require_publish_date": True}
        self.now = datetime(2026, 10, 24, 19, tzinfo=secnews.KST)

    def feed(self, rows):
        return ("<rss><channel>" + "".join(f"<item><title>{title}</title><link>https://airport.example/{n}</link>"
                + (f"<pubDate>{format_datetime(date)}</pubDate>" if date else "") + "</item>"
                for n, (title, date) in enumerate(rows)) + "</channel></rss>").encode()

    def run_at(self, now, rows, classify):
        raw = self.feed(rows)
        return secnews.run(self.config, self.path, lambda *a, **kw: True, now=now, fetcher=lambda _: raw,
                           classify=classify, bootstrap_send=True)

    def test_daytime_window_rejects_old_unknown_and_future_dates_before_ai(self):
        rows = [("Airport boundary", self.now - timedelta(hours=3)),
                ("Airport current", self.now - timedelta(minutes=10)),
                ("Airport late", self.now - timedelta(hours=3, seconds=1)),
                ("Airport yesterday", self.now - timedelta(hours=38)),
                ("Airport undated", None), ("Airport future", self.now + timedelta(minutes=1))]
        classify = mock.Mock(return_value=[])
        self.run_at(self.now, rows, classify)
        self.assertEqual({it["title"] for it in classify.call_args.args[0]}, {"Airport boundary", "Airport current"})

    def test_morning_includes_night_since_last_evening_digest_but_not_previous_day(self):
        morning = self.now.replace(hour=6)
        start = morning.replace(hour=21) - timedelta(days=1)
        rows = [("Airport evening", start), ("Airport overnight", morning - timedelta(hours=2)),
                ("Airport stale", start - timedelta(seconds=1))]
        classify = mock.Mock(return_value=[])
        self.run_at(morning, rows, classify)
        self.assertEqual({it["title"] for it in classify.call_args.args[0]}, {"Airport evening", "Airport overnight"})
        self.assertEqual(secnews.digest_cutoff(self.config, morning.replace(hour=7)), morning.replace(hour=4))

    def test_morning_preparation_uses_next_digest_window_without_sending(self):
        morning = self.now.replace(hour=6)
        start = morning.replace(hour=21) - timedelta(days=1)
        secnews.save_state(self.path, {}, start)
        raw = self.feed([("Airport evening", start), ("Airport stale", start - timedelta(seconds=1))])
        classify = secnews.GeminiClassifier("unit-key", self.config)
        send = mock.Mock()
        with mock.patch.object(secnews, "gemini_classify", return_value=[{
            "i": 0, "relevant": False, "focus": False, "urgent": False, "already_sent": False}]) as ai:
            secnews.run(self.config, self.path, send, now=morning - timedelta(minutes=30),
                        fetcher=lambda _: raw, classify=classify)
        self.assertEqual([it["title"] for it in ai.call_args.args[0]], ["Airport evening"])
        send.assert_not_called()

    def test_short_admission_window_preserves_two_day_duplicate_context(self):
        secnews.save_state(self.path, {}, self.now - timedelta(hours=1),
                           recent=[["Earlier bulletin", [], (self.now - timedelta(hours=10)).timestamp(), "", False]])
        classify = mock.Mock(return_value=[])
        self.run_at(self.now, [("Airport current notice", self.now - timedelta(minutes=5))], classify)
        self.assertIn("Earlier bulletin", str(classify.call_args.args[1]))
        self.assertEqual(secnews.digest_cutoff({"max_age_hours": 48}, self.now), self.now - timedelta(hours=48))


if __name__ == "__main__":
    unittest.main()

import io
import json
from datetime import datetime, timedelta
from email.utils import format_datetime
from pathlib import Path
import tempfile
import unittest
from unittest import mock
import urllib.error

import secnews


def verdict(index=0, **changes):
    return dict({"i": index, "relevant": True, "focus": False, "urgent": False,
                 "already_sent": False, "dup_of": None}, **changes)


def response(rows, version):
    return io.BytesIO(json.dumps({"modelVersion": version, "candidates": [
        {"content": {"parts": [{"text": json.dumps(rows)}]}}]}).encode())


class SchemaFallbackTests(unittest.TestCase):
    def test_one_overload_then_invalid_second_route_reaches_third_route(self):
        routes = ["gemini-flash-latest", "gemini-2.5-flash", "gemini-3.6-flash", "gemini-flash-lite-latest"]
        with tempfile.TemporaryDirectory() as folder:
            budget = secnews.GeminiBudget(Path(folder) / "usage.json", [(m, 18) for m in routes])
            calls = []
            def request(req, timeout):
                model = req.full_url.split("/models/")[1].split(":")[0]
                calls.append(model)
                if len(calls) == 1:
                    raise urllib.error.HTTPError(req.full_url, 503, "busy", {}, None)
                if len(calls) == 2:
                    return response([verdict(urgent="false")], "second-version")
                return response([verdict()], "third-version")
            with mock.patch.object(secnews, "GEMINI_BUDGET", budget), \
                 mock.patch.object(secnews.urllib.request, "urlopen", side_effect=request):
                result = secnews.gemini_classify([{"title": "Airport notice", "summary": ""}],
                                                 "unit-key", routes[0], [], [])
            self.assertEqual(calls, routes[:3])
            self.assertIs(result[0]["urgent"], False)
            self.assertEqual(secnews.gemini_json.last_model, "third-version")
            self.assertEqual(budget.used, dict.fromkeys(routes[:3], 1))
            self.assertLess(budget.resting[routes[1]], budget.resting[routes[0]])

    def test_invalid_fields_on_all_routes_never_become_valid_cached_results(self):
        with tempfile.TemporaryDirectory() as folder:
            routes = [("first-flash", 18), ("second-flash", 18), ("unit-lite", 450)]
            budget = secnews.GeminiBudget(Path(folder) / "usage.json", routes)
            classify = secnews.GeminiClassifier("unit-key", {})
            with mock.patch.object(secnews, "GEMINI_BUDGET", budget), \
                 mock.patch.object(secnews.urllib.request, "urlopen", side_effect=lambda *a, **k: response([verdict(focus="false")], "bad")):
                kept = classify([{"title": "Airport notice", "summary": "", "score": 1}])
            self.assertTrue(classify.failed)
            self.assertEqual(classify.results, {})
            self.assertTrue(kept[0]["keyword_only"])
            self.assertEqual(sum(budget.used.values()), 3)

    def test_schema_retries_still_respect_the_shared_deadline(self):
        with tempfile.TemporaryDirectory() as folder:
            budget = secnews.GeminiBudget(Path(folder) / "usage.json", [("first-flash", 18), ("second-flash", 18)])
            clock = [0.0]
            def request(*args, **kwargs):
                clock[0] += 2
                return response([verdict(urgent="false")], "bad")
            with mock.patch.object(secnews, "GEMINI_BUDGET", budget), \
                 mock.patch.object(secnews.time, "monotonic", side_effect=lambda: clock[0]), \
                 mock.patch.object(secnews.urllib.request, "urlopen", side_effect=request) as http:
                with self.assertRaises(TimeoutError):
                    secnews.gemini_classify([{"title": "Airport notice", "summary": ""}],
                                             "unit-key", "first-flash", [], [], deadline=1)
            self.assertEqual(http.call_count, 1)

    def test_nontext_model_payload_moves_to_the_next_route(self):
        with tempfile.TemporaryDirectory() as folder:
            budget = secnews.GeminiBudget(Path(folder) / "usage.json", [("first-flash", 18), ("second-flash", 18)])
            bad = io.BytesIO(json.dumps({"candidates": [{"content": {"parts": [{"text": 42}]}}]}).encode())
            with mock.patch.object(secnews, "GEMINI_BUDGET", budget), \
                 mock.patch.object(secnews.urllib.request, "urlopen", side_effect=[bad, response([verdict()], "valid-version")]):
                answer = secnews.gemini_classify([{"title": "Airport notice", "summary": ""}],
                                                 "unit-key", "first-flash", [], [])
            self.assertIs(answer[0]["relevant"], True)
            self.assertEqual(budget.used, {"first-flash": 1, "second-flash": 1})


class PrejudgeRetryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / "seen.json"
        self.top = datetime(2026, 10, 24, 18, tzinfo=secnews.KST)
        self.config = {"feeds": [{"name": "Example", "url": "https://airport.example/rss"}],
                       "keywords": {"high": ["airport"]}, "min_score": 1,
                       "digest_on_the_hour": True, "instant_alerts": False, "no_news_notice": "admin"}
        secnews.save_state(self.path, {}, self.top - timedelta(hours=1))
        self.sent, self.alerts = [], []

    def feed(self, *titles):
        stamp = format_datetime(self.top - timedelta(minutes=40))
        return ("<rss><channel>" + "".join(f"<item><title>{title}</title>"
                f"<link>https://airport.example/{i}</link><pubDate>{stamp}</pubDate></item>"
                for i, title in enumerate(titles)) + "</channel></rss>").encode()

    def run_at(self, minute, raw, classify):
        now = self.top - timedelta(hours=1) + timedelta(minutes=minute)
        return secnews.run(self.config, self.path, self.sent.append, now=now, fetcher=lambda _: raw,
                           classify=classify, alert=self.alerts.append)

    def test_failed_zero_judgements_retry_at_five_minutes_and_then_stop_on_success(self):
        raw = self.feed("Airport alpha")
        original = secnews.load_state(self.path)
        with mock.patch.object(secnews, "gemini_classify", side_effect=ValueError("invalid fields")) as failed:
            self.run_at(30, raw, secnews.GeminiClassifier("unit-key", self.config))
            self.run_at(34, raw, secnews.GeminiClassifier("unit-key", self.config))
            self.assertEqual(failed.call_count, 1)
        pre = secnews.load_state(self.path)["prejudged"]
        self.assertFalse(pre["complete"])
        self.assertEqual(pre["attempts"], 1)
        self.assertEqual(pre["items"], {})
        with mock.patch.object(secnews, "gemini_classify", return_value=[verdict()]) as good:
            self.run_at(35, raw, secnews.GeminiClassifier("unit-key", self.config))
            self.run_at(40, raw, secnews.GeminiClassifier("unit-key", self.config))
            self.assertEqual(good.call_count, 1)
        state = secnews.load_state(self.path)
        self.assertTrue(state["prejudged"]["complete"])
        self.assertEqual(state["prejudged"]["attempts"], 2)
        self.assertEqual({k: v for k, v in state.items() if k != "prejudged"}, original)
        self.assertEqual(self.sent, [])
        self.assertEqual(self.alerts, [])

    def test_partial_results_are_preserved_and_only_missing_items_are_retried(self):
        raw = self.feed("Airport alpha", "Airport beta")
        asked = []
        def partial(part, *args):
            asked.extend(it["title"] for it in part)
            if len(asked) == 2:
                raise ValueError("invalid fields")
            return [verdict()]
        with mock.patch.object(secnews, "gemini_classify", side_effect=partial):
            self.run_at(30, raw, secnews.GeminiClassifier("unit-key", self.config, chunk=1))
        pre = secnews.load_state(self.path)["prejudged"]
        self.assertEqual(len(pre["items"]), 1)
        self.assertFalse(pre["complete"])
        cached = next(iter(pre["items"].values()))
        with mock.patch.object(secnews, "gemini_classify", return_value=[verdict()]) as retry:
            self.run_at(35, raw, secnews.GeminiClassifier("unit-key", self.config, chunk=1))
        self.assertEqual([it["title"] for it in retry.call_args.args[0]], ["Airport beta"])
        saved = secnews.load_state(self.path)["prejudged"]
        self.assertEqual(len(saved["items"]), 2)
        self.assertIn(cached, saved["items"].values())
        self.assertTrue(saved["complete"])

    def test_genuine_no_candidates_is_complete_without_sending_or_repeated_queries(self):
        original = secnews.load_state(self.path)
        with mock.patch.object(secnews, "gemini_classify") as request:
            self.run_at(30, self.feed(), secnews.GeminiClassifier("unit-key", self.config))
            self.run_at(35, self.feed(), secnews.GeminiClassifier("unit-key", self.config))
        request.assert_not_called()
        saved = secnews.load_state(self.path)
        self.assertTrue(saved["prejudged"]["complete"])
        self.assertEqual(saved["prejudged"]["attempts"], 1)
        self.assertEqual({k: v for k, v in saved.items() if k != "prejudged"}, original)
        self.assertEqual(self.sent + self.alerts, [])

    def test_retries_are_bounded_to_three_attempts_before_the_next_digest(self):
        with mock.patch.object(secnews, "gemini_classify", side_effect=TimeoutError("offline")) as request:
            for minute in (30, 35, 40, 45, 50, 55):
                self.run_at(minute, self.feed("Airport alpha"), secnews.GeminiClassifier("unit-key", self.config))
        self.assertEqual(request.call_count, 3)
        self.assertEqual(secnews.load_state(self.path)["prejudged"]["attempts"], 3)
        self.assertEqual(self.sent + self.alerts, [])

    def test_legacy_empty_failure_can_retry_but_a_confirmed_empty_success_cannot(self):
        state = secnews.load_state(self.path)
        state["prejudged"] = {"for": "2026-10-24 18", "items": {}}
        self.path.write_text(json.dumps(state))
        with mock.patch.object(secnews, "gemini_classify", return_value=[verdict()]) as request:
            self.run_at(40, self.feed("Airport alpha"), secnews.GeminiClassifier("unit-key", self.config))
        self.assertEqual(request.call_count, 1)
        pre = secnews.load_state(self.path)["prejudged"]
        self.assertEqual(pre["attempts"], 2)
        self.assertTrue(pre["complete"])


if __name__ == "__main__":
    unittest.main()

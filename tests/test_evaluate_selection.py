import contextlib
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

import secnews
from tools import evaluate_selection as evaluation


def case(identity, keep, status="policy", **expected):
    return {"id": identity, "title": "Airport " + identity, "summary": "Frozen notice.",
            "status": status, "expected": dict(keep=keep, **expected)}


class EvaluationTests(unittest.TestCase):
    def test_confusion_matrix_and_undefined_rates_are_counted_honestly(self):
        cases = [case("a", True), case("b", False), case("c", True), case("d", False)]
        predictions = {identity: {"keep": keep} for identity, keep in zip("abcd", [True, True, False, False])}
        score = evaluation.score(cases, predictions)
        self.assertEqual([score[k] for k in ("tp", "fp", "fn", "tn")], [1, 1, 1, 1])
        self.assertEqual([score[k] for k in ("precision", "recall", "f1")], [0.5, 0.5, 0.5])
        no_positive = evaluation.score([case("a", False)], {"a": {"keep": False}})
        self.assertIsNone(no_positive["precision"])
        self.assertIsNone(no_positive["recall"])
        with self.assertRaises(ValueError):
            evaluation.score(cases, {"a": {"keep": "false"}})

    def test_changes_show_tradeoffs_and_do_not_hide_optional_flag_regressions(self):
        cases = [case("a", True, focus=True), case("b", False)]
        before = evaluation.score(cases, {"a": {"keep": True, "focus": True}, "b": {"keep": True}})
        after = evaluation.score(cases, {"a": {"keep": True, "focus": False}, "b": {"keep": False}})
        compared = evaluation.compare(before, after)
        self.assertEqual(compared["status"], "tradeoff")
        self.assertEqual(compared["fixed_cases"], ["b"])
        changed_labels = evaluation.score([case("a", False), case("b", False)],
                                          {"a": {"keep": False}, "b": {"keep": False}})
        with self.assertRaises(ValueError):
            evaluation.compare(before, changed_labels)

    def test_pending_labels_are_excluded_and_invalid_fixtures_are_rejected(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "cases.json"
            rows = [case("a", True), dict(case("b", False, "pending"), expected=None)]
            path.write_text(json.dumps({"version": 1, "cases": rows}))
            data, active, context = evaluation.load_dataset(path)
            self.assertEqual([c["id"] for c in active], ["a"])
            for invalid in ([case("a", True)] * 2, [case("a", "false")],
                            [case(str(i), True) for i in range(16)], [case("a", True, "unknown")]):
                path.write_text(json.dumps({"version": 1, "cases": invalid}))
                with self.assertRaises(ValueError):
                    evaluation.load_dataset(path)

    def test_production_duplicate_and_focus_only_decisions_are_measured(self):
        cases = [case("a", True), case("b", False), dict(case("c", False), focus_only=True)]
        verdicts = [{"i": n, "relevant": True, "focus": False, "urgent": False, "already_sent": False,
                     "dup_of": 0 if n == 1 else None} for n in range(3)]
        with mock.patch.object(secnews, "gemini_json", return_value=verdicts) as request:
            request.last_model = "unit-version"
            predictions, version = evaluation.predict({}, cases, ["Earlier airport notice"], "unit-key", "unit-lite")
        self.assertEqual([predictions[c]["keep"] for c in "abc"], [True, False, False])
        self.assertEqual(version, "unit-version")
        prompt = request.call_args.args[0]
        self.assertIn("Earlier airport notice", prompt)
        self.assertNotIn('"expected"', prompt)
        self.assertNotIn('"status"', prompt)

    def fixture(self, root):
        (root / "evaluation").mkdir()
        (root / "evaluation/cases.json").write_text(json.dumps({"version": 1, "cases": [case("a", True)]}))
        (root / "evaluation/baseline.json").write_text(json.dumps({"lite_thinking": "high"}))
        (root / "feeds.json").write_text(json.dumps({"lite_thinking": "high"}))
        state = root / "disposable"
        state.mkdir()
        day = secnews.GeminiBudget(state / "gemini_usage.json", []).day
        (state / "gemini_usage.json").write_text(json.dumps({"v": 2, "day": day, "used": {}}))
        return state

    def test_failed_classification_and_changed_models_never_claim_improvement(self):
        with tempfile.TemporaryDirectory() as folder, mock.patch.dict(os.environ, {"GEMINI_API_KEY": "unit-key"}):
            root = Path(folder)
            state = self.fixture(root)
            previous = secnews.GEMINI_BUDGET, secnews.LITE_THINKING
            with mock.patch.object(evaluation, "predict", side_effect=TimeoutError("unit failure")):
                result = evaluation.evaluate(root, state, live=True)
            self.assertEqual(result["status"], "incomplete")
            self.assertNotIn("comparison", result)
            self.assertEqual((secnews.GEMINI_BUDGET, secnews.LITE_THINKING), previous)
            with mock.patch.object(evaluation, "predict", side_effect=[({"a": {"keep": True}}, "one"),
                                                                       ({"a": {"keep": True}}, "two")]):
                result = evaluation.evaluate(root, state, live=True)
            self.assertEqual(result["status"], "incomparable")
            self.assertNotIn("comparison", result)
            with mock.patch.object(secnews, "gemini_classify", side_effect=TimeoutError("unit failure")):
                with self.assertRaisesRegex(RuntimeError, "incomplete"):
                    evaluation.predict({}, [case("a", True)], [], "unit-key", "unit-lite")

    def test_attempt_limit_is_recorded_and_merges_once_without_writing_production(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            event = root / "usage/day/evaluation.json"
            budget = evaluation.EvaluationBudget(root / "copy.json", [("unit-lite", 20)], test_usage_event=event)
            for _ in range(4):
                self.assertEqual(budget.take(), "unit-lite")
            with self.assertRaisesRegex(RuntimeError, "attempt limit"):
                budget.take()
            self.assertEqual(json.loads(event.read_text())["requests"], {"unit-lite": 4})
            merged = secnews.GeminiBudget(root / "other.json", [("unit-lite", 20)], test_usage_dir=root / "usage")
            self.assertEqual(merged.used["unit-lite"], 4)
            merged = secnews.GeminiBudget(root / "other.json", [("unit-lite", 20)], test_usage_dir=root / "usage")
            self.assertEqual(merged.used["unit-lite"], 4)

    def test_no_budget_or_exhaustion_skips_before_prediction_and_has_no_score(self):
        with tempfile.TemporaryDirectory() as folder, mock.patch.dict(os.environ, {"GEMINI_API_KEY": "unit-key"}), \
             mock.patch.object(evaluation, "predict") as predict:
            root = Path(folder)
            state = self.fixture(root)
            result = evaluation.evaluate(root, root / "absent", live=True)
            self.assertEqual(result["status"], "skipped_state")
            data = json.loads((state / "gemini_usage.json").read_text())
            data["used"] = {"gemini-flash-lite-latest": 450}
            (state / "gemini_usage.json").write_text(json.dumps(data))
            result = evaluation.evaluate(root, state, live=True)
            self.assertEqual(result["status"], "skipped_budget")
            predict.assert_not_called()
            self.assertEqual(result["api_attempts"], 0)

    def test_validation_is_offline_and_report_contains_no_invented_quality_score(self):
        with tempfile.TemporaryDirectory() as folder, mock.patch.dict(os.environ, {"GITHUB_RUN_ID": "123", "GITHUB_RUN_ATTEMPT": "1"}), \
             mock.patch.object(secnews, "gemini_json") as ai, mock.patch.object(secnews, "telegram_send") as send:
            root = Path(folder)
            self.fixture(root)
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(evaluation.main([str(root)]), 0)
            report = json.loads((root / "reports/selection-evaluation/123-1.json").read_text())
            self.assertEqual(report["status"], "validated")
            self.assertNotIn("comparison", report)
            self.assertEqual(report["api_attempts"], 0)
            ai.assert_not_called()
            send.assert_not_called()

    def test_live_path_uses_one_route_records_both_calls_and_preserves_input_state(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            state = self.fixture(root)
            original = (state / "gemini_usage.json").read_bytes()
            event = root / "increments.json"
            verdict = [{"i": 0, "relevant": True, "focus": False, "urgent": False,
                        "already_sent": False, "dup_of": None}]
            payload = json.dumps({"modelVersion": "unit-lite-version", "candidates": [
                {"content": {"parts": [{"text": json.dumps(verdict)}]}}]}).encode()
            with mock.patch.dict(os.environ, {"GEMINI_API_KEY": "unit-key", "SECNEWS_TEST_USAGE_EVENT": str(event)}), \
                 mock.patch.object(secnews, "NO_THINKING", set()), \
                 mock.patch.object(secnews.urllib.request, "urlopen", side_effect=lambda *a, **kw: io.BytesIO(payload)) as http, \
                 mock.patch.object(secnews, "telegram_send") as send:
                result = evaluation.evaluate(root, state, live=True)
            self.assertEqual(result["status"], "complete")
            self.assertEqual(result["comparison"]["status"], "unchanged")
            self.assertEqual(result["api_attempts"], 2)
            self.assertEqual(http.call_count, 2)
            self.assertTrue(all("gemini-flash-lite-latest:generateContent" in call.args[0].full_url
                                for call in http.call_args_list))
            self.assertEqual(json.loads(event.read_text())["requests"], {"gemini-flash-lite-latest": 2})
            self.assertEqual((state / "gemini_usage.json").read_bytes(), original)
            send.assert_not_called()

    def test_regression_or_tradeoff_flags_the_workflow_after_preserving_the_report(self):
        with tempfile.TemporaryDirectory() as folder, mock.patch.dict(os.environ, {"GITHUB_RUN_ID": "123", "GITHUB_RUN_ATTEMPT": "1"}):
            root = Path(folder)
            for status, exit_code in (("regressed", 1), ("tradeoff", 1), ("unchanged", 0), ("improved", 0)):
                report = {"status": "complete", "comparison": {"status": status},
                          "labelled": 1, "pending": 0, "api_attempts": 2}
                with self.subTest(status=status), mock.patch.object(evaluation, "evaluate", return_value=report), \
                     contextlib.redirect_stdout(io.StringIO()):
                    self.assertEqual(evaluation.main([str(root)]), exit_code)
                saved = json.loads((root / "reports/selection-evaluation/123-1.json").read_text())
                self.assertEqual(saved["comparison"]["status"], status)


if __name__ == "__main__":
    unittest.main()

"""Compare fixed, privately labelled examples without collecting or sending news."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import sys
import tempfile
import time

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import secnews
from tools.private_logs import error_kind


def fingerprint(value):
    return hashlib.sha256(json.dumps(value, ensure_ascii=False, sort_keys=True).encode()).hexdigest()


def load_dataset(path):
    if path.stat().st_size > 1024 * 1024:
        raise ValueError("evaluation dataset exceeds the size limit")
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict) or data.get("version") != 1 or not isinstance(data.get("cases"), list):
        raise ValueError("invalid evaluation dataset")
    active, identifiers = [], set()
    for row in data["cases"]:
        if (not isinstance(row, dict) or not isinstance(row.get("id"), str)
                or not re.fullmatch(r"[A-Za-z0-9_-]{1,80}", row["id"]) or row["id"] in identifiers):
            raise ValueError("invalid or duplicate evaluation identifier")
        identifiers.add(row["id"])
        if row.get("status") not in ("policy", "reviewed", "pending"):
            raise ValueError("evaluation labels need an explicit review status")
        if any(not isinstance(row.get(k), str) or len(row[k]) > 4000 for k in ("title", "summary")):
            raise ValueError("invalid frozen evaluation text")
        if "focus_only" in row and type(row["focus_only"]) is not bool:
            raise ValueError("invalid evaluation admission constraint")
        if row["status"] == "pending":
            continue  # Unknown ground truth is never a model error or a correct answer.
        expected = row.get("expected")
        if (not isinstance(expected, dict) or type(expected.get("keep")) is not bool
                or any(k not in ("keep", "focus", "urgent") or type(v) is not bool
                       for k, v in expected.items())):
            raise ValueError("invalid evaluation labels")
        active.append(row)
    context = data.get("already_sent", [])
    if (not isinstance(context, list) or len(context) > 150
            or any(not isinstance(text, str) or len(text) > 2000 for text in context)):
        raise ValueError("invalid frozen evaluation context")
    if not 1 <= len(active) <= 15:
        raise ValueError("evaluation requires one batch of 1 to 15 labelled examples")
    return data, active, context


def score(cases, predictions):
    if set(predictions) != {row["id"] for row in cases}:
        raise ValueError("missing or extra evaluation predictions")
    counts = dict(tp=0, fp=0, fn=0, tn=0)
    details, fields = [], {}
    for row in cases:
        actual, expected = predictions[row["id"]], row["expected"]
        if not isinstance(actual, dict) or any(type(actual.get(k)) is not bool for k in expected):
            raise ValueError("evaluation predictions must be actual booleans")
        correct = actual["keep"] == expected["keep"]
        kind = ("tp" if actual["keep"] else "fn") if expected["keep"] else ("fp" if actual["keep"] else "tn")
        counts[kind] += 1
        for field, value in expected.items():
            record = fields.setdefault(field, {"labelled": 0, "errors": 0})
            record["labelled"] += 1
            record["errors"] += actual[field] != value
        details.append({"id": row["id"], "label_status": row["status"], "expected": expected,
                        "actual": actual, "outcome": kind, "correct": correct})
    tp, fp, fn = counts["tp"], counts["fp"], counts["fn"]
    ratio = lambda n, d: round(n / d, 4) if d else None
    return dict(counts, total=len(cases), precision=ratio(tp, tp + fp), recall=ratio(tp, tp + fn),
                f1=ratio(2 * tp, 2 * tp + fp + fn), fields=fields, cases=details)


def compare(before, after):
    old, new = {c["id"]: c for c in before["cases"]}, {c["id"]: c for c in after["cases"]}
    if set(old) != set(new) or any(old[k]["expected"] != new[k]["expected"] for k in old):
        raise ValueError("only identical labelled examples can be compared")
    changes = {kind: before[kind] - after[kind] for kind in ("fp", "fn")}
    field_changes = {field: before["fields"][field]["errors"] - after["fields"][field]["errors"]
                     for field in before["fields"]}
    deltas = list(changes.values()) + list(field_changes.values())
    status = ("tradeoff" if min(deltas) < 0 < max(deltas) else "regressed" if min(deltas) < 0
              else "improved" if max(deltas) > 0 else "unchanged")
    return {"status": status, "error_reduction": changes, "field_error_reduction": field_changes,
            "fixed_cases": [k for k in old if not old[k]["correct"] and new[k]["correct"]],
            "regressed_cases": [k for k in old if old[k]["correct"] and not new[k]["correct"]]}


def classifier_config(config):
    return {k: config.get(k, default) for k, default in (
        ("classify_prompt", secnews.CLASSIFY_PROMPT), ("sectors", {}), ("fallback_sectors", {}),
        ("focus_sectors", {}), ("lite_thinking", "medium"))}


class EvaluationBudget(secnews.GeminiBudget):
    """Use a disposable state copy; export increments through the existing test-usage ledger."""
    def __init__(self, *args, **kwargs):
        self.attempts = 0
        super().__init__(*args, **kwargs)

    def take(self, *args, **kwargs):
        if self.attempts >= 4:
            raise RuntimeError("evaluation API attempt limit reached")
        chosen = super().take(*args, **kwargs)
        self.attempts += 1
        return chosen


def predict(config, cases, context, key, model):
    # Match the production classification input and final keep/duplicate/focus-only logic.
    # This benchmark starts after keyword admission; it does not measure RSS or keyword recall.
    items = [{"id": c["id"], "title": c["title"], "summary": c["summary"], "score": 1,
              "source": "Evaluation", "link": "https://example.com/evaluation/" + c["id"],
              "date": None, "focus_only": bool(c.get("focus_only", False))} for c in cases]
    classifier = secnews.GeminiClassifier(key, config, model=model, chunk=15, limit=15)
    classifier.deadline = 180
    kept = {id(it) for it in classifier(items, told=context)}
    if classifier.failed or len(classifier.results) != len(items):
        raise RuntimeError("evaluation classification incomplete; keyword fallback is not an answer")
    predictions, versions = {}, set()
    for row, item in zip(cases, items):
        verdict, version = classifier.results[secnews.cache_key(item)]
        predictions[row["id"]] = {"keep": id(item) in kept, "focus": verdict["focus"],
                                    "urgent": verdict["urgent"],
                                    "decision_reason": item.get("drop_reason", "kept"),
                                    "model_relevant": verdict["relevant"],
                                    "already_sent": verdict["already_sent"],
                                    "dup_of": verdict.get("dup_of")}
        versions.add(version)
    if len(versions) != 1:
        raise RuntimeError("mixed model versions are not comparable")
    return predictions, versions.pop()


def evaluate(private, state, live=False):
    data, cases, context = load_dataset(private / "evaluation/cases.json")
    configs = {"baseline": json.loads((private / "evaluation/baseline.json").read_text()),
               "candidate": json.loads((private / "feeds.json").read_text())}
    configs = {k: classifier_config(v) for k, v in configs.items()}
    report = {"version": 1, "at": datetime.now(timezone.utc).isoformat(), "status": "validated",
              "code_revision": os.environ.get("GITHUB_SHA", "local"),
              "code_hash": hashlib.sha256(Path(secnews.__file__).read_bytes() + Path(__file__).read_bytes()).hexdigest(),
              "dataset_hash": fingerprint(data), "dataset_revision": data.get("revision"),
              "labelled": len(cases), "pending": len(data["cases"]) - len(cases),
              "label_counts": {kind: sum(c["status"] == kind for c in cases) for kind in ("policy", "reviewed")},
              "sample_kinds": {kind: sum(c.get("sample_kind") == kind for c in cases)
                               for kind in ("historical_excerpt", "synthetic")},
              "config_hashes": {k: fingerprint(v) for k, v in configs.items()}, "results": {},
              "telegram_sends": 0, "production_state_written": False,
              "scope": "Fixed post-keyword classifier examples; small policy fixtures are not production accuracy."}
    if not live:
        report["api_attempts"] = 0
        return report
    key = os.environ.get("GEMINI_API_KEY", "")
    if not key:
        raise ValueError("evaluation API key is missing")
    if not (state / "gemini_usage.json").is_file():
        report.update(status="skipped_state", api_attempts=0)
        return report
    # One fixed Lite route for both sides: never spend scarce Flash requests or change models.
    model = "gemini-flash-lite-latest"
    settings = json.loads((private / "feeds.json").read_text())
    configured_models = settings.get("gemini_models", secnews.DEFAULT_GEMINI_MODELS)
    cap = next((m["daily"] for m in configured_models if m["model"] == model), 0)
    with tempfile.TemporaryDirectory(prefix="selection-evaluation-") as working:
        snapshot = Path(working) / "gemini_usage.json"
        snapshot.write_bytes((state / "gemini_usage.json").read_bytes())
        budget = EvaluationBudget(snapshot, [(model, cap)],
                                  test_usage_dir=private / "api-usage",
                                  test_usage_event=os.environ.get("SECNEWS_TEST_USAGE_EVENT"))
        previous = secnews.GEMINI_BUDGET, secnews.LITE_THINKING
        secnews.GEMINI_BUDGET = budget
        report.update(status="incomplete", requested_model=model, thinking={k: v["lite_thinking"] for k, v in configs.items()})
        started = time.monotonic()
        try:
            if budget.used.get(model, 0) + 4 > cap or budget.resting.get(model, 0) > time.time():
                report["status"] = "skipped_budget"
                return report
            for label, config in configs.items():
                secnews.LITE_THINKING = config["lite_thinking"]
                predictions, version = predict(config, cases, context, key, model)
                report["results"][label] = dict(score(cases, predictions), model=version,
                                                 thinking_applied=config["lite_thinking"] != "off" and model not in secnews.NO_THINKING)
            before, after = (report["results"][k] for k in ("baseline", "candidate"))
            if (before["model"] != after["model"] or configs["baseline"]["lite_thinking"] != configs["candidate"]["lite_thinking"]
                    or before["thinking_applied"] != after["thinking_applied"]):
                report["status"] = "incomparable"
            else:
                report.update(status="complete", comparison=compare(before, after))
        except Exception as error:
            # Provider errors must never masquerade as a correct rejection or a precision gain.
            report["error"] = error_kind(f"{type(error).__name__}: {error}")
        finally:
            report["api_attempts"] = budget.attempts
            report["elapsed_seconds"] = round(time.monotonic() - started, 1)
            secnews.GEMINI_BUDGET, secnews.LITE_THINKING = previous
        return report


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("private", type=Path)
    parser.add_argument("--state", type=Path, default=Path(".evaluation-state"))
    parser.add_argument("--live", action="store_true", help="Use at most four recorded Lite attempts; never send news")
    args = parser.parse_args(argv)
    report = evaluate(args.private, args.state, live=args.live)
    identity = "-".join(os.environ.get(k, "local") for k in ("GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT"))
    if not re.fullmatch(r"[0-9]+-[0-9]+|local-local", identity):
        raise ValueError("invalid evaluation run identity")
    folder = args.private / "reports/selection-evaluation"
    folder.mkdir(parents=True, exist_ok=True)
    (folder / f"{identity}.json").write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"selection evaluation: {report['labelled']} labelled, {report['pending']} pending, {report['api_attempts']} attempts")
    if report.get("comparison", {}).get("status") in ("regressed", "tradeoff"):
        print("selection evaluation: quality regression detected; inspect the private report")
        return 1
    return 0 if report["status"] in ("validated", "complete", "skipped_budget", "skipped_state") else 1


if __name__ == "__main__":
    from tools.private_logs import execute
    sys.exit(execute(main, label="evaluation"))

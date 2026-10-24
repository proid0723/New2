"""Read-only collection compatibility check; no AI, subscribers, or news-state writes."""
from datetime import datetime, timezone
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import secnews


def main():
    private = Path(sys.argv[1])
    config = json.loads((private / "feeds.json").read_text(encoding="utf-8"))
    # Inspect all feed transports without spending more requests on article dates.
    errors = {}
    config = dict(config, article_date_budget_seconds=0, _collection_errors=errors)
    counts, failed = {}, []
    items = secnews.collect(config, failed=failed, counts=counts)
    total = len(config["feeds"])
    report = {"mode": "read_only_collection", "checked_at": datetime.now(timezone.utc).isoformat(),
              "feeds": total, "successful_feeds": len(counts), "items": len(items),
              "items_per_feed": counts, "failed_feed_count": len(failed),
              "failed_feed_numbers": [i + 1 for i in range(total) if str(i) not in counts],
              "errors_by_feed": errors,
              "ai_requests": 0, "telegram_sends": 0, "production_state_written": False}
    (private / "reports").mkdir(parents=True, exist_ok=True)
    (private / "reports/summary-diagnostic-result.json").write_text(
        json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"collection check: {len(counts)} of {total} feeds")
    return 0 if total and len(counts) >= total * 0.75 else 1


if __name__ == "__main__":
    from private_logs import execute
    sys.exit(execute(main, label="collection"))

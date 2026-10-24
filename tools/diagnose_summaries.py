"""Inspect configured article summaries; write details only to a private report."""
import io
import json
from pathlib import Path
import re
import sys
from datetime import datetime, timezone

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import secnews


def main():
    private = Path(sys.argv[1])
    config = json.loads((private / "feeds.json").read_text())
    request = json.loads((private / "reports/summary-diagnostic-request.json").read_text())
    feed = request.get("feed") or config["feeds"][int(request["feed_number"]) - 1]
    raw = secnews.fetch(feed["url"])
    parser = secnews.PARSERS.get(feed.get("type"), secnews.parse_feed)
    items = parser(raw, feed["name"])
    sent_links = {}
    for snapshot in sorted((private / "reports").glob("snapshot-*.json")):
        sent_links.update(json.loads(snapshot.read_text()).get("sent_links", {}))
    output = {"checked_at": datetime.now(timezone.utc).isoformat(), "feed_items": len(items),
              "feed_sample": [{"title": it["title"], "link": it["link"], "source": it["source"],
                               "date": it["date"].isoformat() if it["date"] else None} for it in items[:10]],
              "articles": []}
    original = secnews.urlopen_public

    for title in request["titles"]:
        item = next((i for i in items if i["title"] == title), None)
        row = {"title": title, "found_in_feed": item is not None, "requests": []}
        output["articles"].append(row)
        if not item and title in sent_links:
            item = {"title": title, "link": sent_links[title]}
            row["from_sent_snapshot"] = True
        if not item:
            continue
        row["link"] = item["link"]

        def traced(req, timeout=20, **kwargs):
            url = req if isinstance(req, str) else req.full_url
            with original(req, timeout=timeout, **kwargs) as response:
                data = response.read(1_000_000)
                headers = response.headers
                final = response.geturl()
            text = data.decode(headers.get_content_charset() or "utf-8", "replace")
            entry = {"url": url, "final_url": final, "bytes": len(data)}
            if "news.google.com" in url:
                entry["signature_present"] = 'data-n-a-sg="' in text
                entry["timestamp_present"] = 'data-n-a-ts="' in text
                if "batchexecute" in url:
                    entry["rpc_response"] = text[:5000]
            else:
                entry["description_tags"] = [tag for tag in secnews.META_DESC.findall(text)
                                              if "description" in tag.lower()][:10]
            row["requests"].append(entry)
            result = io.BytesIO(data)
            result.headers = headers
            return result

        secnews.urlopen_public = traced
        try:
            row["summary"] = secnews.page_summary(item, timeout=15)
            row["title_match_words"] = [w for w in re.findall(r"\w+", title) if len(w) >= 3]
        except Exception as error:
            row["error"] = f"{type(error).__name__}: {error}"
        finally:
            secnews.urlopen_public = original
    destination = private / "reports/summary-diagnostic-result.json"
    destination.write_text(json.dumps(output, ensure_ascii=False, indent=2) + "\n")
    print("Private summary diagnostic saved; no AI or Telegram calls were made.")


if __name__ == "__main__":
    from private_logs import execute
    sys.exit(execute(main, label="summary"))

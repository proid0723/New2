"""Send a one-off URL-button preview only to configured administrator chats."""
import html
import json
import os
from pathlib import Path
import re
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import secnews


def main():
    token = os.environ.get("TELEGRAM_BOT_TOKEN", "").strip()
    chats = re.split(r"[,\s]+", os.environ.get("TEST_CHAT", "").strip())
    if not token or not chats[0]:
        raise SystemExit("Administrator credentials are required; no fallback recipients.")
    config = json.loads(Path(os.environ["SECNEWS_CONFIG"]).read_text())
    items = []
    for feed in config["feeds"]:
        if feed.get("type", "rss") != "rss":
            continue
        try:
            parsed = secnews.parse_feed(secnews.fetch(feed["url"]), feed["name"])
        except Exception:
            continue
        for item in parsed:
            if not item["link"].startswith(("https://", "http://")):
                continue
            if item["link"] not in {it["link"] for it in items}:
                items.append(item)
            if len(items) == 3:
                break
        if len(items) == 3:
            break
    if not items:
        raise SystemExit("No articles available for the preview.")
    text = "<b>🧪 기사 제목 버튼 테스트</b>\n\n"
    text += "\n\n".join(f"{i}. {html.escape(it['title'][:250])}" for i, it in enumerate(items, 1))
    text += "\n\n아래 버튼은 한 줄에 하나씩입니다. 버튼 안 어디를 눌러도 해당 원문이 열립니다. 긴 제목이 잘리는지도 확인해 주세요."
    markup = {"inline_keyboard": [[{"text": it["title"], "url": it["link"]}] for it in items]}
    for chat in dict.fromkeys(chats):
        if chat:
            result = secnews.telegram_send(token, chat, text, markup=markup)
            if not result.get("ok"):
                raise SystemExit("Telegram did not accept the preview.")
    print("Administrator button preview sent; no subscriber or news state was accessed.")


if __name__ == "__main__":
    main()

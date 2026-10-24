"""Send a one-off message layout preview only to configured administrator chats."""
import html
import json
import os
from pathlib import Path
import re
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import secnews


def linked_article(item, outside_title=False, link_summary=True, title_spaces=0):
    title = html.escape(item["title"]) + secnews.TITLE_LINK_SPACES
    summary = secnews.short_summary(item)
    # One link includes the title, separating whitespace and italic summary.
    content = f"<b>{title}</b>"
    if summary:
        content += f"\n\n<i>{html.escape(summary)}</i>"
    url = html.escape(item["link"], quote=True)
    date = item.get("date")
    when = " · " + date.astimezone(secnews.KST).strftime("%m-%d %H:%M") if date else ""
    if outside_title:
        outside_text = html.escape(item["title"]) + " " * title_spaces
        heading = f'<b><a href="{url}">{outside_text}</a></b>'
        linked_summary = f'<a href="{url}"><i>{html.escape(summary)}</i></a>' if summary else ""
        if summary and not link_summary:
            linked_summary = f'<i>{html.escape(summary)}</i>'
        details = f'📰 {html.escape(item["source"])}{when}'
        body = linked_summary + "\n\n" + details if linked_summary else details
        return f'{heading}\n<blockquote>{body}</blockquote>'
    return (f'<blockquote><a href="{url}">{content}</a>\n\n'
            f'📰 {html.escape(item["source"])}{when}</blockquote>')


def main():
    token = os.environ.get("TELEGRAM_BOT_TOKEN", "").strip()
    chats = re.split(r"[,\s]+", os.environ.get("TEST_CHAT", "").strip())
    if not token or not chats[0]:
        raise SystemExit("Administrator credentials are required; no fallback recipients.")
    config = json.loads(Path(os.environ["SECNEWS_CONFIG"]).read_text())
    style = os.environ.get("PREVIEW_STYLE", "buttons")
    korean = style in ("all_links_ko", "outside_title_ko", "outside_plain_summary_ko", "outside_padded_title_ko")
    items = []
    feeds = config["feeds"]
    if korean:
        feeds = sorted(feeds, key=lambda f: not bool(re.search(r"[가-힣]", f["name"])))
    for feed in feeds:
        if feed.get("type", "rss") != "rss":
            continue
        try:
            parsed = secnews.parse_feed(secnews.fetch(feed["url"]), feed["name"])
        except Exception:
            continue
        for item in parsed:
            if korean and (not re.search(r"[가-힣]", item["title"])
                           or not re.search(r"[가-힣]", secnews.short_summary(item))):
                continue
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
    if style == "outside_padded_title_ko":
        text = "<b>🧪 박스 밖 제목에 공백 90개를 넣은 시안</b>\n\n"
        text += "\n\n".join(linked_article(it, outside_title=True, link_summary=False, title_spaces=90) for it in items)
        text += "\n\n제목 링크 안에 일반 스페이스 90개를 추가했습니다. 요약과 출처는 링크 없는 글자입니다. 공백의 표시와 클릭 범위는 앱에 따라 다를 수 있습니다. 운영 화면은 아직 변경하지 않았습니다."
        markup = None
    elif style == "outside_plain_summary_ko":
        text = "<b>🧪 요약 링크를 뺀 시안</b>\n\n"
        text += "\n\n".join(linked_article(it, outside_title=True, link_summary=False) for it in items)
        text += "\n\n제목만 원문 링크입니다. 박스 안 요약과 출처는 일반 글자입니다. RSS 요약으로 만든 시안이며 운영 화면은 아직 변경하지 않았습니다."
        markup = None
    elif style == "outside_title_ko":
        text = "<b>🧪 제목을 박스 밖으로 뺀 시안</b>\n\n"
        text += "\n\n".join(linked_article(it, outside_title=True) for it in items)
        text += "\n\n제목은 박스 밖, 요약은 박스 안에 두었습니다. 제목과 요약 모두 같은 원문 링크입니다. RSS 요약을 사용한 시안이며 운영 화면은 아직 변경하지 않았습니다."
        markup = None
    elif style in ("all_links", "all_links_ko"):
        text = "<b>🧪 제목·요약 링크 시안</b>\n\n"
        text += "\n\n".join(linked_article(it) for it in items)
        text += "\n\n제목과 요약 모두 원문 링크입니다. 출처는 일반 글자입니다. RSS 요약으로 만든 화면 시안이며 정기 발송에는 적용하지 않았습니다."
        markup = None
    elif style == "buttons":
        text = "<b>🧪 기사 제목 버튼 테스트</b>\n\n"
        text += "\n\n".join(f"{i}. {html.escape(it['title'][:250])}" for i, it in enumerate(items, 1))
        text += "\n\n아래 버튼은 한 줄에 하나씩입니다. 버튼 안 어디를 눌러도 해당 원문이 열립니다. 긴 제목이 잘리는지도 확인해 주세요."
        markup = {"inline_keyboard": [[{"text": it["title"], "url": it["link"]}] for it in items]}
    else:
        raise SystemExit("Unknown preview style.")
    for chat in dict.fromkeys(chats):
        if chat:
            result = secnews.telegram_send(token, chat, text, markup=markup)
            if not result.get("ok"):
                raise SystemExit("Telegram did not accept the preview.")
    print("Administrator layout preview sent; no subscriber or news state was accessed.")


if __name__ == "__main__":
    from private_logs import execute
    sys.exit(execute(main, label="preview"))

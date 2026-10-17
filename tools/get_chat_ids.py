#!/usr/bin/env python3
"""List everyone who messaged the bot recently (Telegram keeps about 24 hours of updates).

Have each recipient open the bot and press /start (or add the bot to a group
and send any message there), then run:
  TELEGRAM_BOT_TOKEN=123:abc python3 tools/get_chat_ids.py
Chats already in feeds.json "chat_ids", TELEGRAM_CHAT_IDS or ~/.config/secnews/env are marked.
"""
import json
import os
import re
import sys
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path

KST = timezone(timedelta(hours=9))
# Actions logs of a public repository are public: show only the first letter of names.
MASK = bool(os.environ.get("GITHUB_ACTIONS"))


def mask(text):
    return (text[:1] + "*" * min(len(text) - 1, 3)) if MASK and text else text


def registered_ids():
    ids = set(re.split(r"[\s,;]+", os.environ.get("TELEGRAM_CHAT_IDS", "")))
    # The encrypted subscriber list kept next to the sent-item state.
    try:
        sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
        import secnews
        state = Path(os.environ.get("SECNEWS_STATE") or secnews.DEFAULT_STATE)
        subs = secnews.load_subscribers(state.with_name("subscribers.json"),
                                        secnews.subscriber_key(os.environ.get("TELEGRAM_BOT_TOKEN", "")))
        ids |= set(subs["ids"])
    except Exception:
        pass
    try:
        ids |= {str(c) for c in json.loads((Path(__file__).resolve().parent.parent / "feeds.json")
                                         .read_text(encoding="utf-8")).get("chat_ids", [])}
    except (OSError, ValueError):
        pass
    env = Path.home() / ".config" / "secnews" / "env"
    try:
        for line in env.read_text(encoding="utf-8").splitlines():
            key, _, value = line.removeprefix("export ").partition("=")
            if key.strip() == "TELEGRAM_CHAT_IDS":
                ids |= set(re.split(r"[\s,;]+", value.strip().strip("'\"")))
    except OSError:
        pass
    return {i for i in ids if i}


def main():
    token = os.environ.get("TELEGRAM_BOT_TOKEN")
    if not token:
        sys.exit("set TELEGRAM_BOT_TOKEN first")
    with urllib.request.urlopen(f"https://api.telegram.org/bot{token}/getUpdates", timeout=20) as resp:
        data = json.loads(resp.read())
    if not data.get("ok"):
        sys.exit(f"telegram error: {data}")

    chats = {}
    for upd in data["result"]:
        msg = upd.get("message") or upd.get("channel_post") or upd.get("my_chat_member") or {}
        chat = msg.get("chat")
        if not chat:
            continue
        name = mask(chat.get("title") or " ".join(filter(None, [chat.get("first_name"), chat.get("last_name")])))
        when = datetime.fromtimestamp(msg.get("date", 0), KST).strftime("%m-%d %H:%M")
        text = (msg.get("text") or "")[:30]
        if MASK and not text.startswith("/"):
            text = "…"
        chats[chat["id"]] = (chat.get("type"), name, chat.get("username") or "", when, text)

    if not chats:
        # The 5-minute run takes updates off Telegram's queue once it has handled them.
        print("아직 처리되지 않은 메시지가 없습니다. /start 를 누른 사람은 5분마다 도는 실행에서 이미 구독됐습니다.")
        return
    registered = registered_ids()
    print(f"최근 봇에 메시지를 보낸 채팅 {len(chats)}개\n")
    for cid, (kind, name, user, when, text) in chats.items():
        mark = "✅ 등록됨" if str(cid) in registered else "➕ 미등록"
        handle = f" @{mask(user)}" if user else ""
        shown = (str(cid)[:2] + "***" + str(cid)[-2:]) if MASK else cid
        print(f"{mark}  {shown}  [{kind}] {name}{handle}  (마지막 메시지 {when} KST: {text!r})")
    new = [str(c) for c in chats if str(c) not in registered]
    if new:
        print("\n미등록 채팅은 다음 정기 실행(5분 안)에서 자동으로 구독됩니다.")


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""Tell the admin when the 5-minute runs have stopped coming.

Failed runs already report themselves; a run that never starts cannot. The external timer
(cron-job.org) starts the runs, so if it stops, or its GitHub token expires, everything goes
quiet. GitHub's own hourly schedule runs this check instead:
  GITHUB_TOKEN=... GITHUB_REPOSITORY=owner/repo TELEGRAM_BOT_TOKEN=... ADMIN_CHAT=... python3 tools/watchdog.py
"""
import json
import os
import sys
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone

KST = timezone(timedelta(hours=9))
STALE_MINUTES = 30


def minutes_since_last_run(runs, now):
    """Minutes since the newest run was created, or None when there is none."""
    times = [datetime.fromisoformat(r["created_at"].replace("Z", "+00:00")) for r in runs]
    return (now - max(times)).total_seconds() / 60 if times else None


def message(minutes):
    if minutes is None:
        return "⚠️ AI 보안 뉴스 비서: 5분 실행 기록을 찾을 수 없어요. cron-job.org 작업을 확인해 주세요."
    return (f"⚠️ AI 보안 뉴스 비서가 {minutes:.0f}분째 실행되지 않았어요.\n"
            "cron-job.org 작업이 꺼졌거나 그 GitHub 토큰이 만료됐을 수 있어요.")


def main():
    repo = os.environ["GITHUB_REPOSITORY"]
    url = (f"https://api.github.com/repos/{repo}/actions/workflows/secnews.yml/runs"
           "?event=workflow_dispatch&per_page=5")
    req = urllib.request.Request(url, headers={"Authorization": f"Bearer {os.environ['GITHUB_TOKEN']}",
                                               "Accept": "application/vnd.github+json"})
    with urllib.request.urlopen(req, timeout=20) as resp:
        runs = json.loads(resp.read())["workflow_runs"]
    now = datetime.now(timezone.utc)
    minutes = minutes_since_last_run(runs, now)
    if minutes is not None and minutes < STALE_MINUTES:
        print(f"ok: last run {minutes:.0f} minutes ago")
        return 0
    print(f"stale: {message(minutes)}")
    token, chat = os.environ.get("TELEGRAM_BOT_TOKEN"), os.environ.get("ADMIN_CHAT", "").strip()
    if not (token and chat):
        return 1
    hour = now.astimezone(KST).hour
    body = urllib.parse.urlencode({"chat_id": chat, "text": message(minutes),
                                   "disable_notification": "true" if hour >= 22 or hour < 6 else "false"})
    urllib.request.urlopen(f"https://api.telegram.org/bot{token}/sendMessage", data=body.encode(), timeout=20)
    return 0


if __name__ == "__main__":
    sys.exit(main())

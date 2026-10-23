#!/usr/bin/env python3
"""Collect cybersecurity news from RSS/Atom feeds and the CISA KEV catalog,
score each item for urgency, and send new items to Telegram chats.

Standard library only, so it runs on a bare self-hosted runner with python3.

Environment:
  TELEGRAM_BOT_TOKEN   bot token from @BotFather
  TELEGRAM_CHAT_IDS    chat ids or @channel names, separated by commas, spaces or newlines
  SECNEWS_STATE        path of the sent-item state file
                       (default: ~/.local/state/secnews/seen.json)

Values missing from the environment are read from ~/.config/secnews/env
(KEY=VALUE lines), so the runner machine can hold them instead of GitHub secrets.
"""
import argparse
import base64
import concurrent.futures
import fcntl
import hashlib
import hmac
import html
import json
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from html.parser import HTMLParser
from datetime import datetime, timedelta, timezone
from email.utils import parsedate_to_datetime
from pathlib import Path

CONFIG_PATH = Path(__file__).with_name("feeds.json")
DEFAULT_STATE = Path.home() / ".local" / "state" / "secnews" / "seen.json"
ENV_FILE = Path.home() / ".config" / "secnews" / "env"
USER_AGENT = "Mozilla/5.0 (compatible; secnews-bot/1.0)"
KST = timezone(timedelta(hours=9))
# Keys stay in the state file this long. It must be longer than max_age_hours,
# otherwise an item could be pruned from the state and then sent again.
STATE_RETENTION = timedelta(days=14)
TELEGRAM_LIMIT = 4096
TRACKING_PARAMS = re.compile(r"^(utm_|fbclid$|gclid$|mc_)")


# Actions logs of a public repository are public. There a run prints only warnings, errors and a
# short summary; the full log is printed only when the run fails (or with SECNEWS_VERBOSE=1).
QUIET = bool(os.environ.get("GITHUB_ACTIONS")) and not os.environ.get("SECNEWS_VERBOSE")
SUMMARY = re.compile(r"^(warning|error|ai models:|pre-judged|summaries from|sent \d|subscribers:|instant alerts:|night notice|review snapshot|\d+ recipient)")
HELD = []


def log(msg):
    if QUIET and not SUMMARY.match(str(msg)):
        HELD.append(msg)
        return
    print(msg, file=sys.stderr, flush=True)


def show_held_log():
    print("--- full log ---", file=sys.stderr)
    for msg in HELD:
        print(msg, file=sys.stderr)
    HELD.clear()


# ---------------------------------------------------------------- fetching

def fetch(url, timeout=20):
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read()


# ----------------------------------------------------------------- parsing

def _local(tag):
    return tag.rsplit("}", 1)[-1].lower()


def _child(el, *names):
    for c in el:
        if _local(c.tag) in names:
            return c
    return None


def _text(el):
    if el is None:
        return ""
    return "".join(el.itertext()).strip()


def clean_text(s):
    s = html.unescape(re.sub(r"<[^>]+>", " ", s or ""))
    # Some feeds escape their HTML twice (&lt;img src=...&gt;): after unescaping, those are tags too.
    s = re.sub(r"<[^>]*>|<(?:img|center|a|p|br|div|span|figure)\b[^>]*$", " ", s, flags=re.I)
    return re.sub(r"\s+", " ", s).strip()


def parse_date(s):
    s = (s or "").strip()
    if not s:
        return None
    try:
        dt = parsedate_to_datetime(s)
    except (TypeError, ValueError):
        try:
            dt = datetime.fromisoformat(s.replace("Z", "+00:00"))
        except ValueError:
            return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def parse_xml(raw):
    """Parse feed bytes. expat cannot decode multi-byte charsets such as
    EUC-KR (used by some Korean feeds), so decode those in Python first."""
    head = raw[:200].decode("ascii", "ignore")
    if re.match(r"\s*<(!doctype html|html)", head, re.I):
        raise ValueError("got an HTML page instead of a feed; the feed URL has probably moved")
    m = re.search(r'encoding=["\']([\w.-]+)["\']', head)
    enc = (m.group(1) if m else "utf-8").lower()
    if enc.replace("-", "").replace("_", "") in ("utf8", "usascii", "ascii", "iso88591"):
        try:
            return ET.fromstring(raw)
        except ET.ParseError:
            text = raw.decode(enc if enc != "usascii" else "ascii", errors="replace")
    else:
        text = raw.decode(enc, errors="replace")
    text = re.sub(r"^\s*<\?xml[^>]*\?>", "", text, count=1)
    try:
        return ET.fromstring(text)
    except ET.ParseError:
        # Some news feeds slip a bare "&" or a control character into a headline; mend and retry.
        text = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f]", "", text)
        text = re.sub(r"&(?!(?:[a-zA-Z][a-zA-Z0-9]*|#[0-9]+|#x[0-9a-fA-F]+);)", "&amp;", text)
        return ET.fromstring(text)


def parse_feed(raw, source):
    """Return items from an RSS 2.0, RSS 1.0 (RDF) or Atom document."""
    root = parse_xml(raw)
    items = []
    for el in root.iter():
        kind = _local(el.tag)
        if kind not in ("item", "entry"):
            continue
        title = clean_text(_text(_child(el, "title")))
        link = ""
        link_el = None
        for c in el:
            if _local(c.tag) == "link" and c.get("rel", "alternate") == "alternate":
                link_el = c
                break
        if link_el is not None:
            link = (link_el.get("href") or _text(link_el)).strip()
        guid = _text(_child(el, "guid", "id"))
        if not link and guid.startswith("http"):
            link = guid
        date = parse_date(_text(_child(el, "pubdate", "published", "updated", "date")))
        summary = clean_text(_text(_child(el, "description", "summary", "content")))
        if not title and summary:  # social-media feeds have posts, not headlines
            title, summary = split_post(summary)
        if not title or not (link or guid):
            continue
        items.append({
            "source": source,
            "title": title,
            "link": link,
            "id": guid or link,
            "date": date,
            "summary": summary[:300],
        })
    return items


def parse_kev(raw, source):
    data = json.loads(raw)
    items = []
    for v in data.get("vulnerabilities", []):
        cve = v.get("cveID", "")
        if not cve:
            continue
        added = parse_date(v.get("dateAdded", "") + "T00:00:00+00:00") if v.get("dateAdded") else None
        title = f"[KEV] {cve} {v.get('vendorProject', '')} {v.get('product', '')} - {v.get('vulnerabilityName', '')}"
        ransomware = v.get("knownRansomwareCampaignUse", "").lower() == "known"
        items.append({
            "source": source,
            "title": re.sub(r"\s+", " ", title).strip() + (" (ransomware)" if ransomware else ""),
            "link": f"https://nvd.nist.gov/vuln/detail/{cve}",
            "id": f"kev:{cve}",
            "date": added,
            "summary": v.get("shortDescription", "")[:300],
            "base_score": 3,  # in the catalog means exploited in the wild
            "vendor": v.get("vendorProject", ""),
        })
    return items


SOCIAL_NOISE = [
    re.compile(r"(?:🔗\s*)?\bread(?: more)?\b\s*[:\-→➜]*\s*https?://\S+", re.I),
    re.compile(r"https?://\S+"),
    re.compile(r"(?<![\w&])#[^\W_][\w-]*"),  # hashtags, but not C# or &#
]


def split_post(text, limit=110):
    """Turn a social-media post into (headline, rest). Links and hashtags are dropped:
    the item already links to the post, and a row of tags says nothing."""
    for r in SOCIAL_NOISE:
        text = r.sub("", text)
    text = re.sub(r"[ \t]{2,}", " ", text).strip()
    text = re.sub(r"^[^\w\[(\"'@]+", "", text)  # channels often lead with 🚨/🔥 and the like
    first = re.split(r"(?<=[.!?。])\s|\n", text, maxsplit=1)[0].strip()
    if len(first) > limit:
        first = first[:limit].rsplit(" ", 1)[0] + "…"
    rest = text[len(first.rstrip("…")):].strip()
    return first, rest


class _TelegramPage(HTMLParser):
    """Collect posts from a public channel's web preview (https://t.me/s/<channel>)."""

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.posts, self._post, self._depth, self._in_text = [], None, 0, 0

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        cls = a.get("class") or ""
        if tag == "div" and "data-post" in a and "tgme_widget_message" in cls:
            self._post = {"id": a["data-post"], "text": [], "date": None}
            self.posts.append(self._post)
        elif self._post is not None:
            if tag == "div" and "tgme_widget_message_text" in cls and not self._in_text:
                self._in_text, self._depth = 1, 0
            elif self._in_text and tag == "div":
                self._depth += 1
            elif self._in_text and tag == "br":
                self._post["text"].append("\n")
            elif tag == "time" and a.get("datetime"):
                self._post["date"] = a["datetime"]

    def handle_endtag(self, tag):
        if self._in_text and tag == "div":
            if self._depth:
                self._depth -= 1
            else:
                self._in_text = 0

    def handle_data(self, data):
        if self._in_text and self._post is not None:
            self._post["text"].append(data)


def parse_telegram(raw, source):
    page = _TelegramPage()
    page.feed(raw.decode("utf-8", "replace"))
    items = []
    for post in page.posts:
        text = re.sub(r"[ \t]+", " ", "".join(post["text"])).strip()
        if len(text) < 20:
            continue
        title, rest = split_post(text)
        items.append({
            "source": source,
            "title": title,
            "link": f"https://t.me/{post['id']}",
            "id": f"tg:{post['id']}",
            "date": parse_date(post["date"]),
            "summary": re.sub(r"\s+", " ", rest)[:300],
        })
    return items


HANGUL = re.compile(r"[\uac00-\ud7a3]")


def parse_ransomware(raw, source, site="https://www.ransomware.live"):
    """Leak-site victim lists from ransomware.live or RansomLook. Field names differ between their
    endpoints, so accept both. The same victim from both sites gets the same id and is sent once."""
    data = json.loads(raw)
    if isinstance(data, dict):
        data = data.get("victims") or data.get("data") or data.get("posts") or []
    items = []
    for v in data:
        name = (v.get("victim") or v.get("post_title") or "").strip()
        group = (v.get("group") or v.get("group_name") or "").strip()
        if not name or not group:
            continue
        country = (v.get("country") or "").strip().upper()
        if not country and (HANGUL.search(name) or re.search(r"\.kr\b", name.lower())):
            country = "KR"  # RansomLook has no country field
        sector = (v.get("activity") or v.get("sector") or "").strip()
        if sector.lower() in ("not found", "unknown"):
            sector = ""
        date = parse_date(v.get("discovered") or v.get("attackdate") or v.get("published") or "")
        details = [f"랜섬웨어 조직 {group}이(가) 다크웹 유출 사이트에 공개 (조직 측 주장, 사실 미확인)"]
        if sector:
            details.append(f"업종: {sector}")
        if country:
            details.append(f"국가: {country}")
        items.append({
            "source": source,
            "title": f"{'🇰🇷 ' if country == 'KR' else ''}{name} — {group} 랜섬웨어 피해 공개",
            "link": f"{site}/group/{urllib.parse.quote(group.lower())}",
            "id": f"rw:{group.lower()}:{name.lower()}",
            "date": date,
            "summary": " · ".join(details),
            "ransomware": True,
            "country": country,
            "sector": sector,
            "no_translate": True,
        })
    return items


def parse_google_news(raw, source):
    """Google News search RSS: titles end in " - <outlet>", descriptions only repeat the link."""
    items = parse_feed(raw, source)
    for it in items:
        title, sep, outlet = it["title"].rpartition(" - ")
        if sep and title:
            it["title"], it["source"] = title, outlet
        it["summary"] = ""
    return items


PARSERS = {"telegram": parse_telegram, "ransomware": parse_ransomware, "google_news": parse_google_news,
           "ransomlook": lambda raw, source: parse_ransomware(raw, source, site="https://www.ransomlook.io")}


# ------------------------------------------------------------------ scoring

def _keyword_re(kw):
    kw = kw.lower()
    pat = re.escape(kw)
    # Word boundaries keep short English keywords ("rce", "apt") from matching
    # inside other words ("source", "adapt"). Korean keywords match as substrings.
    if kw[:1].isascii() and kw[:1].isalnum():
        pat = r"(?<![a-z0-9])" + pat
    if kw[-1:].isascii() and kw[-1:].isalnum():
        pat = pat + r"(?![a-z0-9])"
    return re.compile(pat)


class Scorer:
    def __init__(self, keywords):
        self.critical = [_keyword_re(k) for k in keywords.get("critical", [])]
        self.high = [_keyword_re(k) for k in keywords.get("high", [])]
        self.focus = [_keyword_re(k) for k in keywords.get("focus", [])]
        self.focus_security = [_keyword_re(k) for k in keywords.get("focus_security", [])]
        weak = {k.lower() for k in keywords.get("weak", [])}
        self.strong_high = [_keyword_re(k) for k in keywords.get("high", []) if k.lower() not in weak]

    def classify(self, item):
        """Set score, security_hits and focus on the item and return the score."""
        text = f"{item['title']} {item.get('summary', '')}".lower()
        critical = sum(1 for r in self.critical if r.search(text))
        high = sum(1 for r in self.high if r.search(text))
        title = item["title"].lower()
        # A passing mention in the summary does not make a story a focus story: it needs a focus
        # word in the headline or two in the text.
        focus = (any(r.search(title) for r in self.focus)
                 or sum(1 for r in self.focus if r.search(text)) >= 2)
        item["security_hits"] = critical + high
        item["focus"] = focus
        # Focus-topic news without a security angle stays out. Words listed as weak are too loose
        # to give a focus story that angle on their own.
        item["focus_security"] = (bool(critical) or any(r.search(text) for r in self.strong_high)
                                  or any(r.search(text) for r in self.focus_security))
        score = item.get("base_score", 0) + 3 * critical + high + (1 if focus else 0)
        if not critical and item.get("base_score", 0) < 3:
            # 🚨 (3+) needs a critical keyword such as zero-day or RCE, or a KEV entry. A company
            # press release that says 보안, AI and 해킹 is not urgent however many such words it has.
            score = min(score, 2)
        item["score"] = score
        return score

    score = classify


class SectorTagger:
    """Industry tags from keyword lists in feeds.json, shown as Telegram hashtags."""

    def __init__(self, sectors, max_tags=2, key="sectors", fallback=None):
        self.sectors = [(name, [_keyword_re(k) for k in words]) for name, words in sectors.items()]
        # Catch-alls tried only when no industry matched, so the 기타 section stays small.
        self.fallback = [(name, [_keyword_re(k) for k in words]) for name, words in (fallback or {}).items()]
        self.max_tags = max_tags
        self.key = key

    def tag(self, item):
        text = f"{item['title']} {item.get('summary', '')} {item.get('sector', '')}".lower()
        hits = [(sum(1 for r in rs if r.search(text)), i, name) for i, (name, rs) in enumerate(self.sectors)]
        item[self.key] = [name for n, _, name in sorted(hits, key=lambda h: (-h[0], h[1])) if n][:self.max_tags]
        if not item[self.key]:
            item[self.key] = [name for name, rs in self.fallback if any(r.search(text) for r in rs)][:1]
        return item[self.key]


def level(score):
    if score >= 3:
        return "🚨", "긴급"
    if score >= 1:
        return "⚠️", "주요"
    return "📰", "일반"


def section(item):
    return "urgent" if item["score"] >= 3 else "notable"


SECTIONS = [("urgent", "🚨 <b>긴급</b>"), ("notable", "⚠️ <b>주요</b>")]

# Message titles, section icons and the welcome text can be replaced in feeds.json under "texts".
TEXTS = {
    "focus_title": "📌 <b>중점 보안 속보</b>",
    "general_title": "🛡 <b>보안 속보</b>",
    "ransomware_title": "🏴 <b>랜섬웨어·유출 동향</b>",
    "instant_title": "🚨 <b>긴급 보안 속보</b>",
    "welcome": "🛡 <b>보안 속보 구독이 시작됐어요.</b>\n보안 속보를 정기적으로 모아서 보내 드려요.\n"
               "그만 받으려면 /stop 을 보내 주세요.",
    "night": "🌙 지금부터 {until}시까지는 취침 모드예요. 정기 발송을 쉬고, {morning}시에 밤사이 소식을 한꺼번에 보내 "
             "드릴게요.\n🚨 긴급 속보는 알림 소리 없이 바로 보내요.",
    "no_news": "📭 {time} 기준 새로 보낼 보안 뉴스가 없어요. 새 소식이 생기면 다음 정각에 보내 드릴게요.",
}


def wording(config, name):
    return (config or {}).get("texts", {}).get(name) or TEXTS[name]


def icons(config):
    return {**SECTOR_ICONS, **(config or {}).get("sector_icons", {})}


def ransomware_wanted(item, config):
    """Victims in watched countries, in watched sectors, or with focus-topic names."""
    if item["country"] in config.get("ransomware_countries", ["KR"]):
        return True
    sector = item["sector"].lower()
    if any(s.lower() in sector for s in config.get("ransomware_sectors", [])):
        return True
    return bool(item.get("focus"))


# Focus items go out as their own message with their own cap, so general news never crowds them out.
# (focus?, title text, cap setting, category set in feeds.json)
DIGESTS = [
    (True, "focus_title", "max_focus_per_run", "focus_sectors"),
    (False, "general_title", "max_items_per_run", "sectors"),
]

# Section icons; feeds.json "sector_icons" adds to or replaces these.
SECTOR_ICONS = {"금융": "💰", "가상자산": "🪙", "공공": "🏛", "의료": "🏥", "통신": "📡", "에너지": "⚡",
                "제조": "🏭", "유통": "🛒", "교육": "🎓", "물류": "🚚", "건설": "🏗", "IoT": "📷",
                "IT": "💻", "AI": "🤖", "SW·취약점": "🧩", "기타": "📌"}
OTHER_SECTOR = "기타"


# -------------------------------------------------------------------- state

def item_key(item):
    if item["id"].startswith("kev:"):
        return item["id"]
    link = item["link"] or item["id"]
    try:
        u = urllib.parse.urlsplit(link)
        q = [(k, v) for k, v in urllib.parse.parse_qsl(u.query) if not TRACKING_PARAMS.match(k)]
        scheme = "https" if u.scheme == "http" else u.scheme
        link = urllib.parse.urlunsplit((scheme, u.netloc.lower(), u.path.rstrip("/"), urllib.parse.urlencode(q), ""))
    except ValueError:
        pass
    return link


def title_key(item):
    words = re.sub(r"[^\w]+", " ", item["title"].lower()).split()
    return "t:" + " ".join(words)[:120]


def load_state(path):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return None
    except (OSError, ValueError) as e:
        log(f"warning: state file unreadable ({e}); starting fresh")
        return None


# Bookkeeping that only some runs update; save_state keeps the stored copy when a run passes none.
KEPT_STATE = ("night_notice", "decisions", "stats", "report_week", "deferred_hour", "deferred_tries", "prejudged")


def save_state(path, seen, now, recent=None, feed_failures=None, last_digest=None, instant_checked=None,
               **extra):
    cutoff = (now - STATE_RETENTION).timestamp()
    seen = {k: t for k, t in seen.items() if t >= cutoff}
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    state = {"seen": seen, "last_digest": now.timestamp() if last_digest is None else last_digest,
             "recent": recent or [], "feed_failures": feed_failures or {}}
    if instant_checked is not None:
        state["instant_checked"] = instant_checked
    try:
        old = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        old = {}
    for k in KEPT_STATE:
        if k in extra:
            state[k] = extra[k]
        elif isinstance(old, dict) and k in old:
            state[k] = old[k]
    if "decisions" in state:  # /why looks back three days
        state["decisions"] = {u: d for u, d in state["decisions"].items() if d[1] >= now.timestamp() - 3 * 86400}
    tmp.write_text(json.dumps(state, ensure_ascii=False), encoding="utf-8")
    tmp.replace(path)


# ---------------------------------------------------------------- messages

FEED_FOOTER = re.compile(r"\s*(The post .*? appeared first on .*|Continue reading.*|Read more.*)$", re.I | re.S)


def strip_outlet(title, source):
    """Headlines that end in their outlet's name ("... - 머니투데이", "... | 보안뉴스"): the
    details line names the outlet already."""
    for sep in (" - ", " | ", " : "):
        if source and title.endswith(sep + source) and len(title) > len(sep + source) + 5:
            return title[: -len(sep + source)].rstrip()
    return title


# A reporter's byline opening a Korean article: "현대경제신문 김성훈 기자 | ", "[서울=뉴스핌] 송주원 기자 = ".
BYLINE = re.compile(r"^\s*(?:\[[^\]]{1,20}\]\s*)?(?:[\w·]{2,12}\s+)?[가-힣]{2,4}\s?(?:기자|특파원)\s*[|ㅣ=:]\s*")


def short_summary(item, limit=140):
    """First sentence or so of the feed's own description, or "" if it adds nothing."""
    text = BYLINE.sub("", FEED_FOOTER.sub("", item.get("summary") or "").strip())
    title = item["title"].strip()
    if text.startswith(title):
        text = text[len(title):].lstrip(" :-–—")
    if len(text) < 20:
        return ""
    if len(text) > limit:
        cut = text[:limit]
        text = (cut.rsplit(" ", 1)[0] if " " in cut[limit // 2:] else cut).rstrip(",.;: ") + "…"
    return text


def model_label(model):
    """gemini-3.8-flash-lite -> Gemini 3.8 Flash Lite (the AI that judged an article)."""
    name = re.sub(r"^models/", "", model).replace("-latest", "")
    name = re.sub(r"(-\d{2})+-\d{4}$|-\d{4}(-\d{2})+$|-\d{3,}$", "", name)  # release dates
    words = name.split("-")
    return " ".join(w.capitalize() if w.isalpha() else w for w in words)


ITEM_STYLE = "plain"  # "quote": each article in its own quote box (feeds.json "item_style", set in main())


def model_tag(model):
    """Compact AI mark for the boxed layout: "3.8" for Gemini 3.8 Flash, "3.5L" for 3.5 Flash Lite."""
    label = model_label(model)
    m = re.search(r"\d+(\.\d+)?", label)
    if not m:
        return label
    return m.group(0) + ("L" if "Lite" in label else "")


def model_badge(model):
    """The AI mark at the end of a boxed article's details line, after a Gemini-like sparkle: ✦3.5L for 3.5 Flash Lite."""
    return "✦" + model_tag(model)


TAP_PAD = "\u2800" * 22  # a blank line that still belongs to the title's link (boxed layout)


def format_item(item, hide_sector=None, key="sectors"):
    when = item["date"].astimezone(KST).strftime("%m-%d %H:%M") if item["date"] else ""
    title = html.escape(item.get("display_title", item["title"]))
    if item["link"]:
        title = f'<a href="{html.escape(item["link"], quote=True)}">{title}</a>'
    tags = "".join(f"#{t.replace('·', '_').replace(' ', '_')} " for t in item.get(key, []) if t != hide_sector)
    mark = "🚨 " if hide_sector is not None and item["score"] >= 3 else ""
    lines = [f"🔹 {mark}{tags}<b>{title}</b>"]
    summary = item["display_summary"] if "display_summary" in item else short_summary(item)
    source = html.escape(item["source"])  # the title already links to the article
    if ITEM_STYLE == "quote":
        # Telegram has no bordered boxes; a quote per article is the closest. Quotes cannot nest, so
        # the summary is plain text inside it and the details share one line. The box sets articles
        # apart, so the bullet goes.
        head = f"{mark}{tags}<b>{title}</b>"
        if item["link"]:
            # A tap beside the link opens Telegram's message menu. The line under the title is part
            # of the link, in blank Braille cells (Telegram keeps those; it trims plain spaces), so
            # the tap target is two lines high.
            pad = html.escape(item.get("display_title", item["title"])) + "\n" + TAP_PAD
            head = f'{mark}{tags}<b><a href="{html.escape(item["link"], quote=True)}">{pad}</a></b>'
        lines = [head]
        if summary:
            if not item["link"]:
                lines.append("")
            lines.append(f"<i>{html.escape(summary)}</i>")  # set apart from the title, in italics
        meta = f"📰 {source}" + (f" · {when}" if when else "")
        if item.get("ai_model"):
            meta += f" · {model_badge(item['ai_model'])}"
        elif item.get("keyword_only"):
            meta += " · 🔑 키워드"
        lines.append(meta)
        return "<blockquote>" + "\n".join(lines) + "</blockquote>"
    if summary:
        lines.append(f"<blockquote>{html.escape(summary)}</blockquote>")
    meta = f"📰 출처: {source}" + (f" · {when}" if when else "")
    if item.get("translated"):
        # No link to Google's translated copy: its proxy (translate.goog) is blocked in Korea.
        meta += " · 🌐 영문 기사 (제목·요약 번역)"
    lines.append(meta)
    if item.get("ai_model"):
        lines.append(f"🤖 {model_label(item['ai_model'])}")
    elif item.get("keyword_only"):
        lines.append("🔑 키워드 판단 (AI 응답 지연)")
    return "\n".join(lines)


TAG = re.compile(r"<[^>]+>")
MAX_ENTITIES = 90  # stay under Telegram's cap on formatting entities per message


def visible_len(text):
    """Telegram's 4096 limit counts the text after HTML parsing, so markup and URLs are free."""
    return len(html.unescape(TAG.sub("", text)))


def entity_count(text):
    return len(re.findall(r"<(?!/)[^>]+>", text))


def primary_sector(item, key="sectors"):
    return (item.get(key) or [OTHER_SECTOR])[0]


def build_messages(items, now=None, title="🛡 <b>보안 뉴스</b>", limit=TELEGRAM_LIMIT - 200,
                   sector_order=None, key="sectors", last=(), icons=None):
    """Group items into sections and pack them into as few Telegram messages as fit.
    With sector_order the sections are industries (urgent items marked 🚨), otherwise 긴급/주요."""
    now = now or datetime.now(timezone.utc)
    header = f"{title} · {now.astimezone(KST):%m/%d %H:%M} · {len(items)}건"
    if sector_order is not None:
        names = [n for n in sector_order if n != OTHER_SECTOR] + [OTHER_SECTOR]
        groups = [(f"{(icons or SECTOR_ICONS).get(n, '🔸')} <b>{n}</b>", n, [it for it in items if primary_sector(it, key) == n])
                  for n in names]
        groups.sort(key=lambda g: (g[1] == OTHER_SECTOR, g[1] in last, -max((it["score"] for it in g[2]), default=0)))
    else:
        groups = [(heading, None, [it for it in items if section(it) == key]) for key, heading in SECTIONS]
    blocks = []
    for heading, name, group in groups:
        for i, item in enumerate(group):
            block = format_item(item, name, key)
            if i == 0:
                block = f"{heading} ({len(group)})\n\n{block}" if name else f"{heading}\n\n{block}"
            blocks.append(block)

    messages, cur = [], header
    for block in blocks:
        if (visible_len(cur) + 2 + visible_len(block) > limit
                or entity_count(cur) + entity_count(block) > MAX_ENTITIES):
            messages.append(cur)
            cur = block
        else:
            cur += "\n\n" + block
    messages.append(cur)
    return messages


# -------------------------------------------------------------- translation

HANGUL = re.compile(r"[\uac00-\ud7a3]")


def needs_translation(text):
    letters = sum(c.isascii() and c.isalpha() for c in text)
    return bool(text) and not HANGUL.search(text) and letters >= len(text) * 0.4


def google_translate(text, target="ko", timeout=15):
    """Translate with Google's public web endpoint (no key). Raises on failure."""
    url = "https://translate.googleapis.com/translate_a/single?" + urllib.parse.urlencode(
        {"client": "gtx", "sl": "auto", "tl": target, "dt": "t", "q": text})
    for attempt in range(3):  # the free endpoint throttles bursts now and then
        try:
            data = json.loads(fetch(url, timeout=timeout))
            break
        except (OSError, ValueError):
            if attempt == 2:
                raise
            time.sleep(3 * (attempt + 1))
    out = "".join(seg[0] for seg in data[0] if seg and seg[0])
    if not out.strip():
        raise ValueError("empty translation")
    return out.strip()


GEMINI_PROMPT = """You translate English cybersecurity news into Korean for a Telegram digest.
Write natural Korean news style, never word-for-word:
- Headlines: short Korean news headline style ending in a noun or a short verb stem, no "~합니다/~했습니다",
  no "~는/~은" sentence endings, no "경고 -"/"Warning:" prefixes. E.g. "Warning - Node2Shell RCE exploit works on
  official Node.js builds" -> "Node2Shell RCE 익스플로잇, 공식 Node.js 빌드서도 작동".
- Summaries: plain written news sentences ending in "~했다/~이다" (not "~합니다"), with natural Korean word order.
  E.g. "Researchers demonstrated how crafted Brotli data could trigger code execution in vulnerable Node.js
  apps." -> "연구진이 조작된 Brotli 데이터로 취약한 Node.js 앱에서 코드를 실행할 수 있음을 시연했다."
Keep company, product, group and malware names as they are (Anthropic, BeyondTrust, Lazarus), and keep
CVE ids, version numbers and acronyms (RCE, APT, KEV, CVSS) unchanged. Use the usual Korean security
terms (zero-day = 제로데이, exploit = 익스플로잇 or 악용, patch = 패치). Do not add or drop information.
Return only a JSON array of strings: the translations, in the same order, one per input.

Input:
"""


class GeminiBudget:
    """Caps Gemini requests per model per day (Google's free-tier day, Pacific time) below the free
    quota. Each model has its own quota, so when one model's share is used up the next one in the
    list takes over; when all are used up the keyword filter and Google Translate do the work."""

    def __init__(self, path, models):
        self.path, self.models = path, models  # [(model, daily cap), ...] in order of preference
        # Google's free-tier day starts at midnight Pacific *standard* time all year (08:00 UTC,
        # 17:00 in Korea), not at daylight-saving midnight: counting from 16:00 in summer made the
        # 16:00 digest's requests hit "used up for today" and retired the Flash models for a day.
        self.day = (datetime.now(timezone.utc) - timedelta(hours=8)).strftime("%Y-%m-%d")
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            data = {}
        # v2: days counted from 17:00 KST. Older files used a different day boundary, so their
        # "used up" marks may belong to the previous Google day: start those counts afresh.
        used = data.get("used") if isinstance(data, dict) and data.get("day") == self.day and data.get("v") == 2 else None
        self.used = {m: n for m, n in used.items() if isinstance(n, int)} if isinstance(used, dict) else {}
        # Requests actually sent, per day and model, for the admin's numbers (exhaust() marks a
        # model full without sending anything, so "used" alone overstates).
        history = data.get("history") if isinstance(data, dict) else None
        self.history = ({d: dict(v) for d, v in history.items() if isinstance(v, dict)}
                        if isinstance(history, dict) else {})
        self.history.setdefault(self.day, {})
        # Models that just turned a request away rest until this time (epoch seconds), across
        # requests and runs: asking them again at once only spends the day's quota.
        resting = data.get("resting") if isinstance(data, dict) else None
        self.resting = ({m: t for m, t in resting.items() if isinstance(t, (int, float)) and t > time.time()}
                        if isinstance(resting, dict) else {})

    def rest(self, model, minutes):
        self.resting[model] = max(self.resting.get(model, 0), time.time() + minutes * 60)
        self._save()

    def _save(self):
        keep = sorted(self.history)[-8:]
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self.path.write_text(json.dumps({"v": 2, "day": self.day, "used": self.used, "resting": self.resting,
                                             "history": {d: self.history[d] for d in keep}}), encoding="utf-8")
        except OSError:
            pass

    def take(self, skip=(), lite_first=False):
        """Count one request and return the model to send it to (not one of skip). The Flash
        models' small daily share is kept for classification (digests and alerts): batch
        translations (lite_first) go to the Lite models first."""
        order = sorted(self.models, key=lambda m: "lite" not in m[0]) if lite_first else self.models
        now = time.time()
        # Resting models come last rather than never: if every model is resting, they still get asked.
        order = sorted(order, key=lambda m: self.resting.get(m[0], 0) > now)
        for model, cap in order:
            if model not in skip and self.used.get(model, 0) < cap:
                self.used[model] = self.used.get(model, 0) + 1
                today = self.history[self.day]
                today[model] = today.get(model, 0) + 1
                self._save()
                return model
        raise RuntimeError("today's Gemini budget is used up for every model")

    def exhaust(self, model):
        for m, cap in self.models:
            if m == model:
                self.used[m] = cap
        self._save()

    def summary(self, days=1):
        """Requests per model over the last `days` Google days, as lines for the admin."""
        recent = sorted(self.history)[-days:]
        lines = []
        for model, cap in self.models:
            n = sum(self.history[d].get(model, 0) for d in recent)
            lines.append(f"  - {model}: {n}회" + (f" / 한도 {cap}" if days == 1 else ""))
        total = sum(sum(self.history[d].values()) for d in recent)
        return [f"· AI(Gemini) 사용 {total}회" + (" (오늘, 매일 17시 초기화)" if days == 1 else f" (최근 {len(recent)}일)")] + lines


GEMINI_BUDGET = None  # set in main()
# How hard Lite models think before judging news (Gemini 3 "thinkingLevel": minimal, low, medium,
# high; "off" sends nothing). Lite answers fast without it but misses more; its 450 a day leave
# room. feeds.json "lite_thinking", set in main(). Models that refuse the setting go in NO_THINKING.
LITE_THINKING = "medium"
NO_THINKING = set()
# Free tier, October 2026: each model has its own daily quota (Flash models 20 requests a day, Flash
# Lite 500). Four Flash shares (about 70 a day) cover the digests; Flash Lite is the deep reserve.
# A model this key cannot use answers 404 and is skipped for the day (logged as a warning).
# 2.5 Flash comes second: the newest models are the first to be busy for free-tier keys (on
# 23 October 3.8 and 3.6 answered 503 for hours while 2.5 kept answering).
DEFAULT_GEMINI_MODELS = [{"model": "gemini-flash-latest", "daily": 18},  # 3.8 Flash
                         {"model": "gemini-2.5-flash", "daily": 18},
                         {"model": "gemini-3.6-flash", "daily": 18},
                         {"model": "gemini-3-flash-preview", "daily": 18},
                         {"model": "gemini-flash-lite-latest", "daily": 450},  # 3.5 Flash Lite
                         {"model": "gemini-3.1-flash-lite", "daily": 450}]


def gemini_json(prompt, key, model="gemini-flash-latest", timeout=90, lite_first=False, think=False):
    """One Gemini request that answers in JSON. Raises on any failure. think: a Lite model thinks
    first (LITE_THINKING), for judging news; Flash models think on their own."""

    def body_for(model):
        config = {"temperature": 0.2, "responseMimeType": "application/json"}
        if think and "lite" in model and LITE_THINKING != "off" and model not in NO_THINKING:
            config["thinkingConfig"] = {"thinkingLevel": LITE_THINKING}
        return json.dumps({"contents": [{"parts": [{"text": prompt}]}], "generationConfig": config}).encode()

    busy = set()  # models that answered "overloaded" to this request

    def turned_away(model, minutes=15):
        """Note a busy model. Google counts turned-away requests against the day's quota too, and when
        two Flash models are busy the others usually are as well: then this request goes to Lite.
        The model also rests for a while, so the next requests do not knock on it again."""
        busy.add(model)
        if GEMINI_BUDGET is not None:
            GEMINI_BUDGET.rest(model, minutes)
        if (GEMINI_BUDGET is not None and sum(1 for m in busy if "lite" not in m) >= 2
                and any("lite" in m and GEMINI_BUDGET.used.get(m, 0) < cap and m not in busy
                        for m, cap in GEMINI_BUDGET.models)):
            busy.update(m for m, _ in GEMINI_BUDGET.models if "lite" not in m)

    while True:
        if GEMINI_BUDGET is not None:
            model = GEMINI_BUDGET.take(skip=busy, lite_first=lite_first)
        url = f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent"
        body = body_for(model)
        req = urllib.request.Request(url, data=body, headers={
            "Content-Type": "application/json", "x-goog-api-key": key, "User-Agent": USER_AGENT})
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                data = json.loads(resp.read())
        except urllib.error.HTTPError as e:
            # 400 for the thinking setting: this model does not take it. Ask again without it.
            if e.code == 400 and b"thinkingConfig" in body:
                log(f"warning: Gemini {model}: HTTP 400 with thinking on; asking again without it")
                NO_THINKING.add(model)
                continue
            # 429 per minute (free Flash models allow 5 requests a minute): busy, like a 503 below.
            detail = ""
            if e.code == 429:
                try:
                    detail = e.read().decode("utf-8", "replace")
                except Exception:
                    pass
            per_minute = e.code == 429 and "PerMinute" in detail and "PerDay" not in detail
            spare = GEMINI_BUDGET is not None and len(busy) < len(GEMINI_BUDGET.models) - 1
            if GEMINI_BUDGET is not None and per_minute:
                if not spare:
                    raise  # every model is busy this minute: never retire one for the day over it
                log(f"warning: Gemini {model}: per-minute limit; trying another model")
                turned_away(model, minutes=1)
                continue
            # 429 for the day: this model's free quota is gone (or tests used it up); 404: no such
            # model here. Either way skip the model for the rest of the day and ask the next one.
            if GEMINI_BUDGET is not None and e.code in (404, 429):
                log(f"{'warning: ' if e.code == 404 else ''}Gemini {model}: HTTP {e.code}; switching to the next model for today")
                GEMINI_BUDGET.exhaust(model)
                continue
            # 500/502/503/504: Google is overloaded right now. Another model may answer (up to all
            # the models are tried); the busy one stays available for later requests.
            if GEMINI_BUDGET is not None and e.code in (500, 502, 503, 504) and spare:
                log(f"warning: Gemini {model}: HTTP {e.code}; trying another model")
                turned_away(model)
                time.sleep(3)
                continue
            raise
        except (TimeoutError, urllib.error.URLError, OSError) as e:
            # No answer in time (an overloaded model can sit on a request): ask another model.
            if GEMINI_BUDGET is not None and len(busy) < len(GEMINI_BUDGET.models) - 1:
                log(f"warning: Gemini {model}: {e}; trying another model")
                turned_away(model)
                continue
            raise
        try:
            # Models sometimes add a second JSON value or a remark after the answer: keep the first value.
            answer, _ = json.JSONDecoder().raw_decode(data["candidates"][0]["content"]["parts"][0]["text"].strip())
        except (KeyError, IndexError, TypeError, ValueError) as e:
            if GEMINI_BUDGET is not None and len(busy) < len(GEMINI_BUDGET.models) - 1:
                log(f"warning: Gemini {model}: unusable answer ({e}); trying another model")
                turned_away(model)
                continue
            raise
        # The exact model behind an alias such as gemini-flash-latest, for the article's AI mark.
        gemini_json.last_model = data.get("modelVersion") or model
        log(f"Gemini request answered by {gemini_json.last_model}")
        return answer


def gemini_translate_batch(texts, key, model="gemini-flash-latest", timeout=120):
    """Translate several texts in one Gemini request. Raises on any failure."""
    out = gemini_json(GEMINI_PROMPT + json.dumps(texts, ensure_ascii=False), key, model, timeout, lite_first=True)
    if not isinstance(out, list) or len(out) != len(texts) or not all(isinstance(t, str) and t.strip() for t in out):
        raise ValueError("translation list does not match the input")
    return [t.strip() for t in out]


class GeminiTranslator:
    """Translates a whole digest in a few Gemini requests (the free tier counts requests, not
    words) and falls back to Google Translate for anything Gemini did not return."""

    def __init__(self, key, model="gemini-flash-latest", chunk=40):
        self.key, self.model, self.chunk, self.done = key, model, chunk, {}

    def prefetch(self, texts):
        todo = list(dict.fromkeys(t for t in texts if t not in self.done))
        if not todo:
            return
        for i in range(0, len(todo), self.chunk):
            part = todo[i:i + self.chunk]
            try:
                self.done.update(zip(part, gemini_translate_batch(part, self.key, self.model)))
            except Exception as e:  # quota, outage or a malformed reply: Google Translate takes over
                log(f"warning: Gemini translation failed ({e}); using Google Translate")
                return
        if todo:
            log(f"translated {len(todo)} text(s) with Gemini")

    def __call__(self, text):
        out = self.done.get(text)
        if not out:
            return google_translate(text)
        cap = max(200, 2 * len(text))  # a translation is about as long as its source
        return out if len(out) <= cap else out[:cap].rstrip() + "…"


# feeds.json "classify_prompt" replaces this; it must ask for the same JSON fields.
CLASSIFY_PROMPT = """You sort news items for a Korean cybersecurity digest. For every item decide:
- relevant: true only if it is about cybersecurity or information security: attacks, breaches, leaks,
  vulnerabilities and patches, malware, threat actors, security policy, law or budgets, security events
  or training. False for company earnings, product marketing with no security news, general politics,
  sports, entertainment, spam.
- focus: true only if it directly concerns one of the topics in FOCUS_SECTORS. False when such a topic is
  only mentioned in passing.
- urgent: be strict; usually no more than one item in five. True only for: a vulnerability exploited in
  the wild or a zero-day, a critical (CVSS 9+) remote code execution flaw in widely used software, a breach
  or leak of millions of records or of government data, or an attack disrupting government or critical
  infrastructure. False for small breaches, press releases, partnerships, events, opinion, explainers,
  statistics, arrests and court cases.
- dup_of: if this item reports the same event as an EARLIER item in the list (any language, any outlet),
  that item's number; otherwise null.
- already_sent: true if it reports the same event as a line in ALREADY_SENT (stories that went out in the
  last two days), even with new details; false otherwise.
- story: the event in 4 to 8 lowercase English words, naming the vendor, product or victim
  (e.g. "beyondtrust remote support zero-day exploited").
- sector: the one industry it is mainly about, from SECTORS (use "기타" if none fits).
- focus_sector: the one category from FOCUS_SECTORS (use "기타" if none fits).
- title_ko, summary_ko: if the title or summary is not in Korean, its Korean translation in natural Korean
  news style (short headline; keep company, product, group and malware names, CVE ids, versions and
  acronyms such as RCE, APT, KEV, CVSS as they are; zero-day = 제로데이; add or drop nothing). Empty string
  when the text is already Korean or empty.

Answer only with a JSON array, one object per item in the same order:
{"i": <item number>, "relevant": bool, "focus": bool, "urgent": bool, "sector": str, "focus_sector": str,
 "dup_of": <number or null>, "already_sent": bool, "story": str, "title_ko": str, "summary_ko": str}
"""


def gemini_classify(items, key, model, sectors, focus_sectors, told=(), instructions=None, lite_first=False):
    rows = [{"i": n, "title": it["title"], "summary": short_summary(it)} for n, it in enumerate(items)]
    prompt = ((instructions or CLASSIFY_PROMPT) + "\nSECTORS: " + json.dumps(sectors + ["기타"], ensure_ascii=False)
              + "\nFOCUS_SECTORS: " + json.dumps(focus_sectors + ["기타"], ensure_ascii=False)
              + "\nALREADY_SENT: " + json.dumps(list(told)[-150:], ensure_ascii=False)
              + "\n\nItems:\n" + json.dumps(rows, ensure_ascii=False))
    out = gemini_json(prompt, key, model, timeout=90, lite_first=lite_first, think=True)  # 15 items with translations
    if not isinstance(out, list) or len(out) != len(items):
        raise ValueError("classification list does not match the input")
    by_i = {r.get("i"): r for r in out if isinstance(r, dict)}
    if set(by_i) != set(range(len(items))):
        raise ValueError("classification is missing items")
    return [by_i[n] for n in range(len(items))]


def cache_key(item):
    """The pre-judging cache's key: the item's usual key, or its title for bare test items."""
    return item_key(item) if item.get("id") is not None else item.get("title", "")


class GeminiClassifier:
    """Second opinion on the keyword filter: Gemini drops off-topic items and sets focus,
    urgency and sector. Keyword results stay for anything Gemini could not judge."""

    def __init__(self, key, config, model="gemini-flash-latest", chunk=15, limit=90):
        self.key, self.model, self.chunk, self.limit = key, model, chunk, limit
        self.lite_first = False  # True would send this classifier's requests to the Lite models first
        self.deadline = 420  # seconds for all requests of one run; the job is stopped after 25 minutes
        # Verdicts from the half-past pre-judging run, by item key: [Gemini's answer, model]. Items
        # found here are not asked again; every verdict of this call ends up in results.
        self.cache, self.results = {}, {}
        self.sectors = list(config.get("sectors", {})) + list(config.get("fallback_sectors", {}))
        self.focus_sectors = list(config.get("focus_sectors", {}))
        self.instructions = config.get("classify_prompt")

    def __call__(self, items, told=()):
        """Return the items to keep, best keyword score first in, same order out."""
        judged, dropped, dups, failed, models = {}, 0, 0, False, []
        self.failed = False
        # The best-ranked 90 are judged, 15 per request: an hourly digest needs one or two requests,
        # the 06:00 round-up more, smaller ones (one big request of 60 failed with 503 or timed out
        # far more often). The rest are dropped unless Gemini failed: unjudged low-ranked items
        # must not fill the places of judged ones it turned down.
        head = items[:self.limit]
        told = list(told)

        def remember(it, r, answered):
            judged[id(it)] = r
            it["ai_model"] = answered
            self.results[cache_key(it)] = [r, answered]
            # Later requests see this round's stories too: Gemini compares items only within
            # one request, so the same event split across two requests went out twice.
            if r.get("relevant") and not (r.get("duplicate") or r.get("already_sent")):
                story = r.get("story") if isinstance(r.get("story"), str) else ""
                told.append(f"{it['title']} ({story.strip()})" if story.strip() else it["title"])

        for it in head:
            hit = self.cache.get(cache_key(it))
            if isinstance(hit, list) and len(hit) == 2 and isinstance(hit[0], dict):
                remember(it, dict(hit[0]), hit[1])
        head = [it for it in head if id(it) not in judged]
        started = time.monotonic()
        for i in range(0, len(head), self.chunk):
            part = head[i:i + self.chunk]
            if i and time.monotonic() - started > self.deadline:
                # Google is slow today: the rest keep keyword results rather than run past the job's limit.
                log(f"warning: Gemini classification stopped after {self.deadline // 60} minutes; keeping keyword results")
                failed = self.failed = True
                break
            try:
                results = gemini_classify(part, self.key, self.model, self.sectors, self.focus_sectors, told,
                                          self.instructions, self.lite_first)
                for n, r in enumerate(results):
                    d = r.get("dup_of")
                    if isinstance(d, int) and not isinstance(d, bool) and 0 <= d < len(part) and d != n:
                        results[max(n, d)]["duplicate"] = True  # the better-ranked report stays
                answered = getattr(gemini_json, "last_model", None) or self.model
                models.append(answered)
                for it, r in zip(part, results):
                    remember(it, r, answered)
            except Exception as e:
                log(f"warning: Gemini classification failed ({e}); keeping keyword results")
                failed = self.failed = True
                break
        kept = []
        for it in items:
            r = judged.get(id(it))
            if r is None:
                if failed or it.get("forced"):
                    it["keyword_only"] = failed
                    kept.append(it)
                else:
                    it["drop_reason"] = "gemini_limit"
                continue
            focus = bool(r.get("focus"))
            if r.get("duplicate") or r.get("already_sent"):
                dups += 1
                it["drop_reason"] = "gemini_dup"
                continue
            if not it.get("forced") and (not r.get("relevant") or (it.get("focus_only") and not focus)):
                dropped += 1
                it["drop_reason"] = "gemini_irrelevant" if not r.get("relevant") else "gemini_focus_only"
                continue
            if isinstance(r.get("story"), str) and r["story"].strip():
                it["story"] = r["story"].strip().lower()
            # A runaway answer (or text a feed slipped in to steer Gemini) must not blow up a message.
            for field, cap in (("title_ko", 200), ("summary_ko", 300)):
                if isinstance(r.get(field), str) and r[field].strip():
                    text = r[field].strip()
                    it[field] = text if len(text) <= cap else text[:cap].rstrip() + "…"
            it["focus"] = focus
            it["score"] = max(it["score"], 3) if r.get("urgent") or it.get("forced") else min(it["score"], 2)
            sector, fsector = r.get("sector"), r.get("focus_sector")
            if sector in self.sectors or sector == OTHER_SECTOR:
                it["sectors"] = [] if sector == OTHER_SECTOR else [sector]
            if fsector in self.focus_sectors or fsector == OTHER_SECTOR:
                it["focus_sectors"] = [] if fsector == OTHER_SECTOR else [fsector]
            kept.append(it)
        if judged:
            log(f"classified {len(judged)} item(s) with Gemini; dropped {dropped} as off-topic, {dups} as duplicates"
                + (" (partly)" if failed else ""))
            log("ai models: " + ", ".join(f"{m} x{models.count(m)}" for m in dict.fromkeys(models)))
        return kept


def make_classifier(config):
    key = os.environ.get("GEMINI_API_KEY", "").strip()
    if key and config.get("gemini_classify", True):
        return GeminiClassifier(key, config, config.get("gemini_model", "gemini-flash-latest"))
    return None


def make_translator(config):
    if not config.get("translate_to_korean", True):
        return None
    key = os.environ.get("GEMINI_API_KEY", "").strip()
    if key:
        return GeminiTranslator(key, config.get("gemini_model", "gemini-flash-latest"))
    return google_translate


PAGE_SUMMARIES = False  # fetch missing summaries from the article pages (set in main(); tests stay offline)
META_DESC = re.compile(r"<meta\b[^>]*>", re.I)


def google_news_target(link, timeout=8):
    """The article behind a Google News RSS link (news.google.com/rss/articles/<id>), or "".
    Google's page holds a signature for the id; Google's own page script trades the two for the
    address, and so does this. Two small requests; any change on Google's side just gives ""."""
    m = re.search(r"news\.google\.com/(?:rss/)?articles/([\w-]+)", link)
    if not m:
        return ""
    gid = m.group(1)
    page = fetch(f"https://news.google.com/rss/articles/{gid}", timeout).decode("utf-8", "replace")
    sg, ts = re.search(r'data-n-a-sg="([^"]+)"', page), re.search(r'data-n-a-ts="([^"]+)"', page)
    if not sg or not ts:
        return ""
    req = ('["garturlreq",[["X","X",["X","X"],null,null,1,1,"US:en",null,1,null,null,null,null,null,0,1],'
           '"X","X",1,[1,1,1],1,1,null,0,0,null,0],' + json.dumps(gid) + "," + ts.group(1) + "," + json.dumps(sg.group(1)) + "]")
    body = "f.req=" + urllib.parse.quote(json.dumps([[["Fbv4je", req, None, "generic"]]]))
    post = urllib.request.Request("https://news.google.com/_/DotsSplashUi/data/batchexecute", data=body.encode(),
                                  headers={"Content-Type": "application/x-www-form-urlencoded;charset=UTF-8",
                                           "User-Agent": "Mozilla/5.0"})
    with urllib.request.urlopen(post, timeout=timeout) as resp:
        text = resp.read().decode("utf-8", "replace")
    try:
        url = json.loads(json.loads(text.split("\n\n", 1)[1])[0][2])[1]
    except (IndexError, TypeError, ValueError):
        return ""
    return url if isinstance(url, str) and url.startswith("http") and "news.google.com" not in url else ""


def page_summary(item, timeout=8):
    """The article page's own description (og:description and the like) for an item whose feed
    sent none, or "". Only text that shares a word with the title: a site's generic slogan is not
    a summary. Google News links are first traded for the article's own address."""
    link = item.get("link") or ""
    if "news.google.com" in link:
        link = google_news_target(link, timeout)
    if not link.startswith("http"):
        return ""
    req = urllib.request.Request(link, headers={"User-Agent": "Mozilla/5.0", "Accept-Language": "ko,en;q=0.8"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        raw = resp.read(400_000)
        charset = resp.headers.get_content_charset()
    if not charset:
        m = re.search(rb"<meta[^>]+charset=[\"']?([\w-]+)", raw[:5000], re.I)
        charset = m.group(1).decode() if m else "utf-8"
    try:
        page = raw.decode(charset, "replace")
    except LookupError:
        page = raw.decode("utf-8", "replace")
    found = {}
    for tag in META_DESC.findall(page[:200_000]):
        name = re.search(r"""(?:property|name)\s*=\s*["']([^"']+)""", tag, re.I)
        content = re.search(r"""content\s*=\s*("([^"]*)"|'([^']*)')""", tag, re.I | re.S)
        if name and content:
            found.setdefault(name.group(1).lower(), content.group(2) if content.group(2) is not None else content.group(3))
    words = [w for w in re.findall(r"\w+", item["title"]) if len(w) >= 3]
    for key in ("og:description", "twitter:description", "description"):
        text = clean_text(found.get(key, ""))
        if len(text) >= 30 and any(w[:3] in text for w in words):
            return text
    return ""


def fill_summaries(items):
    """Feeds that send only the title (or the outlet's name) leave articles without a summary:
    take one from the article pages instead, a few at a time."""
    todo = [it for it in items if not short_summary(it) and "display_summary" not in it]
    if not PAGE_SUMMARIES or not todo:
        return
    errors = []

    def one(item):
        try:
            return item, page_summary(item)
        except Exception as e:
            errors.append(f"{type(e).__name__}: {e}"[:80])
            return item, ""
    with concurrent.futures.ThreadPoolExecutor(max_workers=6) as pool:
        got = 0
        for item, text in pool.map(one, todo):
            if text:
                item["summary"], got = text, got + 1
    log(f"summaries from article pages: {got} of {len(todo)}"
        + (f" ({len(errors)} failed, e.g. {errors[0]})" if errors else ""))


def localize(items, translate):
    """Fill display_title/display_summary, translating English text to Korean.
    The original title stays on the item and the link still points at the original article."""
    fill_summaries(items)

    def pending(item):
        """Texts still in English after the classifier's own translations."""
        title, summary = item["title"], short_summary(item)
        return [title if needs_translation(title) and not item.get("title_ko") else None,
                summary if summary and needs_translation(summary) and not item.get("summary_ko") else None]

    if hasattr(translate, "prefetch"):
        texts = []
        for item in items:
            if not item.get("no_translate"):
                texts += [t for t in pending(item) if t]
        translate.prefetch(texts)
    for item in items:
        title, summary = item["title"], short_summary(item)
        if not item.get("no_translate") and (item.get("title_ko") or item.get("summary_ko")):
            # Gemini sometimes "translates" Korean text too; only a real translation is marked.
            if needs_translation(title) and item.get("title_ko"):
                title = item["title_ko"]
                item["translated"] = True
            if summary and needs_translation(summary) and item.get("summary_ko"):
                summary = item["summary_ko"]
                item["translated"] = True
        todo = [needs_translation(title), bool(summary) and needs_translation(summary)]
        if translate and not item.get("no_translate") and any(todo):
            try:
                if todo[0]:
                    title = translate(title)
                if todo[1]:
                    summary = translate(summary)
                item["translated"] = True
            except Exception as e:  # keep the English text rather than drop the item
                log(f"warning: translation failed for {item['title'][:60]!r}: {e}")
                title = item.get("title_ko") or item["title"]
                summary = item.get("summary_ko") or short_summary(item)
            if not getattr(translate, "done", {}).get(item["title"]):
                time.sleep(0.2)  # Google's free endpoint dislikes bursts
        item["display_title"], item["display_summary"] = title, summary


# ---------------------------------------------------------------- telegram

class TelegramError(Exception):
    pass


def telegram_api(token, method, params, timeout=20):
    body = urllib.parse.urlencode(params).encode()
    try:
        with urllib.request.urlopen(urllib.request.Request(
                f"https://api.telegram.org/bot{token}/{method}", data=body), timeout=timeout) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError as e:
        try:
            desc = json.loads(e.read()).get("description", "")
        except ValueError:
            desc = ""
        raise TelegramError(f"{e.code} {method}: {desc}") from None


def telegram_send(token, chat_id, text, retries=3, markup=None, silent=False):
    url = f"https://api.telegram.org/bot{token}/sendMessage"
    params = {
        "chat_id": chat_id,
        "text": text,
        "parse_mode": "HTML",
        "disable_web_page_preview": "true",
    }
    if markup:
        params["reply_markup"] = json.dumps(markup)
    if silent:
        params["disable_notification"] = "true"
    body = urllib.parse.urlencode(params).encode()
    for attempt in range(retries + 1):
        try:
            with urllib.request.urlopen(urllib.request.Request(url, data=body), timeout=20) as resp:
                return json.loads(resp.read())
        except urllib.error.HTTPError as e:
            try:
                info = json.loads(e.read())
            except ValueError:
                info = {}
            wait = info.get("parameters", {}).get("retry_after")
            if e.code == 429 and wait and attempt < retries:
                time.sleep(int(wait) + 1)
                continue
            raise TelegramError(f"{e.code} {info.get('description', e.reason)}") from None
        except urllib.error.URLError as e:
            if attempt < retries:
                time.sleep(2 ** attempt)
                continue
            raise TelegramError(str(e.reason)) from None


def load_env_file(path):
    """Read KEY=VALUE lines; blank lines, comments and an `export ` prefix are allowed."""
    values = {}
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return values
    for line in lines:
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.removeprefix("export ").split("=", 1)
        values[key.strip()] = value.strip().strip("'\"")
    return values


def all_chat_ids(config, extra=""):
    """Recipients listed in feeds.json "chat_ids" plus any from the secret or env file, deduplicated.
    Keeping them in feeds.json means a git push reaches the server's timer without logging in."""
    ids = [str(c) for c in config.get("chat_ids", [])] + parse_chat_ids(extra)
    return list(dict.fromkeys(i.strip() for i in ids if str(i).strip()))


def parse_chat_ids(value):
    return [c for c in re.split(r"[\s,;]+", value or "") if c]


# ----------------------------------------------------------- subscriptions

GOODBYE = "구독을 해지했어요. 다시 받으려면 /start 를 보내 주세요."
REQUESTED = ("구독 신청이 접수됐어요. 관리자가 승인하면 \"구독이 시작됐어요\" 메시지와 함께 뉴스를 보내 드려요.\n"
             "⏳ 관리자 승인 후 10~15분 정도 소요됩니다. /start는 한 번만 누르면 돼요.")
# Shown under the admin's buttons; dropped again when the result replaces the buttons.
APPROVE_HINT = "⏳ 버튼은 한 번만 누르세요. 10~15분 안에 처리되고 이 메시지가 \"승인 완료\"로 바뀌어요."
REJECTED = "구독 신청이 승인되지 않았어요."
# Telegram errors that mean the chat will never accept messages again.
GONE = re.compile(r"blocked by the user|user is deactivated|chat not found|kicked", re.I)


def telegram_get_updates(token, after=0, timeout=20, pages=20):
    """Updates newer than update id `after`. Telegram returns at most 100 per call, oldest
    first, and asking from an offset drops the older ones on its side, so page until done."""
    updates = []
    for _ in range(pages):
        params = {"limit": 100,
                  # Telegram remembers the last list it was given; name every kind the bot handles so
                  # button presses (callback_query) are never filtered out by an older setting.
                  "allowed_updates": json.dumps(["message", "callback_query", "my_chat_member"])}
        if after:
            params["offset"] = after + 1
        query = urllib.parse.urlencode(params)
        with urllib.request.urlopen(f"https://api.telegram.org/bot{token}/getUpdates?{query}",
                                    timeout=timeout) as resp:
            data = json.loads(resp.read())
        if not data.get("ok"):
            raise TelegramError(str(data.get("description")))
        batch = data["result"]
        updates += batch
        if len(batch) < 100:
            break
        after = batch[-1]["update_id"]
    return updates


def fetch_updates(token, after, waits=(2, 5)):
    """telegram_get_updates, asked again when Telegram says more updates are queued than it sent.
    A new bot once answered an empty list for 20 minutes while the admin's button presses waited
    in its queue. Updates just sent stay in the queue count until the next call confirms them."""
    updates = telegram_get_updates(token, after)
    for wait in (None,) + tuple(waits):
        if wait:
            time.sleep(wait)
            updates = telegram_get_updates(token, after) or updates
        try:
            queued = telegram_api(token, "getWebhookInfo", {}).get("result", {}).get("pending_update_count", 0)
        except (TelegramError, OSError, ValueError):
            return updates
        if queued <= len(updates):
            return updates
        log(f"telegram: {queued} update(s) queued but {len(updates)} received"
            + ("; asking again" if wait != waits[-1] else ""))
    return updates


def subscriber_key(token):
    """Key for the subscriber file, derived from the bot token. The file sits in the Actions
    cache of a public repository; without the token (a secret) the chat ids stay unreadable."""
    return hmac.new(token.encode(), b"secnews-subscribers", hashlib.sha256).digest() if token else None


try:  # AES-256-GCM for the subscriber file; the workflow installs it from requirements.txt
    from cryptography.exceptions import InvalidTag
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
except ImportError:
    AESGCM = None
SUBSCRIBERS_AAD = b"secnews-subscribers"


def _aes_key(key):
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None,
                info=b"secnews-subscribers aes-256-gcm").derive(key)


def _decrypt_subscribers(data, key):
    """Plaintext of an encrypted subscriber file, or None when this key cannot open it. Version 2
    is AES-256-GCM; the older format (an HMAC keystream) is still read so it can be converted."""
    if data.get("v") == 2:
        if AESGCM is None:
            raise RuntimeError("the subscriber file is AES-encrypted: install requirements.txt")
        try:
            return AESGCM(_aes_key(key)).decrypt(base64.b64decode(data["nonce"]), base64.b64decode(data["ct"]),
                                                 SUBSCRIBERS_AAD)
        except InvalidTag:
            return None
    nonce, ct = base64.b64decode(data["nonce"]), base64.b64decode(data["ct"])
    if not hmac.compare_digest(base64.b64decode(data["mac"]), hmac.new(key, nonce + ct, hashlib.sha256).digest()):
        return None
    return bytes(a ^ b for a, b in zip(ct, _keystream(key, nonce, len(ct))))


def _keystream(key, nonce, length):
    blocks = (hmac.new(key, nonce + i.to_bytes(4, "big"), hashlib.sha256).digest()
              for i in range((length + 31) // 32))
    return b"".join(blocks)[:length]


def masked(chat_id):
    """Chat id for public logs: enough to tell chats apart, not to address them."""
    s = str(chat_id)
    return f"{s[:2]}***{s[-2:]}" if len(s) > 4 else "***"


def load_subscribers(path, key=None):
    empty = {"ids": [], "stopped": [], "last_update": 0, "pending": {}, "denied": [], "former": []}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return empty
    if "ct" in data:
        if not key:
            log("warning: subscriber file is encrypted and no bot token is set")
            return empty
        plain = _decrypt_subscribers(data, key)
        if plain is None:
            log("warning: subscriber file does not match this bot token; starting a new list")
            return empty
        data = json.loads(plain)
    ids, stopped = list(data.get("ids", [])), list(data.get("stopped", []))
    return {"ids": ids, "stopped": stopped, "last_update": data.get("last_update", 0),
            # Approval mode: requests waiting for the admin (id -> name, kept only in this encrypted
            # file), chats the admin turned down, and chats that were ever subscribers (they may
            # come back with /start without asking again).
            "pending": dict(data.get("pending", {})), "denied": list(data.get("denied", [])),
            "former": list(dict.fromkeys(list(data.get("former", [])) + ids + stopped))}


def save_subscribers(path, subs, key=None):
    path.parent.mkdir(parents=True, exist_ok=True)
    raw = json.dumps(subs).encode()
    if key and AESGCM is not None:
        nonce = os.urandom(12)
        ct = AESGCM(_aes_key(key)).encrypt(nonce, raw, SUBSCRIBERS_AAD)
        raw = json.dumps({"v": 2, "nonce": base64.b64encode(nonce).decode(),
                          "ct": base64.b64encode(ct).decode()}).encode()
    elif key:  # without the cryptography package (local runs): the older format
        nonce = os.urandom(16)
        ct = bytes(a ^ b for a, b in zip(raw, _keystream(key, nonce, len(raw))))
        mac = hmac.new(key, nonce + ct, hashlib.sha256).digest()
        raw = json.dumps({k: base64.b64encode(v).decode() for k, v in
                          (("nonce", nonce), ("ct", ct), ("mac", mac))}).encode()
    path.write_bytes(raw)


def _readable_with(path, key):
    """True when the subscriber file exists and this bot token can open it."""
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return False
    if "ct" not in data:
        return not key
    return bool(key) and _decrypt_subscribers(data, key) is not None


def backup_subscribers(path, backup, key=None):
    """Copy the (encrypted) subscriber file to backup when who is subscribed has changed, so a lost
    Actions cache does not lose the list. Returns True when the backup was written. An empty list
    never replaces a backup this token can still read: that looks like a lost cache, not a change."""
    if not path.exists():
        return False
    current = load_subscribers(path, key)
    if _readable_with(backup, key):
        old = load_subscribers(backup, key)
        same_format = (json.loads(backup.read_text(encoding="utf-8")).get("v")
                       == json.loads(path.read_text(encoding="utf-8")).get("v"))
        if same_format and all((sorted(current[f]) if isinstance(current[f], list) else current[f])
                               == (sorted(old[f]) if isinstance(old[f], list) else old[f])
                               for f in ("ids", "stopped", "pending", "denied", "former")):
            return False
        if old["ids"] and not current["ids"]:
            log("warning: subscriber list is empty but the backup is not; keeping the backup")
            return False
    backup.parent.mkdir(parents=True, exist_ok=True)
    backup.write_bytes(path.read_bytes())
    return True


def add_subscribers(path, chat_ids, key=None):
    """Fold ids from feeds.json or the secret into the stored list (people who sent /stop stay out)."""
    subs = load_subscribers(path, key)
    new = [c for c in chat_ids if c not in subs["ids"] and c not in subs["stopped"]]
    if new:
        subs["ids"] += new
        save_subscribers(path, subs, key)
    return new


def _chat_name(chat):
    name = chat.get("title") or " ".join(filter(None, [chat.get("first_name"), chat.get("last_name")]))
    return (name or "?") + (f" (@{chat['username']})" if chat.get("username") else "")


def sync_subscribers(path, updates, send=None, key=None, admin=None, api=None, welcome=TEXTS["welcome"],
                     why=None):
    """Subscribe chats that message the bot and unsubscribe ones that send /stop.

    Without an admin, /start (or the bot being added to a group) subscribes at once, even after an
    earlier /stop, and any other message subscribes chats that never stopped. With an admin, /start
    from a new chat becomes a request: the admin gets ✅/❌ buttons and the answer is applied on a
    later run (former subscribers and the admin themself need no approval; a rejected chat that
    sends /start again becomes a new request). Updates already handled
    are skipped (Telegram keeps about a day of them).

    send(chat_id, text, markup=None) sends a message; api(method, params) answers button presses.
    Returns (added, removed)."""
    subs = load_subscribers(path, key)
    ids, stopped = dict.fromkeys(subs["ids"]), dict.fromkeys(subs["stopped"])
    pending, denied, former = dict(subs["pending"]), dict.fromkeys(subs["denied"]), dict.fromkeys(subs["former"])
    last_seen = subs.get("last_update", 0)
    added, removed, requests, rejected, presses, tests = [], [], [], [], [], []
    stats_asked, questions = False, []
    if updates:
        kinds = [k for u in updates for k in ("message", "callback_query", "my_chat_member") if k in u]
        log(f"telegram updates: {len(updates)} ({', '.join(sorted(set(kinds)))}), "
            f"{sum(1 for u in updates if u.get('update_id', 0) > last_seen)} new")
    for upd in sorted(updates, key=lambda u: u.get("update_id", 0)):
        if upd.get("update_id", 0) <= last_seen:
            continue
        last_seen = upd.get("update_id", last_seen)
        if "callback_query" in upd:
            cq = upd["callback_query"]
            if not admin or str(cq.get("from", {}).get("id")) != admin:
                log("ignored a button press from someone other than the admin")
                continue  # only the admin's buttons count
            verb, _, cid = (cq.get("data") or "").partition(":")
            if verb == "test":
                note = ("🧪 테스트 성공: " + ("✅ 승인" if cid == "ok" else "❌ 거절")
                        + " 버튼 정상 처리 (구독자 목록은 그대로)")
            elif cid in pending and verb in ("ok", "no"):
                name = pending.pop(cid)
                if verb == "ok":
                    stopped.pop(cid, None)
                    denied.pop(cid, None)
                    ids[cid] = None
                    former[cid] = None
                    added.append(cid)
                    note = "✅ 승인 완료"
                else:
                    denied[cid] = None
                    rejected.append(cid)
                    note = "❌ 거절 완료"
            else:
                note = "이미 처리된 신청이에요"
            presses.append((cq, note))
            continue
        if "my_chat_member" in upd:
            m = upd["my_chat_member"]
            chat = m["chat"]
            gone = m.get("new_chat_member", {}).get("status") in ("left", "kicked")
            action = "stop" if gone else "start"
        else:
            msg = upd.get("message") or {}
            chat = msg.get("chat")
            if not chat:
                continue
            text = (msg.get("text") or "").strip().lower()
            action = ("stop" if text.startswith("/stop") else "start" if text.startswith("/start")
                      else "test" if text.startswith("/test")
                      else "stats" if text.startswith("/stats")
                      else "why" if text.startswith("/why") else "chat")
        cid = str(chat["id"])
        if action == "test":
            # The admin rehearses a request: same messages and buttons, nothing stored.
            if admin and cid == admin:
                tests.append(_chat_name(chat))
            continue
        if action == "stats":
            stats_asked = stats_asked or bool(admin and cid == admin)  # others get no answer
            continue
        if action == "why":
            if admin and cid == admin:
                questions.append(re.sub(r"^/why(@\S+)?", "", (msg.get("text") or "").strip()).strip())
            continue
        if action == "stop":
            if cid in ids:
                removed.append(cid)
            ids.pop(cid, None)
            pending.pop(cid, None)
            if not admin or cid in former:
                stopped[cid] = None
        elif cid in ids:
            continue
        elif not admin:
            if action == "start" or cid not in stopped:
                stopped.pop(cid, None)
                ids[cid] = None
                former[cid] = None
                added.append(cid)
        elif cid == admin or (action == "start" and cid in former and cid not in denied):
            stopped.pop(cid, None)
            ids[cid] = None
            former[cid] = None
            added.append(cid)
        elif action == "start" and cid not in pending:
            # A rejected chat may ask again with /start; it always goes back to the admin.
            pending[cid] = _chat_name(chat)
            requests.append(cid)
    save_subscribers(path, {"ids": list(ids), "stopped": list(stopped), "last_update": last_seen,
                            "pending": pending, "denied": list(denied), "former": list(former)}, key)
    added = [c for c in added if c in ids]
    removed = [c for c in removed if c not in ids]
    requests = [c for c in requests if c in pending]
    if requests:
        log(f"subscription requests waiting for the admin: {len(requests)}")
    if send:
        def say(cid, text, markup=None):
            try:
                send(cid, text, markup) if markup else send(cid, text)
            except TelegramError as e:
                log(f"warning: message to {masked(cid)}: {e}")
        for cid in added:
            say(cid, welcome)
        for cid in removed:
            say(cid, GOODBYE)
        for cid in rejected:
            say(cid, REJECTED)
        for name in tests:
            say(admin, "🧪 (테스트) 신청자에게는 이렇게 가요:\n" + REQUESTED)
            say(admin, f"🔔 <b>새 구독 신청</b> (테스트)\n이름: {html.escape(name)}\nID: <code>{admin}</code>"
                       f"\n\n{APPROVE_HINT}",
                {"inline_keyboard": [[{"text": "✅ 승인", "callback_data": "test:ok"},
                                      {"text": "❌ 거절", "callback_data": "test:no"}]]})
        if stats_asked:
            say(admin, f"📊 <b>구독 현황</b> ({datetime.now(KST):%m/%d %H:%M})\n"
                       f"· 구독 중: {sum(1 for c in ids if c not in stopped)}명\n"
                       f"· 승인 대기: {len(pending)}명\n· 해지: {len(stopped)}명\n· 거절: {len(denied)}명"
                       + ("\n" + "\n".join(GEMINI_BUDGET.summary()) if GEMINI_BUDGET else ""))
        for q in questions:
            say(admin, why(q) if why else "이 기능을 쓸 수 없어요.")
        for cid in requests:
            say(cid, REQUESTED)
            say(admin, f"🔔 <b>새 구독 신청</b>\n이름: {html.escape(pending[cid])}\nID: <code>{cid}</code>"
                       f"\n\n{APPROVE_HINT}",
                {"inline_keyboard": [[{"text": "✅ 승인", "callback_data": f"ok:{cid}"},
                                      {"text": "❌ 거절", "callback_data": f"no:{cid}"}]]})
    stamp = datetime.now(KST).strftime("%H:%M")
    # Several taps on the same message (the result only shows minutes later) count once.
    once, unique = set(), []
    for cq, note in presses:
        mid = (cq.get("message") or {}).get("message_id") or cq.get("id")
        if mid not in once:
            once.add(mid)
            unique.append((cq, note))
    presses = unique
    if presses:
        log(f"handling {len(presses)} admin button press(es)")
    for cq, note in presses:
        # The result goes into the request message itself (buttons replaced by "✅ 승인 완료 (11:40)").
        # The press is only seen on the next run, so Telegram's own button answer usually comes too
        # late; that is harmless, and the change is applied either way.
        msg = cq.get("message") or {}
        edited = False
        if api:
            try:
                api("answerCallbackQuery", {"callback_query_id": cq["id"], "text": note})
            except (TelegramError, OSError):
                pass  # expected: the press is usually minutes old by now
            if msg.get("message_id"):
                try:
                    text = msg.get("text", "").replace(APPROVE_HINT, "").rstrip()
                    api("editMessageText", {"chat_id": msg["chat"]["id"], "message_id": msg["message_id"],
                                            "text": f"{text}\n\n{note} ({stamp})"})
                    edited = True
                except (TelegramError, OSError) as e:
                    if "not modified" in str(e):
                        edited = True  # already shows this result
                    else:
                        log(f"warning: could not update the request message: {e}")
        if send and not edited:
            try:
                send(admin, f"{note} ({stamp})")
            except TelegramError:
                pass
    return added, removed


def mark_gone(path, chat_ids, key=None):
    """Stop sending to chats that blocked the bot or no longer exist."""
    if not chat_ids:
        return
    subs = load_subscribers(path, key)
    subs["ids"] = [c for c in subs["ids"] if c not in chat_ids]
    subs["stopped"] = list(dict.fromkeys(subs["stopped"] + list(chat_ids)))
    save_subscribers(path, subs, key)


# --------------------------------------------------------------------- main

def feed_label(feed, n):
    """Actions logs of a public repository are public: there a feed shows as its number only,
    so the list of sources (kept in a private settings repo) does not leak through the logs."""
    return f"source {n + 1}" if os.environ.get("GITHUB_ACTIONS") else feed["name"]


def blocked_outlet(item, blocked):
    """Outlets the config chose to drop, matched by name or by the link's domain."""
    where = (item.get("source", "") + " " + urllib.parse.urlsplit(item.get("link") or "").netloc).lower()
    return any(b in where for b in blocked)


def collect(config, fetcher=fetch, failed=None, counts=None):
    items = []
    blocked = [b.strip().lower() for b in config.get("blocked_outlets", []) if b.strip()]
    for n, feed in enumerate(config["feeds"]):
        try:
            raw = fetcher(feed["url"])
            kind = feed.get("type", "rss")
            parser = {"rss": parse_feed, "cisa_kev": parse_kev}.get(kind) or PARSERS[kind]
            got = [it for it in parser(raw, feed["name"]) if not blocked_outlet(it, blocked)]
            for it in got:
                it["title"] = strip_outlet(it["title"], it.get("source", ""))
                it["security_only"] = feed.get("security_only", False)
                it["min_score"] = feed.get("min_score")
                it["focus_only"] = feed.get("focus_only", False)
                it["instant_all"] = feed.get("instant") == "all"
                it["instant_always"] = feed.get("instant") == "always"
            log(f"{feed_label(feed, n)}: {len(got)} items")
            if counts is not None:
                counts[str(n)] = len(got)
            items.extend(got)
        except Exception as e:  # one broken feed must not stop the others
            log(f"warning: {feed_label(feed, n)} failed: {e}")
            if failed is not None:
                failed.append(feed["name"])
    return items


CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.I)


def _bigrams(text):
    text = re.sub(r"[\W_]+", "", text.lower())
    return {text[i:i + 2] for i in range(len(text) - 1)}


def similar(a, b, threshold=0.45):
    """Same story from different outlets: share most character pairs of the shorter headline."""
    a, b = _bigrams(a), _bigrams(b)
    return bool(a and b) and len(a & b) / min(len(a), len(b)) >= threshold


def item_cves(item):
    return {c.upper() for c in CVE_RE.findall(f"{item['title']} {item.get('summary', '')}")}


def mark_forced(item, always):
    """Items the admin always wants as alerts: from a feed marked "instant": "always", or naming
    one of keywords.always_urgent. Only duplicates keep them out."""
    text = f"{item['title']} {item.get('summary', '')}".lower()
    item["forced"] = bool(item.get("instant_always") or any(r.search(text) for r in always))
    return item["forced"]


def told_line(record):
    """A sent story as Gemini sees it: the headline as it went out, plus the English story
    line when there is one, so a Korean follow-up can be matched against either."""
    title, story = record[0], (record[3] if len(record) > 3 else "")
    return f"{title} ({story})" if story else title


def already_told(item, recent, sent_cves):
    """A story sent in an earlier digest, now from another outlet (or the KEV entry for it):
    every CVE it names went out already, or its headline matches one that did."""
    cves = item_cves(item)
    if cves and cves <= sent_cves:
        return True
    return any(similar(item["title"], r[0]) for r in recent)


# A large-scale incident in the headline: "371만건", "2만 7천 개 서버", "3.7 million records", "27,000 servers".
SCALE = re.compile(r"\d[\d,.]*\s*(만|억)\s*(\d[\d,.]*\s*천\s*)?(건|명|개|대|곳|명분)|"
                   r"\b\d[\d,.]*\s*(million|billion)\b|"
                   r"\b\d{1,3}(,\d{3})+\s+(servers|devices|systems|hosts|sites|websites|customers|users|records|accounts)\b",
                   re.I)
EXPLOIT_WORDS = re.compile(r"zero-day|0-day|zeroday|exploit|제로데이|악용", re.I)


def kev_covered(item, titles):
    """A KEV entry whose vendor appears in a news headline about an exploited hole (the
    catalog adding "BeyondTrust ..." the day "BeyondTrust patches zero-day exploited in
    attacks" ran): the article says more, so the KEV entry is the one dropped."""
    vendor = item.get("vendor", "").strip().lower()
    if not item["id"].startswith("kev:") or len(vendor) < 3:
        return False
    return any(vendor in t.lower() and EXPLOIT_WORDS.search(t) for t in titles)


STORY_FILLER = {"a", "an", "the", "of", "in", "on", "to", "for", "and", "by", "with", "from", "after", "new",
                "flaw", "flaws", "bug", "vulnerability", "vulnerabilities", "patch", "patched", "patches",
                "fix", "fixed", "critical", "attack", "attacks", "data", "breach", "leak", "hack", "hacked",
                "exploited", "exploit", "zero-day", "rce", "remote", "code", "execution", "severity", "max",
                "maximum", "actively", "wild", "cvss"}


def same_story(a, b):
    """Gemini's story lines name the same thing: every telling word of the shorter one (vendor,
    product, victim) appears in the other. "fortinet fortiweb rce" and "fortinet fortios rce" differ."""
    words = [set(w for w in re.findall(r"[a-z0-9.\-]+", (x.get("story") or "").lower()) if w not in STORY_FILLER)
             for x in (a, b)]
    short, other = sorted(words, key=len)
    return len(short) >= 2 and short <= other


def trim(items, max_items, max_per_source=0):
    """Drop stories about a CVE already covered by a higher-ranked item, keep at most
    max_per_source items from any one source so a busy channel cannot fill the digest,
    then cap the count. Items are expected best-first; whatever is dropped is still marked as seen."""
    kept, covered, per_source = [], set(), {}
    for item in items:
        cves = item_cves(item)  # summaries name the CVE when the headline only says "PHP flaw"
        if cves and cves <= covered:
            continue
        if max_per_source and per_source.get(item.get("source"), 0) >= max_per_source:
            continue
        if any(similar(item["title"], k["title"]) or same_story(item, k) for k in kept):
            continue
        covered |= cves
        per_source[item.get("source")] = per_source.get(item.get("source"), 0) + 1
        kept.append(item)
    return kept[:max_items] if max_items else kept


def quiet(config, now):
    """Inside "quiet_hours" [start, end) in Korean time, e.g. [22, 6]: no regular digests."""
    hours = config.get("quiet_hours")
    if not hours:
        return False
    start, end = hours
    h = now.astimezone(KST).hour
    return (start <= h or h < end) if start > end else start <= h < end


def night_notice(config, state, state_path, sender, now):
    """With "night_notice": true, tell everyone once, at the first run of the quiet hours' first
    hour, that regular digests pause until the morning round-up."""
    hours = config.get("quiet_hours")
    local = now.astimezone(KST)
    if not (config.get("night_notice") and hours and state is not None and local.hour == hours[0]):
        return
    if state.get("night_notice") == f"{local:%Y-%m-%d}":
        return
    end = hours[1]
    text = wording(config, "night").replace("{until}", f"{(end - 1) % 24:02d}").replace("{morning}", f"{end:02d}")
    if not sender(text, silent=True):
        log("warning: the night notice was not delivered")
        return
    state["night_notice"] = f"{local:%Y-%m-%d}"
    stored = dict(load_state(state_path) or state, night_notice=state["night_notice"])
    state_path.write_text(json.dumps(stored, ensure_ascii=False), encoding="utf-8")
    log("night notice sent")


def morning(config, now):
    """The first hour after quiet hours: the overnight round-up."""
    hours = config.get("quiet_hours")
    return bool(hours) and now.astimezone(KST).hour == hours[1]


def due(state, config, now):
    """True when a digest should go out now. The timer wakes the script often; with
    "digest_on_the_hour" the first run of each new clock hour sends, otherwise the first run
    after digest_interval_minutes. Nothing is due during quiet hours."""
    if quiet(config, now):
        return False
    last = (state or {}).get("last_digest")
    if last is None:
        return True
    if config.get("digest_on_the_hour"):
        return int(now.timestamp() // 3600) > int(last // 3600)
    interval = config.get("digest_interval_minutes", 0)
    # A minute of slack so a 15-minute timer lands on 90 minutes, not 105.
    return not interval or now.timestamp() - last >= interval * 60 - 60


def next_digest_minutes(state, config, now):
    if config.get("digest_on_the_hour"):
        return 60 - now.minute
    return config.get("digest_interval_minutes", 0) - (now.timestamp() - state["last_digest"]) / 60


FEED_ALERT_AFTER = 3  # digests in a row a feed may fail before the owner hears about it


def run(config, state_path, sender, now=None, fetcher=fetch, bootstrap_send=False, translate=None, force=False,
        classify=None, alert=None, prejudge=False):
    """Collect, filter and send. Returns the list of sent items.

    sender(text) must return True when at least one chat received the text."""
    now = now or datetime.now(timezone.utc)
    state = load_state(state_path)
    hour = f"{now.astimezone(KST):%Y-%m-%d %H}"
    # This hour's digest was given up for an unavailable Gemini: its news waits for the next one.
    gave_up = (state or {}).get("deferred_hour") == hour and (state or {}).get("deferred_tries", 0) >= 2
    if not force and (gave_up or not due(state, config, now)):
        # Half past the hour: Gemini judges what is in so far, so the digest on the hour only asks about
        # the last half hour's news (Gemini is often overloaded right on the hour, US/EU working time).
        upcoming = f"{(now + timedelta(minutes=30)).astimezone(KST):%Y-%m-%d %H}"
        if (classify is not None and hasattr(classify, "cache") and state is not None
                and config.get("prejudge", True) and 30 <= now.astimezone(KST).minute < 35
                and not quiet(config, now + timedelta(minutes=30))
                and (state.get("prejudged") or {}).get("for") != upcoming):
            run(config, state_path, sender, now, fetcher, translate=translate, force=True, classify=classify,
                prejudge=upcoming)
            state = load_state(state_path)
        if quiet(config, now):
            log(f"quiet hours: next digest at {config['quiet_hours'][1]:02d}:00 KST")
            night_notice(config, state, state_path, sender, now)
        else:
            log(f"next digest in about {next_digest_minutes(state, config, now):.0f} minutes")
        if config.get("instant_alerts", True):
            return run_instant(config, state, state_path, sender, now, fetcher, translate, classify)
        return []
    first_run = state is None
    seen = (state or {}).get("seen", {})
    scorer = Scorer(config.get("keywords", {}))
    fallback = config.get("fallback_sectors", {})
    tagger = SectorTagger(config.get("sectors", {}), fallback=fallback)
    focus_tagger = SectorTagger(config.get("focus_sectors", {}), key="focus_sectors")
    max_age = timedelta(hours=config.get("max_age_hours", 48))
    min_score = config.get("min_score", 0)

    # Stories already sent in the last max_age_hours: [title, [CVEs], timestamp, story, sent as urgent].
    recent = [r for r in (state or {}).get("recent", []) if now.timestamp() - r[2] <= max_age.total_seconds()]
    sent_cves = {c for r in recent for c in r[1]}

    fresh, keys, fresh_titles, failed, counts = [], set(), [], [], {}
    always = [_keyword_re(k) for k in config.get("keywords", {}).get("always_urgent", [])]
    decisions = dict((state or {}).get("decisions", {}))
    ts = now.timestamp()

    reviewed = {}

    def decide(item, reason):
        """Remember for /why what became of an item (by link, else by title), and for the weekly
        review file: reason, title, source, whether it is a focus story, and its first category."""
        key = item.get("link") or title_key(item)
        decisions[key] = [reason, ts, item["title"][:120]]
        if reason not in ("old", "first_run"):
            tags = item.get("focus_sectors" if item.get("focus") else "sectors") or [""]
            reviewed[key] = [reason, item["title"][:120], item.get("source", ""), bool(item.get("focus")), tags[0]]

    for item in collect(config, fetcher, failed, counts):
        if item["date"] and item["date"] > now + timedelta(hours=1):
            # Some Korean feeds stamp Korean time as GMT, which puts their articles 9 hours ahead.
            item["date"] = min(item["date"] - timedelta(hours=9), now)
        if item["date"] and now - item["date"] > max_age:
            if not item["id"].startswith("kev:") and (item.get("link") or title_key(item)) not in decisions:
                decide(item, "old")  # the KEV catalog is mostly old entries; not worth remembering
            continue
        key, tkey = item_key(item), title_key(item)
        if key in seen or key in keys or tkey in seen or tkey in keys:
            continue
        keys.update((key, tkey))
        scorer.classify(item)
        if mark_forced(item, always):
            item["score"] = max(item["score"], 3)
        tagger.tag(item)
        if item["focus"]:
            focus_tagger.tag(item)
        fresh.append((key, item))
        fresh_titles.append(tkey)

    # Topic feeds and social channels carry much else; keep only security ones.
    news = []
    for it in (it for _, it in fresh if not it.get("ransomware")):
        if it.get("forced"):
            if already_told(it, recent, sent_cves):
                decide(it, "told")
            else:
                news.append(it)
        elif it["score"] < (it.get("min_score") or min_score):
            decide(it, "score")
        # A focus story with its own security angle (focus_security words) counts as security news.
        elif it["security_only"] and not it["security_hits"] and not (it.get("focus") and it.get("focus_security")):
            decide(it, "nosec")
        elif it.get("focus_only") and not it.get("focus"):
            decide(it, "focus_only")
        elif it.get("focus") and not it.get("focus_security", True):
            decide(it, "focus_nosec")
        elif already_told(it, recent, sent_cves):
            decide(it, "told")
        else:
            news.append(it)
    titles = [it["title"] for it in news if not it["id"].startswith("kev:")] + [r[0] for r in recent]
    for it in [it for it in news if kev_covered(it, titles)]:
        decide(it, "kev")
        news.remove(it)
    news.sort(key=lambda it: (-it["score"], -(it["date"] or now).timestamp()))
    passed = len(news)
    held = []  # items Gemini could not judge in a digest that goes out anyway: kept for the next one
    if classify and news:
        pre = (state or {}).get("prejudged") or {}
        if hasattr(classify, "cache") and not prejudge and pre.get("for") == hour:
            classify.cache = pre.get("items") or {}
        # Gemini also spots stories sent in an earlier digest, across languages.
        kept = classify(news, [told_line(r) for r in recent])
        if prejudge:
            stored = dict(load_state(state_path) or state or {},
                          prejudged={"for": prejudge, "items": dict(getattr(classify, "results", {}))})
            state_path.write_text(json.dumps(stored, ensure_ascii=False), encoding="utf-8")
            log(f"pre-judged {len(stored['prejudged']['items'])} item(s) for the {prejudge[-2:]}:00 digest")
            return []
        # Gemini unavailable (overloaded, timing out): nothing goes out on keyword judgement alone.
        # The digest tries once more five minutes later; if that fails too, this hour is skipped
        # and its news, still unsent, goes out with the next hour's digest. The admin hears why.
        judged_any = any(not it.get("keyword_only") for it in kept)
        tries = ((state or {}).get("deferred_tries", 0) + 1 if (state or {}).get("deferred_hour") == hour else 1)
        if getattr(classify, "failed", False) and not force and tries >= 2 and judged_any:
            # Second failure, but the half-past run judged part of the news: that part goes out now,
            # the rest (never judged) waits for the next digest.
            held = [it for it in kept if it.get("keyword_only")]
            kept = [it for it in kept if not it.get("keyword_only")]
            log(f"warning: Gemini is unavailable; sending {len(kept)} pre-judged item(s), holding {len(held)}")
            if alert:
                alert(f"⏳ {now.astimezone(KST).hour}시 정기 발송: AI 응답이 늦어 미리 판단해 둔 기사만 보내고, "
                      f"나머지 {len(held)}건은 다음 정기 발송에 함께 보내요.")
        elif getattr(classify, "failed", False) and not force:
            log(f"warning: Gemini is unavailable; digest attempt {tries} put off")
            stored = dict(load_state(state_path) or state or {}, deferred_hour=hour, deferred_tries=tries)
            state_path.parent.mkdir(parents=True, exist_ok=True)
            state_path.write_text(json.dumps(stored, ensure_ascii=False), encoding="utf-8")
            if alert:
                h = now.astimezone(KST).hour
                alert(f"⏳ {h}시 정기 발송: AI 응답이 늦어 5분 뒤 한 번 더 시도해요." if tries == 1 else
                      f"⏳ {h}시 정기 발송: AI가 계속 응답하지 않아 이번 기사는 다음 정기 발송에 함께 보내요.")
            return []
        for it in news:
            if it not in kept and it not in held:
                decide(it, it.get("drop_reason", "gemini_irrelevant"))
        news = sorted(kept, key=lambda it: (-it["score"], -(it["date"] or now).timestamp()))
    # The 06:00 round-up carries the whole night, so its caps are larger.
    factor = config.get("morning_cap_factor", 1.5) if morning(config, now) and not force else 1
    suffix = " · 🌅 밤사이 모음" if factor != 1 else ""

    def capped(name):
        return int(config.get(name, 0) * factor)

    digests = [(wording(config, title) + suffix, trim([it for it in news if bool(it.get("focus")) == focus],
                                                   capped(cap), config.get("max_per_source", 0)), categories)
               for focus, title, cap, categories in DIGESTS]
    leaks = []
    for it in (it for _, it in fresh if it.get("ransomware")):
        if ransomware_wanted(it, config):
            leaks.append(it)
        else:
            decide(it, "rw_filtered")
    leaks.sort(key=lambda it: (it["country"] not in config.get("ransomware_countries", ["KR"]),
                               -(it["date"] or now).timestamp()))
    digests.append((wording(config, "ransomware_title") + suffix, leaks[:capped("max_ransomware_per_run") or None],
                    "sectors"))

    if first_run and not bootstrap_send:
        log(f"first run: marking {len(fresh)} current items as seen without sending")
        digests = []
        for _, it in fresh:
            decide(it, "first_run")

    sent = []
    # The round's funnel under its last message: how much came in and how much made it through.
    going = [items for _, items, _ in digests if items]
    footer = ""
    if going and config.get("digest_footer", True):
        footer = f"\n\n📊 새 기사 {len(fresh)}건 중 {sum(len(i) for i in going)}건 통과"
    for title, items, categories in digests:
        if not items:
            continue
        localize(items, translate)
        extra = list(fallback) if categories == "sectors" else []
        msgs = build_messages(items, now, title, sector_order=list(config.get(categories, {})) + extra,
                              key=categories, last=extra, icons=icons(config))
        if items is going[-1]:
            msgs[-1] += footer
        for msg in msgs:
            if not sender(msg):
                # Keep state untouched so the same items are retried next run.
                raise TelegramError("message was not delivered to any chat")
        sent += items
    log(f"sent {len(sent)} of {len(fresh)} new items")
    for it in news + leaks:
        decide(it, "sent" if it in sent else "cap")
    # feeds.json "no_news_notice": "all" (silent message to everyone), "admin", or "off" (default).
    notice = config.get("no_news_notice", "off")
    if not sent and digests and notice != "off":
        text = wording(config, "no_news").replace("{time}", f"{now.astimezone(KST):%H:%M}")
        if notice == "admin":
            if alert:
                alert(f"📭 {now.astimezone(KST):%H}시 정기 발송: 새 기사 {len(fresh)}건 중 보낼 기사 없음")
        elif not sender(text, silent=True):
            log("warning: the no-news notice was not delivered")

    holding = {item_key(it) for it in held} | {title_key(it) for it in held}
    for key, _ in fresh:
        if key not in holding:
            seen[key] = ts
    for tkey in fresh_titles:
        if tkey not in holding:
            seen[tkey] = ts
    recent += [[it["title"], sorted(item_cves(it)), ts, it.get("story", ""), it["score"] >= 3] for it in sent]

    # A feed that keeps failing has probably moved or changed format; say so once.
    failures = {n: c + 1 for n, c in (state or {}).get("feed_failures", {}).items() if n in failed}
    failures.update({n: 1 for n in failed if n not in failures})
    broken = [n for n, c in failures.items() if c == FEED_ALERT_AFTER]
    if broken and alert:
        alert("⚠️ 보안 속보 봇: 다음 출처가 " + f"{FEED_ALERT_AFTER}번 연속 실패했어요 (주소 변경 가능성)\n"
              + "\n".join(f"· {html.escape(n)}" for n in broken))

    # Weekly numbers for the admin's Monday report.
    stats = dict((state or {}).get("stats") or {"since": ts})
    stats["runs"] = stats.get("runs", 0) + 1
    stats["collected"] = stats.get("collected", 0) + len(fresh)
    stats["passed"] = stats.get("passed", 0) + passed
    stats["sent"] = stats.get("sent", 0) + len(sent)
    ai_dropped = [d[2] for d in decisions.values() if d[1] == ts and d[0] == "gemini_irrelevant"]
    stats["ai_dropped"] = stats.get("ai_dropped", 0) + len(ai_dropped)
    stats["ai_examples"] = (stats.get("ai_examples", []) + ai_dropped)[-15:]
    feeds = dict(stats.get("feeds", {}))
    for n in range(len(config["feeds"])):
        feeds[str(n)] = feeds.get(str(n), 0) + counts.get(str(n), 0)
    stats["feeds"] = feeds
    stats["review"] = dict(list({**stats.get("review", {}), **reviewed}.items())[-REVIEW_LIMIT:])
    report_week = (state or {}).get("report_week")
    local = now.astimezone(KST)
    week = f"{local:%G-W%V}"
    if local.weekday() == 0 and local.hour >= 9 and report_week != week and not first_run:
        if alert:
            alert(weekly_report(config, stats, now))
        write_review(state_path.parent / "reviews", stats, now)
        stats, report_week = {"since": ts}, week
    save_state(state_path, seen, now, recent, failures, instant_checked=(state or {}).get("instant_checked"),
               decisions=decisions, stats=stats, report_week=report_week)
    return sent


REASONS = {
    "sent": "✅ 발송했어요.",
    "cap": "칸별 발송 상한을 넘었거나, 비슷한 제목의 기사가 먼저 나가서 뺐어요.",
    "score": "키워드 점수가 낮아서 뺐어요 (보안 단어가 없거나 약해요).",
    "nosec": "보안 글만 받는 출처인데 보안 키워드가 없어서 뺐어요.",
    "focus_only": "군 기사만 받는 출처인데 군 기사가 아니라서 뺐어요.",
    "focus_nosec": "군 기사지만 보안 내용이 없어서 뺐어요.",
    "told": "이미 보낸 사건과 같은 기사라서 뺐어요.",
    "kev": "같은 취약점을 다룬 뉴스 기사가 있어서 KEV 항목을 뺐어요.",
    "gemini_irrelevant": "AI(Gemini)가 보안과 무관하다고 판단해서 뺐어요.",
    "gemini_dup": "AI(Gemini)가 다른 기사나 이미 보낸 사건과 같은 내용으로 판단해서 뺐어요.",
    "gemini_limit": "새 기사가 많아 AI 판단 한도(1회 90건) 밖으로 밀려서 뺐어요 (키워드 점수 하위).",
    "gemini_focus_only": "군 기사만 받는 출처인데 AI(Gemini)가 군 기사가 아니라고 판단했어요.",
    "rw_filtered": "감시 대상(한국·주요 업종·군 관련)이 아닌 랜섬웨어 피해라서 뺐어요.",
    "old": "48시간보다 오래된 기사라서 뺐어요.",
    "first_run": "봇을 처음 켤 때 이미 있던 기사라서 기록만 했어요.",
}


def explain(state, query):
    """Answer for the admin's /why: what happened to an article, found by link or title words."""
    query = query.strip()
    if not query:
        return "사용법: /why 기사링크  또는  /why 제목 일부"
    decisions = (state or {}).get("decisions", {})

    def norm(url):
        return re.sub(r"^https?://(www\.)?", "", url.split("#")[0].split("?")[0]).rstrip("/").lower()

    if re.match(r"https?://", query):
        hits = [(k, d) for k, d in decisions.items() if norm(k) == norm(query)]
    else:
        hits = [(k, d) for k, d in decisions.items() if query.lower() in d[2].lower()][-3:]
    if not hits:
        return ("🔍 최근 3일 안에 우리 출처에서 수집한 기록이 없어요.\n"
                "출처에 없는 매체이거나, 3일보다 오래된 기사일 수 있어요. 구글뉴스 기사는 링크가 달라서 "
                "제목 일부로 다시 물어보세요: /why 제목일부")
    lines = ["🔍 <b>기사 처리 결과</b>"]
    for _, (reason, when, title) in hits:
        lines.append(f"\n· {html.escape(title)}\n  {datetime.fromtimestamp(when, KST):%m/%d %H:%M} 수집 · "
                     + REASONS.get(reason, reason))
    return "\n".join(lines)


REVIEW_LIMIT = 6000


def write_review(folder, stats, now, name=None):
    """The week's decisions as a file the workflow commits to the private settings repo, where the
    weekly review reads them. Feeds appear by number, as in the logs; the settings name them."""
    local = now.astimezone(KST)
    body = {"since": datetime.fromtimestamp(stats.get("since", now.timestamp()), KST).isoformat(),
            "until": local.isoformat(),
            "numbers": {k: stats.get(k, 0) for k in ("runs", "collected", "passed", "ai_dropped", "sent")},
            "items_per_feed": stats.get("feeds", {}),
            "gemini": ({"caps": dict(GEMINI_BUDGET.models), "requests_by_day": GEMINI_BUDGET.history}
                       if GEMINI_BUDGET else None),
            "fields": ["reason", "title", "source", "focus", "category"],
            "items": list(stats.get("review", {}).values()),
            **({"sent_links": stats["links"]} if "links" in stats else {})}
    folder.mkdir(parents=True, exist_ok=True)
    (folder / (name or f"{local:%G-W%V}.json")).write_text(json.dumps(body, ensure_ascii=False, indent=1), encoding="utf-8")


def weekly_report(config, stats, now):
    since = datetime.fromtimestamp(stats.get("since", now.timestamp()), KST)
    quiet_feeds = [f["name"] for n, f in enumerate(config["feeds"]) if not stats.get("feeds", {}).get(str(n))]
    lines = [f"📊 <b>주간 리포트</b> ({since:%m/%d} ~ {now.astimezone(KST):%m/%d})",
             f"· 정기 발송 {stats.get('runs', 0)}회, 새 기사 {stats.get('collected', 0)}건 수집",
             f"· 키워드 통과 {stats.get('passed', 0)}건 → AI 제외 {stats.get('ai_dropped', 0)}건 → "
             f"발송 {stats.get('sent', 0)}건",
             "· 기간 내내 0건인 출처: " + (", ".join(html.escape(n) for n in quiet_feeds) or "없음")]
    if GEMINI_BUDGET:
        lines += GEMINI_BUDGET.summary(days=7)
    if stats.get("ai_examples"):
        lines.append("· AI가 무관하다고 뺀 기사 (놓친 게 있으면 키워드·기준을 고쳐요):")
        lines += [f"  - {html.escape(t)}" for t in stats["ai_examples"][-10:]]
    return "\n".join(lines)




def run_instant(config, state, state_path, sender, now, fetcher=fetch, translate=None, classify=None):
    """Between digests: check the fast feeds ("instant": true) for new items with a strong urgent
    signal (keywords.instant, or a new KEV entry), let Gemini confirm when it is available, and
    send the urgent ones at once. During quiet hours they go out without a notification sound.
    Items that are not urgent stay unseen and wait for the next digest."""
    feeds = [f for f in config["feeds"] if f.get("instant")]
    if not feeds or state is None:
        return []
    seen = state.get("seen", {})
    checked = state.get("instant_checked")
    first = checked is None
    checked = dict(checked or {})
    max_age = timedelta(hours=config.get("max_age_hours", 48))
    recent = [r for r in state.get("recent", []) if now.timestamp() - r[2] <= max_age.total_seconds()]
    # Only stories already sent as urgent block an alert: one that went out in a digest as ordinary
    # news (say, a patch announced for next week) still gets its alert once it turns into a zero-day.
    urgent_told = [r for r in recent if len(r) > 4 and r[4]]
    sent_cves = {c for r in urgent_told for c in r[1]}
    scorer = Scorer(config.get("keywords", {}))
    fallback = config.get("fallback_sectors", {})
    tagger = SectorTagger(config.get("sectors", {}), fallback=fallback)
    focus_tagger = SectorTagger(config.get("focus_sectors", {}), key="focus_sectors")
    strong = [_keyword_re(k) for k in config.get("keywords", {}).get("instant", [])]
    always = [_keyword_re(k) for k in config.get("keywords", {}).get("always_urgent", [])]
    window = timedelta(minutes=config.get("instant_max_age_minutes", 180))
    ts = now.timestamp()

    candidates = []
    for item in collect(dict(config, feeds=feeds), fetcher):
        if item["date"] and item["date"] > now + timedelta(hours=1):
            item["date"] = min(item["date"] - timedelta(hours=9), now)
        # Forced items come through search feeds that lag, so they get a day instead of three hours.
        forced = mark_forced(item, always)
        if not item["date"] or now - item["date"] > (timedelta(hours=24) if forced else window):
            continue
        key, tkey = item_key(item), title_key(item)
        # Judged once; a miss waits for the digest. An item that became forced after an earlier
        # look (the always-urgent list grew) gets one more look under its own mark.
        mark = "!" + key if forced else key
        if key in seen or tkey in seen or mark in checked:
            continue
        checked[mark] = ts
        scorer.classify(item)
        text = f"{item['title']} {item.get('summary', '')}".lower()
        # A critical word in the headline (RCE, unauthenticated, CVSS 9…) is enough to ask Gemini,
        # which applies the strict urgent rules. So is a breach or attack of large scale ("371만 건
        # 유출", "27,000 servers infected"). A feed marked "instant": "all" (a narrow topic search)
        # has every new security item asked about; forced items always go, unless duplicates.
        signal = (item["id"].startswith("kev:") or any(r.search(text) for r in strong)
                  or any(r.search(item["title"].lower()) for r in scorer.critical)
                  or bool(item["security_hits"] and classify and SCALE.search(item["title"])))
        if forced:
            signal = True
            item["score"] = max(item["score"], 3)
        elif item.get("instant_all") and classify:
            signal = item["focus_security"] or item["security_hits"]
        elif item["score"] < 3 and not (classify and signal and SCALE.search(item["title"])):
            signal = False
        if first or not signal or already_told(item, urgent_told, sent_cves):
            continue
        tagger.tag(item)
        if item["focus"]:
            focus_tagger.tag(item)
        candidates.append((key, tkey, item))

    sent, extra = [], {}
    if first:
        log("instant alerts: first check; current items recorded, nothing sent")
    elif candidates:
        items = [it for _, _, it in candidates]
        titles = [it["title"] for it in items if not it["id"].startswith("kev:")] + [r[0] for r in urgent_told]
        items = [it for it in items if not kev_covered(it, titles)]
        if classify and items:
            # Alerts are few and read at once: Flash judges and translates them (the owner's call).
            items = classify(items, [told_line(r) for r in urgent_told])
            if getattr(classify, "failed", False):
                # No alert on keywords alone; only the always-urgent ones go. The rest wait for the digest.
                items = [it for it in items if it.get("forced")]
        urgent = trim(sorted([it for it in items if it["score"] >= 3], key=lambda it: -it["score"]),
                      config.get("max_instant_per_run", 5))
        if urgent:
            localize(urgent, translate)
            hush = quiet(config, now)
            # One alert message for both kinds: a focus story shows under its focus category.
            for it in urgent:
                if it.get("focus") and it.get("focus_sectors"):
                    it["sectors"] = it["focus_sectors"]
            for msg in build_messages(urgent, now, wording(config, "instant_title"),
                                      sector_order=list(dict.fromkeys(list(config.get("focus_sectors", {}))
                                                                      + list(config.get("sectors", {})) + list(fallback))),
                                      key="sectors", last=list(fallback), icons=icons(config)):
                if not sender(msg, silent=hush):
                    raise TelegramError("message was not delivered to any chat")
            sent = urgent
            for key, tkey, it in candidates:
                if it in urgent:
                    seen[key] = seen[tkey] = ts
            recent += [[it["title"], sorted(item_cves(it)), ts, it.get("story", ""), True] for it in urgent]
            decisions = dict(state.get("decisions", {}))
            for it in urgent:
                decisions[it.get("link") or title_key(it)] = ["sent", ts, it["title"][:120]]
            extra["decisions"] = decisions
        dropped = sum(1 for _, _, it in candidates if it.get("drop_reason"))
        log(f"instant alerts: {len(candidates)} candidate(s), sent {len(sent)}, {dropped} dropped by Gemini"
            + (" quietly" if sent and quiet(config, now) else ""))
    checked = {k: t for k, t in checked.items() if ts - t <= 2 * 86400}
    save_state(state_path, seen, now, recent, state.get("feed_failures", {}),
               last_digest=state.get("last_digest"), instant_checked=checked, **extra)
    return sent


def test_send(config, state_path, token, chats, translator):
    """Send the current news to the given chats only, as a first run would, and leave
    the real state and subscriber list alone: what subscribers get next hour is unchanged."""
    import tempfile
    log(f"test mode: sending only to {len(chats)} chat(s); nothing is saved")

    def sender(text, silent=False):
        delivered = 0
        for chat in chats:
            try:
                telegram_send(token, chat, text, silent=silent)
                delivered += 1
            except TelegramError as e:
                log(f"warning: chat {masked(chat)}: {e}")
        return delivered > 0

    # A test shows the last hour only, like one digest: more news took minutes and held up the timer runs.
    config = dict(config, max_age_hours=min(config.get("max_age_hours", 48), 1))
    with tempfile.TemporaryDirectory() as d:
        try:
            run(config, Path(d) / "seen.json", sender, bootstrap_send=True, translate=translator, force=True,
                classify=make_classifier(config))
        except TelegramError as e:
            log(f"error: {e}")
            return 1
    return 0


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--dry-run", action="store_true", help="print messages instead of sending; state is not saved")
    ap.add_argument("--reset", action="store_true",
                    help="forget what was already sent and send the current news again")
    ap.add_argument("--now", action="store_true",
                    help="send a digest now even if digest_interval_minutes has not passed")
    ap.add_argument("--quiet-first-run", action="store_true",
                    help="when no state file exists, record current items without sending them")
    # SECNEWS_CONFIG points at the settings checked out from the private repository, when there is one.
    ap.add_argument("--config", type=Path, default=Path(os.environ.get("SECNEWS_CONFIG") or CONFIG_PATH))
    ap.add_argument("--backup-subscribers", type=Path, metavar="FILE",
                    help="copy the encrypted subscriber list to FILE if it changed; prints changed/unchanged")
    ap.add_argument("--write-review", action="store_true",
                    help="write this week's decisions so far for review (nothing is sent or changed)")
    args = ap.parse_args(argv)

    if args.backup_subscribers:
        state = Path(os.environ.get("SECNEWS_STATE") or DEFAULT_STATE).expanduser()
        key = subscriber_key(os.environ.get("TELEGRAM_BOT_TOKEN", "").strip())
        print("changed" if backup_subscribers(state.with_name("subscribers.json"), args.backup_subscribers,
                                              key) else "unchanged")
        return 0

    config = json.loads(args.config.read_text(encoding="utf-8"))
    state_path = Path(os.environ.get("SECNEWS_STATE") or DEFAULT_STATE).expanduser()
    translator = make_translator(config)
    global GEMINI_BUDGET, ITEM_STYLE, LITE_THINKING, PAGE_SUMMARIES
    PAGE_SUMMARIES = bool(config.get("page_summaries", True)) and not os.environ.get("SECNEWS_OFFLINE")
    LITE_THINKING = str(config.get("lite_thinking", LITE_THINKING)).strip().lower() or "off"
    ITEM_STYLE = os.environ.get("SECNEWS_ITEM_STYLE", "").strip() or config.get("item_style", "plain")
    GEMINI_BUDGET = GeminiBudget(state_path.with_name("gemini_usage.json"),
                                 [(m["model"], m["daily"]) for m in config.get("gemini_models", DEFAULT_GEMINI_MODELS)])
    if args.write_review:
        now = datetime.now(timezone.utc)
        stored = load_state(state_path) or {}
        stats = dict(stored.get("stats") or {})
        # Snapshots also list the links of the last three days' sent items, to check where they lead.
        stats["links"] = {d[2]: k for k, d in (stored.get("decisions") or {}).items() if d and d[0] == "sent"}
        write_review(state_path.parent / "reviews", stats, now, f"snapshot-{now.astimezone(KST):%Y-%m-%d-%H%M}.json")
        log(f"review snapshot: {len(stats.get('review', {}))} items")
        return 0

    if args.dry_run:
        def sender(text, silent=False):
            print(text + "\n" + "-" * 40)
            return True
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            tmp_state = Path(d) / "seen.json"
            if state_path.exists():
                tmp_state.write_bytes(state_path.read_bytes())
            run(config, tmp_state, sender, bootstrap_send=True, translate=translator, force=True,
                classify=make_classifier(config))
        return 0

    file_values = load_env_file(ENV_FILE)
    token = (os.environ.get("TELEGRAM_BOT_TOKEN") or file_values.get("TELEGRAM_BOT_TOKEN", "")).strip()
    if not token:
        log(f"error: TELEGRAM_BOT_TOKEN not set. Add it as a repository secret "
            f"(Settings > Secrets and variables > Actions > Secrets) or in {ENV_FILE}")
        return 2

    # The systemd timer and a manual Actions run share the state file; never run both at once.
    state_path.parent.mkdir(parents=True, exist_ok=True)
    lock = open(state_path.with_suffix(".lock"), "w")
    try:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        log("another run is in progress; skipping")
        return 0

    subs_path = state_path.with_name("subscribers.json")
    key = subscriber_key(token)
    only = parse_chat_ids(os.environ.get("SECNEWS_ONLY_CHATS", ""))
    if only:
        return test_send(config, state_path, token, only, translator)

    # Anyone who presses /start is subscribed automatically; /stop or blocking the bot ends it.
    # Ids from feeds.json or the secret join the encrypted list, so they can later be removed
    # from the public repository.
    configured = all_chat_ids(config, os.environ.get("TELEGRAM_CHAT_IDS") or file_values.get("TELEGRAM_CHAT_IDS", ""))
    add_subscribers(subs_path, configured, key)
    # With an admin (the test chat) and require_approval on, new /start requests wait for the admin.
    approver = os.environ.get("SECNEWS_ADMIN_CHAT", "").strip() if config.get("require_approval", True) else ""
    try:
        added, removed = sync_subscribers(subs_path, fetch_updates(token, load_subscribers(subs_path, key)
                                                                   .get("last_update", 0)),
                                          send=lambda cid, text, markup=None: telegram_send(token, cid, text,
                                                                                             markup=markup),
                                          key=key, admin=approver, welcome=wording(config, "welcome"),
                                          why=lambda q: explain(load_state(state_path), q),
                                          api=lambda method, params: telegram_api(token, method, params))
        if added or removed:
            log(f"subscribers: +{len(added)} -{len(removed)}")
    except (TelegramError, OSError, ValueError) as e:
        log(f"warning: subscriber check failed: {e}")
    subs = load_subscribers(subs_path, key)
    chats = [c for c in subs["ids"] if c not in subs["stopped"]]
    log(f"{len(chats)} recipient(s)")
    if not chats:
        log("no recipients yet: press /start in the bot or add ids to feeds.json \"chat_ids\"")
        return 0
    gone = set()

    def sender(text, silent=False):
        delivered = 0
        for chat in chats:
            if chat in gone:
                continue
            try:
                telegram_send(token, chat, text, silent=silent)
                delivered += 1
            except TelegramError as e:
                log(f"warning: chat {masked(chat)}: {e}")
                if GONE.search(str(e)):
                    gone.add(chat)
            time.sleep(0.1)
        return delivered > 0

    if args.reset and state_path.exists():
        state_path.unlink()
        log(f"reset: removed {state_path}")
    try:
        # A first run (or a reset) sends the current news; the per-run caps keep it to a few digests.
        admin = os.environ.get("SECNEWS_ADMIN_CHAT", "").strip()

        def alert(text):
            if not admin:
                return
            try:
                # Status notes (no news, a delayed digest) come without a sound.
                telegram_send(token, admin, text, silent=text.startswith(("📭", "⏳")))
            except TelegramError as e:
                log(f"warning: could not alert the owner: {e}")

        run(config, state_path, sender, bootstrap_send=not args.quiet_first_run, translate=translator,
            classify=make_classifier(config), alert=alert,
            force=args.now or args.reset)
    except TelegramError as e:
        log(f"error: {e}")
        return 1
    finally:
        mark_gone(subs_path, gone, key)
    return 0


if __name__ == "__main__":
    try:
        code = main()
    except BaseException:
        show_held_log()
        raise
    if code:
        show_held_log()
    sys.exit(code)

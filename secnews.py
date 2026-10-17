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


def log(msg):
    print(msg, file=sys.stderr, flush=True)


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
        return ET.fromstring(raw)
    text = raw.decode(enc, errors="replace")
    text = re.sub(r"^\s*<\?xml[^>]*\?>", "", text, count=1)
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


def parse_ransomware(raw, source):
    """ransomware.live victim list. Field names differ between its endpoints, so accept both."""
    data = json.loads(raw)
    if isinstance(data, dict):
        data = data.get("victims") or data.get("data") or []
    items = []
    for v in data:
        name = (v.get("victim") or v.get("post_title") or "").strip()
        group = (v.get("group") or v.get("group_name") or "").strip()
        if not name or not group:
            continue
        country = (v.get("country") or "").strip().upper()
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
            "link": f"https://www.ransomware.live/group/{urllib.parse.quote(group.lower())}",
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


PARSERS = {"telegram": parse_telegram, "ransomware": parse_ransomware, "google_news": parse_google_news}


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


def save_state(path, seen, now, recent=None, feed_failures=None, last_digest=None, instant_checked=None):
    cutoff = (now - STATE_RETENTION).timestamp()
    seen = {k: t for k, t in seen.items() if t >= cutoff}
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    state = {"seen": seen, "last_digest": now.timestamp() if last_digest is None else last_digest,
             "recent": recent or [], "feed_failures": feed_failures or {}}
    if instant_checked is not None:
        state["instant_checked"] = instant_checked
    try:  # the night the bedtime notice went out, written by night_notice
        state["night_notice"] = json.loads(path.read_text(encoding="utf-8"))["night_notice"]
    except (OSError, ValueError, KeyError, TypeError):
        pass
    tmp.write_text(json.dumps(state, ensure_ascii=False), encoding="utf-8")
    tmp.replace(path)


# ---------------------------------------------------------------- messages

FEED_FOOTER = re.compile(r"\s*(The post .*? appeared first on .*|Continue reading.*|Read more.*)$", re.I | re.S)


def short_summary(item, limit=140):
    """First sentence or so of the feed's own description, or "" if it adds nothing."""
    text = FEED_FOOTER.sub("", item.get("summary") or "").strip()
    title = item["title"].strip()
    if text.startswith(title):
        text = text[len(title):].lstrip(" :-–—")
    if len(text) < 20:
        return ""
    if len(text) > limit:
        cut = text[:limit]
        text = (cut.rsplit(" ", 1)[0] if " " in cut[limit // 2:] else cut).rstrip(",.;: ") + "…"
    return text


def translated_page_url(link, target="ko"):
    """Google Translate's proxy URL, which opens the article already translated."""
    u = urllib.parse.urlsplit(link)
    if u.scheme not in ("http", "https") or not u.hostname or u.hostname.endswith("t.me"):
        return ""
    host = u.hostname.replace("-", "--").replace(".", "-") + ".translate.goog"
    query = urllib.parse.parse_qsl(u.query) + [("_x_tr_sl", "auto"), ("_x_tr_tl", target), ("_x_tr_hl", target)]
    return urllib.parse.urlunsplit(("https", host, u.path or "/", urllib.parse.urlencode(query), ""))


def format_item(item, hide_sector=None, key="sectors"):
    when = item["date"].astimezone(KST).strftime("%m-%d %H:%M") if item["date"] else ""
    title = html.escape(item.get("display_title", item["title"]))
    if item["link"]:
        title = f'<a href="{html.escape(item["link"], quote=True)}">{title}</a>'
    tags = "".join(f"#{t.replace('·', '_').replace(' ', '_')} " for t in item.get(key, []) if t != hide_sector)
    mark = "🚨 " if hide_sector is not None and item["score"] >= 3 else ""
    lines = [f"🔹 {mark}{tags}<b>{title}</b>"]
    summary = item["display_summary"] if "display_summary" in item else short_summary(item)
    if summary:
        lines.append(f"<blockquote>{html.escape(summary)}</blockquote>")
    source = html.escape(item["source"])  # the title already links to the article
    meta = f"📰 출처: {source}" + (f" · {when}" if when else "")
    if item.get("translated"):
        ko_page = translated_page_url(item["link"]) if item["link"] else ""
        meta += f' · <a href="{html.escape(ko_page, quote=True)}">🇰🇷 번역본 보기</a>' if ko_page else " · 🌐 영문 번역"
    lines.append(meta)
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
Write natural Korean news style: headlines short like Korean news headlines, summaries as plain sentences.
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
        try:
            from zoneinfo import ZoneInfo
            self.day = datetime.now(ZoneInfo("America/Los_Angeles")).strftime("%Y-%m-%d")
        except Exception:
            self.day = (datetime.now(timezone.utc) - timedelta(hours=8)).strftime("%Y-%m-%d")
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            data = {}
        used = data.get("used") if data.get("day") == self.day else None
        self.used = used if isinstance(used, dict) else {}

    def take(self):
        """Count one request and return the model to send it to."""
        for model, cap in self.models:
            if self.used.get(model, 0) < cap:
                self.used[model] = self.used.get(model, 0) + 1
                try:
                    self.path.parent.mkdir(parents=True, exist_ok=True)
                    self.path.write_text(json.dumps({"day": self.day, "used": self.used}), encoding="utf-8")
                except OSError:
                    pass
                return model
        raise RuntimeError("today's Gemini budget is used up for every model")

    def exhaust(self, model):
        for m, cap in self.models:
            if m == model:
                self.used[m] = cap
        try:
            self.path.write_text(json.dumps({"day": self.day, "used": self.used}), encoding="utf-8")
        except OSError:
            pass


GEMINI_BUDGET = None  # set in main()
# Free tier, October 2026: Flash models 20 requests a day each, Flash Lite 500. The Flash shares
# cover the hourly digests with room for a manual test; Flash Lite is the deep reserve.
DEFAULT_GEMINI_MODELS = [{"model": "gemini-flash-latest", "daily": 18},
                         {"model": "gemini-3.7-flash", "daily": 18},
                         {"model": "gemini-3.6-flash", "daily": 18},
                         {"model": "gemini-flash-lite-latest", "daily": 450}]


def gemini_json(prompt, key, model="gemini-flash-latest", timeout=90):
    """One Gemini request that answers in JSON. Raises on any failure."""
    body = json.dumps({
        "contents": [{"parts": [{"text": prompt}]}],
        "generationConfig": {"temperature": 0.2, "responseMimeType": "application/json"},
    }).encode()
    while True:
        if GEMINI_BUDGET is not None:
            model = GEMINI_BUDGET.take()
        url = f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent"
        req = urllib.request.Request(url, data=body, headers={
            "Content-Type": "application/json", "x-goog-api-key": key, "User-Agent": USER_AGENT})
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                data = json.loads(resp.read())
        except urllib.error.HTTPError as e:
            # 429: this model's free quota is gone (or tests used it up); 404: no such model here.
            # Either way skip the model for the rest of the day and ask the next one.
            if GEMINI_BUDGET is not None and e.code in (404, 429):
                log(f"Gemini {model}: HTTP {e.code}; switching to the next model for today")
                GEMINI_BUDGET.exhaust(model)
                continue
            raise
        log(f"Gemini request answered by {model}")
        return json.loads(data["candidates"][0]["content"]["parts"][0]["text"])


def gemini_translate_batch(texts, key, model="gemini-flash-latest", timeout=60):
    """Translate several texts in one Gemini request. Raises on any failure."""
    out = gemini_json(GEMINI_PROMPT + json.dumps(texts, ensure_ascii=False), key, model, timeout)
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


def gemini_classify(items, key, model, sectors, focus_sectors, told=(), instructions=None):
    rows = [{"i": n, "title": it["title"], "summary": short_summary(it)} for n, it in enumerate(items)]
    prompt = ((instructions or CLASSIFY_PROMPT) + "\nSECTORS: " + json.dumps(sectors + ["기타"], ensure_ascii=False)
              + "\nFOCUS_SECTORS: " + json.dumps(focus_sectors + ["기타"], ensure_ascii=False)
              + "\nALREADY_SENT: " + json.dumps(list(told)[-150:], ensure_ascii=False)
              + "\n\nItems:\n" + json.dumps(rows, ensure_ascii=False))
    out = gemini_json(prompt, key, model, timeout=240)  # 60 items with translations take a while
    if not isinstance(out, list) or len(out) != len(items):
        raise ValueError("classification list does not match the input")
    by_i = {r.get("i"): r for r in out if isinstance(r, dict)}
    if set(by_i) != set(range(len(items))):
        raise ValueError("classification is missing items")
    return [by_i[n] for n in range(len(items))]


class GeminiClassifier:
    """Second opinion on the keyword filter: Gemini drops off-topic items and sets focus,
    urgency and sector. Keyword results stay for anything Gemini could not judge."""

    def __init__(self, key, config, model="gemini-flash-latest", chunk=60, limit=60):
        self.key, self.model, self.chunk, self.limit = key, model, chunk, limit
        self.sectors = list(config.get("sectors", {})) + list(config.get("fallback_sectors", {}))
        self.focus_sectors = list(config.get("focus_sectors", {}))
        self.instructions = config.get("classify_prompt")

    def __call__(self, items, told=()):
        """Return the items to keep, best keyword score first in, same order out."""
        judged, dropped, dups, failed = {}, 0, 0, False
        # One request per digest: the best-ranked 60 are judged, the rest keep keyword results
        # (they are past the per-digest caps nearly always).
        head = items[:self.limit]
        for i in range(0, len(head), self.chunk):
            part = head[i:i + self.chunk]
            try:
                results = gemini_classify(part, self.key, self.model, self.sectors, self.focus_sectors, told,
                                          self.instructions)
                for n, r in enumerate(results):
                    d = r.get("dup_of")
                    if isinstance(d, int) and not isinstance(d, bool) and 0 <= d < len(part) and d != n:
                        results[max(n, d)]["duplicate"] = True  # the better-ranked report stays
                for it, r in zip(part, results):
                    judged[id(it)] = r
            except Exception as e:
                log(f"warning: Gemini classification failed ({e}); keeping keyword results")
                failed = True
                break
        kept = []
        for it in items:
            r = judged.get(id(it))
            if r is None:
                kept.append(it)
                continue
            focus = bool(r.get("focus"))
            if r.get("duplicate") or r.get("already_sent"):
                dups += 1
                continue
            if not r.get("relevant") or (it.get("focus_only") and not focus):
                dropped += 1
                continue
            if isinstance(r.get("story"), str) and r["story"].strip():
                it["story"] = r["story"].strip().lower()
            # A runaway answer (or text a feed slipped in to steer Gemini) must not blow up a message.
            for field, cap in (("title_ko", 200), ("summary_ko", 300)):
                if isinstance(r.get(field), str) and r[field].strip():
                    text = r[field].strip()
                    it[field] = text if len(text) <= cap else text[:cap].rstrip() + "…"
            it["focus"] = focus
            it["score"] = max(it["score"], 3) if r.get("urgent") else min(it["score"], 2)
            sector, fsector = r.get("sector"), r.get("focus_sector")
            if sector in self.sectors or sector == OTHER_SECTOR:
                it["sectors"] = [] if sector == OTHER_SECTOR else [sector]
            if fsector in self.focus_sectors or fsector == OTHER_SECTOR:
                it["focus_sectors"] = [] if fsector == OTHER_SECTOR else [fsector]
            kept.append(it)
        if judged:
            log(f"classified {len(judged)} item(s) with Gemini; dropped {dropped} as off-topic, {dups} as duplicates"
                + (" (partly)" if failed else ""))
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


def localize(items, translate):
    """Fill display_title/display_summary, translating English text to Korean.
    The original title stays on the item and the link still points at the original article."""
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
            if needs_translation(title) and item.get("title_ko"):
                title = item["title_ko"]
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
        nonce, ct = base64.b64decode(data["nonce"]), base64.b64decode(data["ct"])
        if not hmac.compare_digest(base64.b64decode(data["mac"]), hmac.new(key, nonce + ct, hashlib.sha256).digest()):
            log("warning: subscriber file does not match this bot token; starting a new list")
            return empty
        data = json.loads(bytes(a ^ b for a, b in zip(ct, _keystream(key, nonce, len(ct)))))
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
    if key:
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
    nonce, ct = base64.b64decode(data["nonce"]), base64.b64decode(data["ct"])
    return bool(key) and hmac.compare_digest(base64.b64decode(data["mac"]),
                                             hmac.new(key, nonce + ct, hashlib.sha256).digest())


def backup_subscribers(path, backup, key=None):
    """Copy the (encrypted) subscriber file to backup when who is subscribed has changed, so a lost
    Actions cache does not lose the list. Returns True when the backup was written. An empty list
    never replaces a backup this token can still read: that looks like a lost cache, not a change."""
    if not path.exists():
        return False
    current = load_subscribers(path, key)
    if _readable_with(backup, key):
        old = load_subscribers(backup, key)
        if all((sorted(current[f]) if isinstance(current[f], list) else current[f])
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


def sync_subscribers(path, updates, send=None, key=None, admin=None, api=None, welcome=TEXTS["welcome"]):
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
    stats_asked = False
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
                      else "stats" if text.startswith("/stats") else "chat")
        cid = str(chat["id"])
        if action == "test":
            # The admin rehearses a request: same messages and buttons, nothing stored.
            if admin and cid == admin:
                tests.append(_chat_name(chat))
            continue
        if action == "stats":
            stats_asked = stats_asked or bool(admin and cid == admin)  # others get no answer
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
                       f"· 승인 대기: {len(pending)}명\n· 해지: {len(stopped)}명\n· 거절: {len(denied)}명")
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


def collect(config, fetcher=fetch, failed=None):
    items = []
    for n, feed in enumerate(config["feeds"]):
        try:
            raw = fetcher(feed["url"])
            kind = feed.get("type", "rss")
            parser = {"rss": parse_feed, "cisa_kev": parse_kev}.get(kind) or PARSERS[kind]
            got = parser(raw, feed["name"])
            for it in got:
                it["security_only"] = feed.get("security_only", False)
                it["min_score"] = feed.get("min_score")
                it["focus_only"] = feed.get("focus_only", False)
            log(f"{feed_label(feed, n)}: {len(got)} items")
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


def already_told(item, recent, sent_cves):
    """A story sent in an earlier digest, now from another outlet (or the KEV entry for it):
    every CVE in its headline went out already, or its headline matches one that did."""
    cves = {c.upper() for c in CVE_RE.findall(item["title"])}
    if cves and cves <= sent_cves:
        return True
    return any(similar(item["title"], r[0]) for r in recent)


EXPLOIT_WORDS = re.compile(r"zero-day|0-day|zeroday|exploit|제로데이|악용", re.I)


def kev_covered(item, titles):
    """A KEV entry whose vendor appears in a news headline about an exploited hole (the
    catalog adding "BeyondTrust ..." the day "BeyondTrust patches zero-day exploited in
    attacks" ran): the article says more, so the KEV entry is the one dropped."""
    vendor = item.get("vendor", "").strip().lower()
    if not item["id"].startswith("kev:") or len(vendor) < 3:
        return False
    return any(vendor in t.lower() and EXPLOIT_WORDS.search(t) for t in titles)


def trim(items, max_items, max_per_source=0):
    """Drop stories about a CVE already covered by a higher-ranked item, keep at most
    max_per_source items from any one source so a busy channel cannot fill the digest,
    then cap the count. Items are expected best-first; whatever is dropped is still marked as seen."""
    kept, covered, per_source = [], set(), {}
    for item in items:
        cves = {c.upper() for c in CVE_RE.findall(item["title"])}
        if cves and cves <= covered:
            continue
        if max_per_source and per_source.get(item.get("source"), 0) >= max_per_source:
            continue
        if any(similar(item["title"], k["title"]) for k in kept):
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
        classify=None, alert=None):
    """Collect, filter and send. Returns the list of sent items.

    sender(text) must return True when at least one chat received the text."""
    now = now or datetime.now(timezone.utc)
    state = load_state(state_path)
    if not force and not due(state, config, now):
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

    # Stories already sent in the last max_age_hours: [title, [CVEs], timestamp].
    recent = [r for r in (state or {}).get("recent", []) if now.timestamp() - r[2] <= max_age.total_seconds()]
    sent_cves = {c for r in recent for c in r[1]}

    fresh, keys, fresh_titles, failed = [], set(), [], []
    for item in collect(config, fetcher, failed):
        if item["date"] and item["date"] > now + timedelta(hours=1):
            # Some Korean feeds stamp Korean time as GMT, which puts their articles 9 hours ahead.
            item["date"] = min(item["date"] - timedelta(hours=9), now)
        if item["date"] and now - item["date"] > max_age:
            continue
        key, tkey = item_key(item), title_key(item)
        if key in seen or key in keys or tkey in seen or tkey in keys:
            continue
        keys.update((key, tkey))
        scorer.classify(item)
        tagger.tag(item)
        if item["focus"]:
            focus_tagger.tag(item)
        fresh.append((key, item))
        fresh_titles.append(tkey)

    # Topic feeds and social channels carry much else; keep only security ones.
    news = [it for _, it in fresh if not it.get("ransomware")
            and it["score"] >= (it.get("min_score") or min_score)
            and not (it["security_only"] and not it["security_hits"])
            and not (it.get("focus_only") and not it.get("focus"))
            and not (it.get("focus") and not it.get("focus_security", True))
            and not already_told(it, recent, sent_cves)]
    titles = [it["title"] for it in news if not it["id"].startswith("kev:")] + [r[0] for r in recent]
    news = [it for it in news if not kev_covered(it, titles)]
    news.sort(key=lambda it: (-it["score"], -(it["date"] or now).timestamp()))
    if classify and news:
        # Gemini also spots stories sent in an earlier digest, across languages.
        news = classify(news, [r[3] if len(r) > 3 and r[3] else r[0] for r in recent])
        news.sort(key=lambda it: (-it["score"], -(it["date"] or now).timestamp()))
    # The 06:00 round-up carries the whole night, so its caps are larger.
    factor = config.get("morning_cap_factor", 1.5) if morning(config, now) and not force else 1
    suffix = " · 🌅 밤사이 모음" if factor != 1 else ""

    def capped(name):
        return int(config.get(name, 0) * factor)

    digests = [(wording(config, title) + suffix, trim([it for it in news if bool(it.get("focus")) == focus],
                                                   capped(cap), config.get("max_per_source", 0)), categories)
               for focus, title, cap, categories in DIGESTS]
    leaks = [it for _, it in fresh if it.get("ransomware") and ransomware_wanted(it, config)]
    leaks.sort(key=lambda it: (it["country"] not in config.get("ransomware_countries", ["KR"]),
                               -(it["date"] or now).timestamp()))
    digests.append((wording(config, "ransomware_title") + suffix, leaks[:capped("max_ransomware_per_run") or None],
                    "sectors"))

    if first_run and not bootstrap_send:
        log(f"first run: marking {len(fresh)} current items as seen without sending")
        digests = []

    sent = []
    for title, items, categories in digests:
        if not items:
            continue
        localize(items, translate)
        extra = list(fallback) if categories == "sectors" else []
        for msg in build_messages(items, now, title, sector_order=list(config.get(categories, {})) + extra,
                                  key=categories, last=extra, icons=icons(config)):
            if not sender(msg):
                # Keep state untouched so the same items are retried next run.
                raise TelegramError("message was not delivered to any chat")
        sent += items
    log(f"sent {len(sent)} of {len(fresh)} new items")
    # feeds.json "no_news_notice": "all" (silent message to everyone), "admin", or "off" (default).
    notice = config.get("no_news_notice", "off")
    if not sent and digests and notice != "off":
        text = wording(config, "no_news").replace("{time}", f"{now.astimezone(KST):%H:%M}")
        if notice == "admin":
            if alert:
                alert(text)
        elif not sender(text, silent=True):
            log("warning: the no-news notice was not delivered")

    ts = now.timestamp()
    for key, _ in fresh:
        seen[key] = ts
    for tkey in fresh_titles:
        seen[tkey] = ts
    recent += [[it["title"], sorted(item_cves(it)), ts, it.get("story", "")] for it in sent]

    # A feed that keeps failing has probably moved or changed format; say so once.
    failures = {n: c + 1 for n, c in (state or {}).get("feed_failures", {}).items() if n in failed}
    failures.update({n: 1 for n in failed if n not in failures})
    broken = [n for n, c in failures.items() if c == FEED_ALERT_AFTER]
    if broken and alert:
        alert("⚠️ 보안 속보 봇: 다음 출처가 " + f"{FEED_ALERT_AFTER}번 연속 실패했어요 (주소 변경 가능성)\n"
              + "\n".join(f"· {html.escape(n)}" for n in broken))
    save_state(state_path, seen, now, recent, failures, instant_checked=(state or {}).get("instant_checked"))
    return sent




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
    sent_cves = {c for r in recent for c in r[1]}
    scorer = Scorer(config.get("keywords", {}))
    fallback = config.get("fallback_sectors", {})
    tagger = SectorTagger(config.get("sectors", {}), fallback=fallback)
    strong = [_keyword_re(k) for k in config.get("keywords", {}).get("instant", [])]
    window = timedelta(minutes=config.get("instant_max_age_minutes", 180))
    ts = now.timestamp()

    candidates = []
    for item in collect(dict(config, feeds=feeds), fetcher):
        if item["date"] and item["date"] > now + timedelta(hours=1):
            item["date"] = min(item["date"] - timedelta(hours=9), now)
        if not item["date"] or now - item["date"] > window:
            continue
        key, tkey = item_key(item), title_key(item)
        if key in seen or tkey in seen or key in checked:
            continue
        checked[key] = ts  # judged once; a miss waits for the digest
        scorer.classify(item)
        text = f"{item['title']} {item.get('summary', '')}".lower()
        signal = item["id"].startswith("kev:") or any(r.search(text) for r in strong)
        if first or not signal or item["score"] < 3 or already_told(item, recent, sent_cves):
            continue
        tagger.tag(item)
        candidates.append((key, tkey, item))

    sent = []
    if first:
        log("instant alerts: first check; current items recorded, nothing sent")
    elif candidates:
        items = [it for _, _, it in candidates]
        titles = [it["title"] for it in items if not it["id"].startswith("kev:")] + [r[0] for r in recent]
        items = [it for it in items if not kev_covered(it, titles)]
        if classify and items:
            items = classify(items, [r[3] if len(r) > 3 and r[3] else r[0] for r in recent])
        urgent = trim(sorted([it for it in items if it["score"] >= 3], key=lambda it: -it["score"]),
                      config.get("max_instant_per_run", 5))
        if urgent:
            localize(urgent, translate)
            hush = quiet(config, now)
            for msg in build_messages(urgent, now, wording(config, "instant_title"),
                                      sector_order=list(config.get("sectors", {})) + list(fallback),
                                      key="sectors", last=list(fallback), icons=icons(config)):
                if not sender(msg, silent=hush):
                    raise TelegramError("message was not delivered to any chat")
            sent = urgent
            for key, tkey, it in candidates:
                if it in urgent:
                    seen[key] = seen[tkey] = ts
            recent += [[it["title"], sorted(item_cves(it)), ts, it.get("story", "")] for it in urgent]
        log(f"instant alerts: {len(candidates)} candidate(s), sent {len(sent)}" + (" quietly" if sent and quiet(config, now) else ""))
    checked = {k: t for k, t in checked.items() if ts - t <= 2 * 86400}
    save_state(state_path, seen, now, recent, state.get("feed_failures", {}),
               last_digest=state.get("last_digest"), instant_checked=checked)
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
    global GEMINI_BUDGET
    GEMINI_BUDGET = GeminiBudget(state_path.with_name("gemini_usage.json"),
                                 [(m["model"], m["daily"]) for m in config.get("gemini_models", DEFAULT_GEMINI_MODELS)])

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
                telegram_send(token, admin, text)
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
    sys.exit(main())

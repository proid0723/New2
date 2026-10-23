import os
import base64
import json
import sys
import tempfile
import unittest
from unittest import mock
import urllib.parse
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import secnews  # noqa: E402

NOW = datetime(2026, 10, 15, 3, 0, tzinfo=timezone.utc)

RSS = b"""<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0"><channel><title>t</title>
<item><title>Chrome zero-day actively exploited &amp; patched</title>
<link>https://example.com/a?utm_source=rss</link><guid>https://example.com/a</guid>
<pubDate>Wed, 15 Oct 2026 01:00:00 +0000</pubDate><description>&lt;p&gt;CVE-2026-1234&lt;/p&gt;</description></item>
<item><title>Open source conference recap</title><link>https://example.com/b</link>
<pubDate>Wed, 15 Oct 2026 00:30:00 +0000</pubDate></item>
<item><title>Old ransomware story</title><link>https://example.com/old</link>
<pubDate>Mon, 01 Sep 2026 00:00:00 +0000</pubDate></item>
</channel></rss>"""

ATOM = b"""<?xml version="1.0" encoding="utf-8"?>
<feed xmlns="http://www.w3.org/2005/Atom"><title>t</title>
<entry><title>Major data breach at retailer</title>
<link rel="alternate" href="https://atom.example/x"/><id>tag:x</id>
<updated>2026-10-15T02:00:00Z</updated><summary>malware</summary></entry>
</feed>"""

EUCKR = ('<?xml version="1.0" encoding="euc-kr"?><rss version="2.0"><channel>'
         '<item><title>국내 기업 랜섬웨어 피해, 긴급 패치 필요</title><link>http://kr.example/1</link>'
         '<pubDate>Wed, 15 Oct 2026 10:00:00 +0900</pubDate></item></channel></rss>').encode("euc-kr")

KEV = json.dumps({"vulnerabilities": [
    {"cveID": "CVE-2026-9999", "vendorProject": "Acme", "product": "Gateway",
     "vulnerabilityName": "Auth Bypass", "dateAdded": "2026-10-14",
     "shortDescription": "bad", "knownRansomwareCampaignUse": "Known"},
    {"cveID": "CVE-2020-0001", "vendorProject": "Old", "product": "Thing",
     "vulnerabilityName": "Old bug", "dateAdded": "2021-11-03"},
]}).encode()

CONFIG = {
    "max_age_hours": 48,
    "min_score": 1,
    "feeds": [
        {"name": "RSS", "url": "rss"},
        {"name": "Atom", "url": "atom"},
        {"name": "KR", "url": "kr"},
        {"name": "CISA KEV", "url": "kev", "type": "cisa_kev"},
        {"name": "Broken", "url": "broken"},
    ],
    "keywords": json.loads((Path(__file__).with_name("test_feeds.json")).read_text("utf-8"))["keywords"],
}


def fake_fetch(url):
    if url == "broken":
        raise OSError("boom")
    return {"rss": RSS, "atom": ATOM, "kr": EUCKR, "kev": KEV}[url]


class ParseTests(unittest.TestCase):
    def test_rss(self):
        items = secnews.parse_feed(RSS, "RSS")
        self.assertEqual(len(items), 3)
        self.assertEqual(items[0]["title"], "Chrome zero-day actively exploited & patched")
        self.assertEqual(items[0]["summary"], "CVE-2026-1234")
        self.assertEqual(items[0]["date"], datetime(2026, 10, 15, 1, tzinfo=timezone.utc))

    def test_atom(self):
        (item,) = secnews.parse_feed(ATOM, "Atom")
        self.assertEqual(item["link"], "https://atom.example/x")
        self.assertEqual(item["date"], datetime(2026, 10, 15, 2, tzinfo=timezone.utc))

    def test_euc_kr(self):
        (item,) = secnews.parse_feed(EUCKR, "KR")
        self.assertIn("랜섬웨어", item["title"])

    def test_html_page_is_reported(self):
        with self.assertRaisesRegex(ValueError, "HTML page"):
            secnews.parse_feed(b"<!doctype html><html><head></head></html>", "X")

    def test_whitespace_after_declaration(self):
        raw = b'<?xml version="1.0" encoding="utf-8" ?>\n    <rss version="2.0"><channel><item><title>t</title><link>https://e/1</link></item></channel></rss>'
        self.assertEqual(len(secnews.parse_feed(raw, "X")), 1)

    def test_kev(self):
        items = secnews.parse_kev(KEV, "CISA KEV")
        self.assertEqual(items[0]["id"], "kev:CVE-2026-9999")
        self.assertTrue(items[0]["title"].endswith("(ransomware)"))


TG_PAGE = """<html><body>
<div class="tgme_widget_message_wrap"><div class="tgme_widget_message text_not_supported_wrap js-widget_message" data-post="chan/101">
 <div class="tgme_widget_message_text js-message_text" dir="auto"><b>Zero-day in Fortinet exploited</b><br/>Attackers are using a new flaw to break into VPN appliances. <a href="https://x">Read</a></div>
 <div class="tgme_widget_message_footer"><a class="tgme_widget_message_date"><time datetime="2026-10-15T01:30:00+00:00" class="time">01:30</time></a></div>
</div></div>
<div class="tgme_widget_message_wrap"><div class="tgme_widget_message js-widget_message" data-post="chan/102">
 <div class="tgme_widget_message_text js-message_text" dir="auto">hi</div>
 <time datetime="2026-10-15T01:31:00+00:00"></time>
</div></div>
</body></html>""".encode()

BSKY = b"""<?xml version="1.0" encoding="UTF-8"?><rss version="2.0"><channel><title>x</title>
<item><link>https://bsky.app/profile/a/post/1</link><description>New ransomware strain hits hospitals across Europe. Details below.</description>
<pubDate>Wed, 15 Oct 2026 01:00:00 +0000</pubDate><guid>at://a/1</guid></item></channel></rss>"""

RW_RECENT = json.dumps([
    {"victim": "acme-airlines.com", "group": "akira", "discovered": "2026-10-15 01:00:00", "country": "US", "activity": "Aviation"},
    {"victim": "bakery.fr", "group": "qilin", "discovered": "2026-10-15 01:00:00", "country": "FR", "activity": "Food"},
    {"post_title": "한국전자", "group_name": "lockbit", "published": "2026-10-14 10:00:00", "country": "KR", "activity": "Not Found"},
]).encode()


class SourceParserTests(unittest.TestCase):
    def test_telegram(self):
        items = secnews.parse_telegram(TG_PAGE, "TG")
        self.assertEqual(len(items), 1)  # the two-character post is skipped
        it = items[0]
        self.assertEqual(it["title"], "Zero-day in Fortinet exploited")
        self.assertTrue(it["summary"].startswith("Attackers are using"))
        self.assertEqual(it["link"], "https://t.me/chan/101")
        self.assertEqual(it["date"], datetime(2026, 10, 15, 1, 30, tzinfo=timezone.utc))

    def test_feed_with_a_bare_ampersand_or_control_character_is_mended(self):
        raw = ("<?xml version='1.0' encoding='UTF-8'?><rss version='2.0'><channel>"
               "<item><title>Airline A&B breach\x01 confirmed</title><link>https://e/a?x=1&y=2</link><guid>a</guid></item>"
               "</channel></rss>").encode()
        (it,) = secnews.parse_feed(raw, "Wire")
        self.assertEqual(it["title"], "Airline A&B breach confirmed")

    def test_titleless_rss_post(self):
        (it,) = secnews.parse_feed(BSKY, "Bluesky")
        self.assertEqual(it["title"], "New ransomware strain hits hospitals across Europe.")
        self.assertEqual(it["summary"], "Details below.")

    def test_google_news(self):
        raw = ("<?xml version='1.0' encoding='UTF-8'?><rss version='2.0'><channel>"
               "<item><title>[단독] 카메라 달린 中전기차 200대, 공항 시설 자유 출입 - 조선일보</title>"
               "<link>https://news.google.com/rss/articles/abc</link><guid>abc</guid>"
               "<pubDate>Wed, 15 Oct 2026 21:01:00 GMT</pubDate>"
               "<description>&lt;a href='x'&gt;same title&lt;/a&gt;</description></item></channel></rss>").encode()
        (it,) = secnews.parse_google_news(raw, "구글뉴스")
        self.assertEqual(it["title"], "[단독] 카메라 달린 中전기차 200대, 공항 시설 자유 출입")
        self.assertEqual(it["source"], "조선일보")
        self.assertEqual(it["summary"], "")
        scorer = secnews.Scorer(json.loads(Path(__file__).with_name("test_feeds.json").read_text("utf-8"))["keywords"])
        scorer.classify(it)
        self.assertTrue(it["focus"])

    def test_blocked_outlets_are_dropped_by_name_or_domain(self):
        raw = ("<?xml version='1.0' encoding='UTF-8'?><rss version='2.0'><channel>"
               "<item><title>Airport outage - Example Daily</title><link>https://news.google.com/a</link><guid>a</guid></item>"
               "<item><title>Airport outage - Good Paper</title><link>https://news.google.com/b</link><guid>b</guid></item>"
               "</channel></rss>").encode()
        rss = ("<?xml version='1.0' encoding='UTF-8'?><rss version='2.0'><channel>"
               "<item><title>Airline breach</title><link>https://spam.example.net/x</link><guid>c</guid></item>"
               "</channel></rss>").encode()
        config = {"blocked_outlets": ["example daily", "spam.example.net", " "],
                  "feeds": [{"name": "G", "type": "google_news", "url": "g"}, {"name": "R", "url": "r"}]}
        items = secnews.collect(config, fetcher=lambda url: raw if url == "g" else rss)
        self.assertEqual([it["source"] for it in items], ["Good Paper"])

    def test_ransomlook_posts_and_the_same_victim_from_both_sites(self):
        raw = json.dumps([
            {"post_title": "hanbit-tech.co.kr", "group_name": "Qilin", "discovered": "2026-10-15 01:00:00.123456"},
            {"post_title": "(주)한국정밀", "group_name": "akira", "discovered": "2026-10-15 02:00:00"},
            {"post_title": "bakery.fr", "group_name": "play", "discovered": "2026-10-15 01:00:00"},
        ]).encode()
        items = secnews.PARSERS["ransomlook"](raw, "ransomlook")
        self.assertEqual([i["country"] for i in items], ["KR", "KR", ""])
        self.assertTrue(items[0]["title"].startswith("🇰🇷 hanbit-tech.co.kr"))
        self.assertTrue(items[0]["link"].startswith("https://www.ransomlook.io/group/qilin"))
        live = secnews.parse_ransomware(json.dumps([{"victim": "hanbit-tech.co.kr", "group": "qilin",
                                                    "country": "KR"}]).encode(), "rw")
        self.assertEqual(live[0]["id"], items[0]["id"])  # collected once

    def test_ransomware_both_shapes(self):
        items = secnews.parse_ransomware(RW_RECENT, "rw")
        self.assertEqual(len(items), 3)
        kr = items[2]
        self.assertTrue(kr["title"].startswith("🇰🇷 한국전자"))
        self.assertEqual(kr["sector"], "")
        self.assertIn("주장", kr["summary"])
        self.assertTrue(kr["no_translate"])


class ScoreTests(unittest.TestCase):
    def setUp(self):
        self.scorer = secnews.Scorer(CONFIG["keywords"])

    def score(self, title):
        return self.scorer.score({"title": title})

    def test_word_boundaries(self):
        self.assertEqual(self.score("Open source conference adapts"), 0)  # no "rce"/"apt"
        self.assertGreaterEqual(self.score("Unauthenticated RCE in router"), 3)
        self.assertGreaterEqual(self.score("Fix for CVE-2026-1"), 1)

    def test_korean(self):
        self.assertGreaterEqual(self.score("제로데이 취약점 발견"), 4)

    def test_focus(self):
        item = {"title": "해킹조직, 항공사 노린 악성코드 유포"}
        self.scorer.classify(item)
        self.assertTrue(item["focus"])
        item = {"title": "Airline contractor hit by ransomware"}
        self.scorer.classify(item)
        self.assertTrue(item["focus"])
        for title in ["Microsoft Defender update", "Classified ads site leaks user data",
                      "Flight simulator mod spreads malware", "Big tech lays off IT workers",
                      "눈에 안보이는 위협, 클라우드 설정 오류", "핵심 인프라 보안 강화",
                      "전자파 차단 스마트폰 케이스 출시"]:
            item = {"title": title}
            self.scorer.classify(item)
            self.assertFalse(item["focus"], title)
        for title in ["Hackers target South Korean airline suppliers", "Airport networks hit by intrusion",
                      "국토부 항공 관제망 해킹 시도 포착", "해커, 항공사 공격",
                      "[단독] 항공기 정비 시스템 ‘새어나가는 정보’ 등급화한다"]:
            item = {"title": title}
            self.scorer.classify(item)
            self.assertTrue(item["focus"], title)


class RunTests(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.state = Path(self.dir.name) / "state" / "seen.json"
        self.sent = []

    def tearDown(self):
        self.dir.cleanup()

    def sender(self, text):
        self.sent.append(text)
        return True

    def run_once(self, **kw):
        return secnews.run(CONFIG, self.state, self.sender, now=NOW, fetcher=fake_fetch, **kw)

    def test_first_run_sends_nothing_then_only_new(self):
        self.assertEqual(self.run_once(), [])
        self.assertEqual(self.sent, [])
        self.assertTrue(self.state.exists())
        self.assertEqual(self.run_once(), [])  # nothing new

    def test_bootstrap_send_filters_and_sorts(self):
        sent = self.run_once(bootstrap_send=True)
        titles = [i["title"] for i in sent]
        self.assertNotIn("Open source conference recap", titles)  # score 0 < min_score
        self.assertNotIn("Old ransomware story", titles)  # older than max_age
        self.assertFalse(any("CVE-2020-0001" in t for t in titles))
        self.assertEqual(len(sent), 4)
        scores = [i["score"] for i in sent]
        self.assertEqual(scores, sorted(scores, reverse=True))
        self.assertEqual(len(self.sent), 1)
        self.assertIn("🛡", self.sent[0])
        self.assertIn("&amp;", self.sent[0])  # HTML escaped
        self.assertEqual(self.run_once(), [])  # dedup on second run

    @staticmethod
    def rss(*items):
        body = "".join(f"<item><title>{t}</title><link>https://e/{abs(hash(t))}</link><pubDate>{d}</pubDate></item>"
                       for t, d in items)
        return f'<?xml version="1.0"?><rss version="2.0"><channel>{body}</channel></rss>'.encode()

    def test_no_news_notice(self):
        quiet_feed = self.rss(("Company opens new office", "Wed, 15 Oct 2026 01:00:00 +0000"))
        got, alerts = [], []
        for mode in ("all", "admin", "off"):
            got.clear(), alerts.clear()
            state = Path(self.dir.name) / mode / "seen.json"
            cfg = dict(CONFIG, feeds=[{"name": "F", "url": "f"}], no_news_notice=mode)
            secnews.run(cfg, state, lambda text, silent=False: got.append((text, silent)) or True, now=NOW,
                        fetcher=lambda u: quiet_feed, bootstrap_send=True, alert=alerts.append)
            if mode == "all":
                self.assertEqual(len(got), 1)
                self.assertTrue(got[0][1])  # silent
                self.assertIn("새로 보낼 보안 뉴스가 없어요", got[0][0])
            elif mode == "admin":
                self.assertEqual((len(got), len(alerts)), (0, 1))
            else:
                self.assertEqual((got, alerts), ([], []))
        got.clear()
        cfg = dict(CONFIG, feeds=[{"name": "F", "url": "f"}], no_news_notice="all")
        secnews.run(cfg, Path(self.dir.name) / "first" / "seen.json",
                    lambda text, silent=False: got.append(text) or True,
                    now=NOW, fetcher=lambda u: quiet_feed)  # a first run only records what it sees
        self.assertEqual(got, [])

    def test_night_notice_once_at_the_start_of_quiet_hours(self):
        cfg = dict(CONFIG, feeds=[{"name": "F", "url": "f"}], quiet_hours=[22, 6], night_notice=True)
        empty = self.rss()
        got = []
        send = lambda text, silent=False: got.append((text, silent)) or True
        evening = datetime(2026, 10, 15, 12, 5, tzinfo=timezone.utc)  # 21:05 KST
        secnews.run(cfg, self.state, send, now=evening, fetcher=lambda u: empty, bootstrap_send=True)
        got.clear()
        for minutes in (60, 65, 120):  # 22:05, 22:10, 23:05 KST
            secnews.run(cfg, self.state, send, now=evening + timedelta(minutes=minutes), fetcher=lambda u: empty)
        notices = [g for g in got if "취침 모드" in g[0]]
        self.assertEqual(len(notices), 1)
        self.assertTrue(notices[0][1])  # silent
        self.assertIn("05시까지", notices[0][0])
        self.assertIn("06시에", notices[0][0])

    def test_why_explains_what_became_of_an_article(self):
        cfg = dict(CONFIG, feeds=[{"name": "F", "url": "f"}])
        d = "Wed, 15 Oct 2026 01:00:00 +0000"
        feed = (f'<?xml version="1.0"?><rss version="2.0"><channel>'
                f'<item><title>Zero-day actively exploited in router</title><link>https://e.com/a?utm=x</link>'
                f'<pubDate>{d}</pubDate></item>'
                f'<item><title>Company opens new office</title><link>https://e.com/b</link>'
                f'<pubDate>{d}</pubDate></item>'
                f'<item><title>Bank malware campaign spreads</title><link>https://e.com/c</link>'
                f'<pubDate>{d}</pubDate></item></channel></rss>').encode()
        drop = lambda items, told=(): [it for it in items if "Bank" not in it["title"]
                                       or it.update(drop_reason="gemini_irrelevant")]
        secnews.run(cfg, self.state, self.sender, now=NOW, fetcher=lambda u: feed, bootstrap_send=True,
                    classify=drop)
        state = secnews.load_state(self.state)
        self.assertIn("발송했어요", secnews.explain(state, "https://www.e.com/a"))
        self.assertIn("키워드 점수", secnews.explain(state, "https://e.com/b"))
        self.assertIn("AI(Gemini)", secnews.explain(state, "malware campaign"))
        self.assertIn("기록이 없어요", secnews.explain(state, "https://other.com/x"))

    def test_weekly_report_on_monday_morning(self):
        cfg = dict(CONFIG, feeds=[{"name": "Quiet feed", "url": "q"}, {"name": "F", "url": "f"}])
        d = "Wed, 15 Oct 2026 01:00:00 +0000"
        busy = self.rss(("Zero-day actively exploited in router", d))
        alerts = []
        fetch = lambda u: busy if u == "f" else self.rss()
        secnews.run(cfg, self.state, self.sender, now=NOW, fetcher=fetch, bootstrap_send=True, alert=alerts.append)
        monday = datetime(2026, 10, 19, 0, 1, tzinfo=timezone.utc)  # 09:01 KST
        secnews.run(cfg, self.state, self.sender, now=monday, fetcher=fetch, alert=alerts.append)
        secnews.run(cfg, self.state, self.sender, now=monday + timedelta(hours=1), fetcher=fetch,
                    alert=alerts.append)
        reports = [a for a in alerts if "주간 리포트" in a]
        self.assertEqual(len(reports), 1)
        self.assertIn("발송 1건", reports[0])
        self.assertIn("0건인 출처: Quiet feed", reports[0])
        self.assertEqual(secnews.load_state(self.state)["stats"]["runs"], 1)  # counting starts again
        review = json.loads((self.state.parent / "reviews" / "2026-W43.json").read_text("utf-8"))
        self.assertEqual(review["numbers"]["sent"], 1)
        self.assertEqual(review["items"], [["sent", "Zero-day actively exploited in router", "F", False, ""]])
        self.assertEqual(secnews.load_state(self.state)["stats"]["review"], {})  # a new week starts empty

    def test_review_snapshot_writes_the_week_so_far_and_sends_nothing(self):
        cfg = dict(CONFIG, feeds=[{"name": "F", "url": "f"}])
        d = "Wed, 15 Oct 2026 01:00:00 +0000"
        secnews.run(cfg, self.state, self.sender, now=NOW, fetcher=lambda u: self.rss(("Zero-day actively exploited in router", d)),
                    bootstrap_send=True)
        before = self.state.read_text("utf-8")
        with mock.patch.dict(os.environ, {"SECNEWS_STATE": str(self.state)}):
            secnews.main(["--write-review", "--config", str(Path(__file__).with_name("test_feeds.json"))])
        (snap,) = (self.state.parent / "reviews").glob("snapshot-*.json")
        self.assertEqual(json.loads(snap.read_text("utf-8"))["items"][0][1], "Zero-day actively exploited in router")
        self.assertEqual(self.state.read_text("utf-8"), before)

    def test_story_sent_earlier_is_not_sent_again_from_another_outlet(self):
        cfg = dict(CONFIG, feeds=[{"name": "F", "url": "f"}])
        d = "Wed, 15 Oct 2026 01:00:00 +0000"
        first = self.rss(("China-Linked Hackers Exploit BeyondTrust Zero-Day (CVE-2026-102764)", d))
        later = self.rss(("Chinese APT Exploits BeyondTrust Vulnerability as Zero-Day", d),
                         ("[KEV] CVE-2026-102764 BeyondTrust Remote Support auth bypass", d),
                         ("Burger King Japan data breach exposes customer records", d))
        secnews.run(cfg, self.state, self.sender, now=NOW, fetcher=lambda u: first, bootstrap_send=True)
        sent = secnews.run(cfg, self.state, self.sender, now=NOW + timedelta(hours=1),
                           fetcher=lambda u: later)
        self.assertEqual([i["title"] for i in sent], ["Burger King Japan data breach exposes customer records"])

    def test_focus_story_with_its_own_security_angle_passes_a_security_only_feed(self):
        cfg = dict(CONFIG, feeds=[{"name": "Wire", "url": "w", "security_only": True}])
        cfg["keywords"] = dict(CONFIG["keywords"], focus_security=list(CONFIG["keywords"].get("focus_security", [])) + ["출입금지"])
        d = "Wed, 15 Oct 2026 01:00:00 +0000"
        feed = self.rss(("공항, 외국산 카메라 차량 출입금지", d), ("공항 개항 기념 행사 열려", d))
        sent = secnews.run(cfg, self.state, self.sender, now=NOW, fetcher=lambda u: feed, bootstrap_send=True)
        self.assertEqual([i["title"] for i in sent], ["공항, 외국산 카메라 차량 출입금지"])

    def test_focus_news_without_a_security_angle_is_left_out(self):
        cfg = dict(CONFIG, feeds=[{"name": "F", "url": "f"}])
        d = "Wed, 15 Oct 2026 01:00:00 +0000"
        feed = self.rss(("'광명동굴 빛 축제' 개막…드론 1천 대 라이트쇼", d),
                        ("인천공항 비상 대응 훈련 실시", d),
                        ("항공사 기밀 유출 혐의 직원 구속", d))
        sent = secnews.run(cfg, self.state, self.sender, now=NOW, fetcher=lambda u: feed, bootstrap_send=True)
        self.assertEqual([i["title"] for i in sent], ["항공사 기밀 유출 혐의 직원 구속"])

    def test_urgent_needs_a_critical_keyword(self):
        scorer = secnews.Scorer(CONFIG["keywords"])
        pr = {"title": "보안 기업, 해킹 대응 AI 사이버 보안 솔루션 출시", "summary": "랜섬웨어 악성코드 피싱 탐지"}
        self.assertEqual(scorer.classify(pr), 2)
        self.assertGreaterEqual(scorer.classify({"title": "Zero-day actively exploited"}), 3)
        self.assertGreaterEqual(scorer.classify({"title": "[KEV] x", "base_score": 3}), 3)

    def test_kev_entry_dropped_when_the_news_already_reports_the_exploit(self):
        kev = {"id": "kev:CVE-1", "vendor": "BeyondTrust", "title": "[KEV] CVE-1 BeyondTrust RS"}
        self.assertTrue(secnews.kev_covered(kev, ["BeyondTrust patches zero-day exploited in attacks"]))
        self.assertFalse(secnews.kev_covered(kev, ["BeyondTrust opens new office"]))
        self.assertFalse(secnews.kev_covered(dict(kev, id="news"), ["BeyondTrust zero-day"]))

    def test_passing_mention_in_summary_does_not_make_a_story_a_focus_story(self):
        scorer = secnews.Scorer(CONFIG["keywords"])
        item = {"title": "Cisco email gateway flaw exploited",
                "summary": "Used by banks and airline customers"}
        scorer.classify(item)
        self.assertFalse(item["focus"])

    def test_feed_dated_hours_ahead_is_pulled_back(self):
        cfg = dict(CONFIG, feeds=[{"name": "F", "url": "f"}])
        feed = self.rss(("랜섬웨어 피해 기업 늘어", "Wed, 15 Oct 2026 11:00:00 +0000"))  # KST stamped as GMT
        sent = secnews.run(cfg, self.state, self.sender, now=NOW, fetcher=lambda u: feed, bootstrap_send=True)
        self.assertEqual(sent[0]["date"], datetime(2026, 10, 15, 2, 0, tzinfo=timezone.utc))

    def test_gemini_classification_drops_reclassifies_and_sets_urgency(self):
        cfg = dict(CONFIG, feeds=[{"name": "F", "url": "f"}], sectors={"금융": ["bank"]},
                   focus_sectors={"항공사": ["airline"]})
        d = "Wed, 15 Oct 2026 01:00:00 +0000"
        feed = self.rss(("Security vendor announces partnership, hackers beware", d),
                        ("Bank data breach exposes customers", d),
                        ("Malware campaign hits airline suppliers", d))
        answers = {"Security vendor announces partnership, hackers beware": dict(relevant=False),
                   "Bank data breach exposes customers": dict(relevant=True, focus=False, urgent=True,
                                                              sector="금융", focus_sector="기타"),
                   "Malware campaign hits airline suppliers": dict(relevant=True, focus=True, urgent=False,
                                                                   sector="기타", focus_sector="항공사")}
        saved = secnews.gemini_classify
        secnews.gemini_classify = lambda items, *a: [answers[it["title"]] for it in items]
        try:
            sent = secnews.run(cfg, self.state, self.sender, now=NOW, fetcher=lambda u: feed,
                               bootstrap_send=True, classify=secnews.GeminiClassifier("k", cfg))
        finally:
            secnews.gemini_classify = saved
        by_title = {i["title"]: i for i in sent}
        self.assertNotIn("Security vendor announces partnership, hackers beware", by_title)
        bank, mal = by_title["Bank data breach exposes customers"], by_title["Malware campaign hits airline suppliers"]
        self.assertGreaterEqual(bank["score"], 3)
        self.assertEqual(bank["sectors"], ["금융"])
        self.assertTrue(mal["focus"])
        self.assertEqual(mal["focus_sectors"], ["항공사"])
        self.assertLess(mal["score"], 3)

    def test_digest_waits_while_gemini_is_overloaded(self):
        cfg = dict(CONFIG, feeds=[{"name": "F", "url": "f"}])
        feed = self.rss(("Zero-day actively exploited in router", "Wed, 15 Oct 2026 01:00:00 +0000"))
        secnews.run(cfg, self.state, self.sender, now=NOW, fetcher=lambda u: self.rss(), bootstrap_send=True)
        broken = secnews.GeminiClassifier("k", cfg)
        saved = secnews.gemini_classify
        secnews.gemini_classify = lambda *a, **k: (_ for _ in ()).throw(OSError("503"))
        try:
            top = NOW.replace(minute=0) + timedelta(hours=1)
            alerts = []
            self.assertEqual(secnews.run(cfg, self.state, self.sender, now=top + timedelta(minutes=1),
                                         fetcher=lambda u: feed, classify=broken, alert=alerts.append), [])
            self.assertEqual(self.sent, [])  # waits once; the items stay new
            self.assertTrue(alerts and alerts[0].startswith("⏳"))  # and the admin hears why
            self.assertEqual(secnews.run(cfg, self.state, self.sender, now=top + timedelta(minutes=6),
                                         fetcher=lambda u: feed, classify=broken, alert=alerts.append), [])
            self.assertIn("다음 정기 발송에 함께", alerts[-1])  # never sent on keywords alone
            calls = []
            secnews.run(cfg, self.state, self.sender, now=top + timedelta(minutes=11),
                        fetcher=lambda u: calls.append(u) or feed, classify=broken, alert=alerts.append)
            self.assertEqual(self.sent, [])  # the hour is given up: no third try
        finally:
            secnews.gemini_classify = saved
        # Next hour, Gemini back: the held news goes out.
        sent = secnews.run(cfg, self.state, self.sender, now=top + timedelta(hours=1, minutes=1),
                           fetcher=lambda u: feed, classify=lambda items, told=(): items)
        self.assertEqual(len(sent), 1)

    def test_admin_hears_when_a_digest_has_nothing_to_send(self):
        cfg = dict(CONFIG, feeds=[{"name": "F", "url": "f"}], no_news_notice="admin")
        secnews.run(cfg, self.state, self.sender, now=NOW, fetcher=lambda u: self.rss(), bootstrap_send=True)
        alerts = []
        quiet = self.rss(("Company opens new office", "Wed, 15 Oct 2026 01:00:00 +0000"))
        secnews.run(cfg, self.state, self.sender, now=NOW.replace(minute=0) + timedelta(hours=1),
                    fetcher=lambda u: quiet, alert=alerts.append)
        self.assertEqual(self.sent, [])  # subscribers get nothing
        self.assertTrue(any(a.startswith("📭") and "새 기사 1건 중 보낼 기사 없음" in a for a in alerts))

    def test_later_requests_see_stories_kept_by_earlier_ones(self):
        items = [dict(title=f"Airline breach {n}", summary="", score=2, focus=False) for n in range(3)]
        seen = []

        def fake(part, key, model, sectors, fsectors, told=(), *rest):
            seen.append(list(told))
            return [dict(relevant=True, focus=False, urgent=False, story=f"airline {it['title'][-1]} breach")
                    for it in part]
        saved = secnews.gemini_classify
        secnews.gemini_classify = fake
        try:
            secnews.GeminiClassifier("k", CONFIG, chunk=2)(items, ["Old story"])
        finally:
            secnews.gemini_classify = saved
        self.assertEqual(seen[0], ["Old story"])
        self.assertEqual(seen[1], ["Old story", "Airline breach 0 (airline 0 breach)", "Airline breach 1 (airline 1 breach)"])

    def test_same_story_lines_are_one_story(self):
        self.assertTrue(secnews.same_story({"story": "gitlab ce ee rce patched"},
                                           {"story": "gitlab ce ee critical flaw fixed"}))
        self.assertFalse(secnews.same_story({"story": "fortinet fortiweb rce"}, {"story": "fortinet fortios rce"}))
        self.assertFalse(secnews.same_story({"story": "capcom account data breach"},
                                            {"story": "nol universe data breach"}))

    def test_items_past_the_gemini_limit_are_dropped_unless_gemini_failed(self):
        items = [dict(title=f"Airline breach {n}", summary="", score=2, focus=False) for n in range(3)]
        saved = secnews.gemini_classify
        secnews.gemini_classify = lambda part, *a: [dict(relevant=True, focus=False, urgent=False) for _ in part]
        try:
            kept = secnews.GeminiClassifier("k", CONFIG, limit=2)(items)
        finally:
            secnews.gemini_classify = saved
        self.assertEqual([i["title"] for i in kept], ["Airline breach 0", "Airline breach 1"])
        self.assertEqual(items[2]["drop_reason"], "gemini_limit")

    def test_forced_item_survives_an_off_topic_verdict_but_not_a_duplicate_one(self):
        cfg = dict(CONFIG, feeds=[{"name": "Topic", "url": "f", "focus_only": True}])
        cfg["keywords"] = dict(CONFIG["keywords"], always_urgent=["공항보안단"])
        d = "Wed, 15 Oct 2026 01:00:00 +0000"
        feed = self.rss(("공항보안단 신임 단장 취임", d), ("공항보안단 감사 착수, 근무자 휴대폰 확인", d))
        answers = {"공항보안단 신임 단장 취임": dict(relevant=False, focus=False, urgent=False),
                   "공항보안단 감사 착수, 근무자 휴대폰 확인": dict(relevant=True, focus=True, duplicate=True)}
        saved = secnews.gemini_classify
        secnews.gemini_classify = lambda items, *a: [answers[it["title"]] for it in items]
        try:
            sent = secnews.run(cfg, self.state, self.sender, now=NOW, fetcher=lambda u: feed,
                               bootstrap_send=True, classify=secnews.GeminiClassifier("k", cfg))
        finally:
            secnews.gemini_classify = saved
        self.assertEqual([(i["title"], i["score"] >= 3) for i in sent], [("공항보안단 신임 단장 취임", True)])

    def test_gemini_drops_same_story_in_other_language_and_stories_already_sent(self):
        cfg = dict(CONFIG, feeds=[{"name": "F", "url": "f"}])
        d = "Wed, 15 Oct 2026 01:00:00 +0000"
        first = self.rss(("Zero-day actively exploited in BeyondTrust", d))
        later = self.rss(("BeyondTrust 제로데이 실제 악용", d), ("Burger King Japan breach exposes records", d),
                         ("버거킹재팬 회원 정보 유출", d))
        seen_told = []

        def fake(items, key, model, sectors, fsectors, told=(), instructions=None, lite_first=False):
            seen_told.append(list(told))
            out = []
            for n, it in enumerate(items):
                r = dict(relevant=True, focus=False, urgent=False, sector="기타", focus_sector="기타",
                         dup_of=None, already_sent=False, story="")
                if "BeyondTrust" in it["title"]:
                    r.update(story="beyondtrust zero-day exploited", already_sent=bool(told))
                if "버거킹" in it["title"]:
                    r["dup_of"] = [i for i, x in enumerate(items) if "Burger" in x["title"]][0]
                out.append(r)
            return out
        saved = secnews.gemini_classify
        secnews.gemini_classify = fake
        try:
            secnews.run(cfg, self.state, self.sender, now=NOW, fetcher=lambda u: first, bootstrap_send=True,
                        classify=secnews.GeminiClassifier("k", cfg))
            sent = secnews.run(cfg, self.state, self.sender, now=NOW + timedelta(hours=1), fetcher=lambda u: later,
                               classify=secnews.GeminiClassifier("k", cfg))
        finally:
            secnews.gemini_classify = saved
        titles = [i["title"] for i in sent]
        self.assertEqual(len(titles), 1)  # one Burger King report; BeyondTrust went out last hour
        self.assertTrue("Burger" in titles[0] or "버거킹" in titles[0])
        self.assertEqual(seen_told[1], ["Zero-day actively exploited in BeyondTrust (beyondtrust zero-day exploited)"])

    def test_gemini_classification_failure_keeps_keyword_results(self):
        cfg = dict(CONFIG, feeds=[{"name": "F", "url": "f"}])
        feed = self.rss(("Zero-day actively exploited", "Wed, 15 Oct 2026 01:00:00 +0000"))
        saved = secnews.gemini_classify

        def broken(*a):
            raise OSError("429")
        secnews.gemini_classify = broken
        try:
            # A manual run (force: the admin's test or "send now") still goes out on keyword results;
            # timer runs wait for Gemini instead (test_digest_waits_while_gemini_is_overloaded).
            sent = secnews.run(cfg, self.state, self.sender, now=NOW + timedelta(minutes=35),
                               fetcher=lambda u: feed, bootstrap_send=True, force=True,
                               classify=secnews.GeminiClassifier("k", cfg))
        finally:
            secnews.gemini_classify = saved
        self.assertEqual([i["title"] for i in sent], ["Zero-day actively exploited"])

    def test_owner_is_told_once_when_a_feed_keeps_failing(self):
        cfg = dict(CONFIG, feeds=[{"name": "Broken", "url": "broken"}, {"name": "F", "url": "f"}])
        feed = self.rss(("Zero-day actively exploited", "Wed, 15 Oct 2026 01:00:00 +0000"))

        def fetcher(url):
            if url == "broken":
                raise OSError("404")
            return feed
        alerts = []
        for hour in range(5):
            secnews.run(cfg, self.state, self.sender, now=NOW + timedelta(hours=hour), fetcher=fetcher,
                        bootstrap_send=True, alert=alerts.append)
        self.assertEqual(len(alerts), 1)
        self.assertIn("Broken", alerts[0])

    def test_quiet_hours_and_morning(self):
        cfg = {"quiet_hours": [22, 6], "digest_on_the_hour": True}
        at = lambda h: datetime(2026, 10, 17, h, 0, tzinfo=secnews.KST)
        self.assertEqual([secnews.quiet(cfg, at(h)) for h in (21, 22, 2, 5, 6)], [False, True, True, True, False])
        self.assertTrue(secnews.morning(cfg, at(6)))
        self.assertFalse(secnews.due({"last_digest": at(21).timestamp()}, cfg, at(23)))
        self.assertTrue(secnews.due({"last_digest": at(21).timestamp()}, cfg, at(6) + timedelta(days=1)))

    def instant_setup(self):
        cfg = dict(CONFIG, quiet_hours=[22, 6], digest_on_the_hour=True,
                   feeds=[{"name": "Fast", "url": "fast", "instant": True}])
        cfg["keywords"] = dict(CONFIG["keywords"], instant=["zero-day", "actively exploited"])
        calls = []

        def sender(text, silent=False):
            calls.append((text, silent))
            return True
        return cfg, calls, sender

    def test_instant_alert_goes_out_between_digests_and_not_again(self):
        cfg, calls, sender = self.instant_setup()
        start = datetime(2026, 10, 17, 10, 0, tzinfo=secnews.KST)
        stamp = lambda dt: dt.astimezone(timezone.utc).strftime("%a, %d %b %Y %H:%M:%S +0000")
        quiet_feed = self.rss(("Weekly security recap", stamp(start)))
        secnews.run(cfg, self.state, sender, now=start, fetcher=lambda u: quiet_feed, bootstrap_send=True)
        # 10:05 first instant check only records what is there.
        secnews.run(cfg, self.state, sender, now=start + timedelta(minutes=5), fetcher=lambda u: quiet_feed)
        calls.clear()
        hot = self.rss(("Chrome zero-day actively exploited", stamp(start + timedelta(minutes=8))),
                       ("New ransomware report", stamp(start + timedelta(minutes=8))))
        sent = secnews.run(cfg, self.state, sender, now=start + timedelta(minutes=10), fetcher=lambda u: hot)
        self.assertEqual([i["title"] for i in sent], ["Chrome zero-day actively exploited"])
        self.assertIn("긴급 보안 속보", calls[0][0])
        self.assertFalse(calls[0][1])  # daytime: with sound
        calls.clear()
        # 11:00 digest: the ransomware report goes, the zero-day does not go twice.
        sent = secnews.run(cfg, self.state, sender, now=start + timedelta(hours=1), fetcher=lambda u: hot)
        self.assertEqual([i["title"] for i in sent], ["New ransomware report"])

    def test_story_sent_as_ordinary_news_still_gets_its_alert_when_it_turns_urgent(self):
        cfg, calls, sender = self.instant_setup()
        start = datetime(2026, 10, 17, 10, 0, tzinfo=secnews.KST)
        stamp = lambda dt: dt.astimezone(timezone.utc).strftime("%a, %d %b %Y %H:%M:%S +0000")
        notice = self.rss(("Airline booking platform schedules release for two critical vulnerabilities",
                           stamp(start)))
        sent = secnews.run(cfg, self.state, sender, now=start, fetcher=lambda u: notice, bootstrap_send=True)
        self.assertEqual(len(sent), 1)
        self.assertFalse(secnews.load_state(self.state)["recent"][0][4])  # went out as ordinary news
        secnews.run(cfg, self.state, sender, now=start + timedelta(minutes=5), fetcher=lambda u: notice)
        calls.clear()
        later = self.rss(("Airline booking platform releases critical patches for two zero-day vulnerabilities",
                          stamp(start + timedelta(minutes=8))))
        sent = secnews.run(cfg, self.state, sender, now=start + timedelta(minutes=10), fetcher=lambda u: later)
        self.assertEqual(len(sent), 1)
        self.assertIn("긴급 보안 속보", calls[0][0])
        # Once sent as urgent, another outlet's take on it is not sent again.
        again = self.rss(("Airline booking platform patches two zero-day vulnerabilities, update now",
                          stamp(start + timedelta(minutes=13))))
        sent = secnews.run(cfg, self.state, sender, now=start + timedelta(minutes=15), fetcher=lambda u: again)
        self.assertEqual(sent, [])

    def test_critical_word_in_the_headline_is_an_alert_candidate(self):
        cfg, calls, sender = self.instant_setup()
        start = datetime(2026, 10, 17, 10, 0, tzinfo=secnews.KST)
        stamp = lambda dt: dt.astimezone(timezone.utc).strftime("%a, %d %b %Y %H:%M:%S +0000")
        empty = self.rss(("Weekly security recap", stamp(start)))
        secnews.run(cfg, self.state, sender, now=start, fetcher=lambda u: empty, bootstrap_send=True)
        secnews.run(cfg, self.state, sender, now=start + timedelta(minutes=5), fetcher=lambda u: empty)
        hot = self.rss(("Critical unauthenticated RCE flaw in airport kiosk software", stamp(start + timedelta(minutes=8))))
        asked = []

        def gemini(items, told=()):
            asked.extend(it["title"] for it in items)
            return []  # judged not urgent: nothing goes out now, the digest decides later
        sent = secnews.run(cfg, self.state, sender, now=start + timedelta(minutes=10), fetcher=lambda u: hot,
                           classify=gemini)
        self.assertEqual(asked, ["Critical unauthenticated RCE flaw in airport kiosk software"])
        self.assertEqual(sent, [])

    def test_feed_marked_instant_all_has_every_security_item_judged(self):
        cfg, calls, sender = self.instant_setup()
        cfg["feeds"] = [{"name": "Topic search", "url": "fast", "instant": "all"}]
        start = datetime(2026, 10, 17, 10, 0, tzinfo=secnews.KST)
        stamp = lambda dt: dt.astimezone(timezone.utc).strftime("%a, %d %b %Y %H:%M:%S +0000")
        empty = self.rss(("Weekly security recap", stamp(start)))
        secnews.run(cfg, self.state, sender, now=start, fetcher=lambda u: empty, bootstrap_send=True)
        secnews.run(cfg, self.state, sender, now=start + timedelta(minutes=5), fetcher=lambda u: empty)
        calls.clear()
        new = self.rss(("공항 관제 시스템 해킹 피해 확인", stamp(start + timedelta(minutes=8))),
                       ("공항 개항 기념 행사 열려", stamp(start + timedelta(minutes=8))))
        asked = []

        def gemini(items, told=()):
            asked.extend(it["title"] for it in items)
            for it in items:
                it["score"] = 3  # Gemini: urgent
            return items
        sent = secnews.run(cfg, self.state, sender, now=start + timedelta(minutes=10), fetcher=lambda u: new,
                           classify=gemini)
        self.assertEqual(asked, ["공항 관제 시스템 해킹 피해 확인"])  # no security word, not asked
        self.assertEqual([i["title"] for i in sent], ["공항 관제 시스템 해킹 피해 확인"])

    def test_large_breach_headline_is_an_alert_candidate(self):
        cfg, calls, sender = self.instant_setup()
        start = datetime(2026, 10, 17, 10, 0, tzinfo=secnews.KST)
        stamp = lambda dt: dt.astimezone(timezone.utc).strftime("%a, %d %b %Y %H:%M:%S +0000")
        empty = self.rss(("Weekly security recap", stamp(start)))
        secnews.run(cfg, self.state, sender, now=start, fetcher=lambda u: empty, bootstrap_send=True)
        secnews.run(cfg, self.state, sender, now=start + timedelta(minutes=5), fetcher=lambda u: empty)
        calls.clear()
        hot = self.rss(("항공사 예약 사이트 해킹…371만건 개인정보 유출", stamp(start + timedelta(minutes=8))),
                       ("항공사 회원 1,014명 개인정보 유출", stamp(start + timedelta(minutes=8))))
        asked = []

        def gemini(items, told=()):
            asked.extend(it["title"] for it in items)
            for it in items:
                it["score"] = 3
            return items
        sent = secnews.run(cfg, self.state, sender, now=start + timedelta(minutes=10), fetcher=lambda u: hot,
                           classify=gemini)
        self.assertEqual(asked, ["항공사 예약 사이트 해킹…371만건 개인정보 유출"])
        self.assertEqual(len(sent), 1)
        # Without Gemini a keyword-only guess about scale never goes out as an alert.
        self.assertFalse(secnews.SCALE.search("항공사 회원 1,014명 개인정보 유출"))

    def test_always_urgent_keyword_goes_out_as_an_alert_whatever_gemini_says(self):
        cfg, calls, sender = self.instant_setup()
        cfg["keywords"] = dict(cfg["keywords"], always_urgent=["공항보안단"])
        start = datetime(2026, 10, 17, 10, 0, tzinfo=secnews.KST)
        stamp = lambda dt: dt.astimezone(timezone.utc).strftime("%a, %d %b %Y %H:%M:%S +0000")
        empty = self.rss(("Weekly security recap", stamp(start)))
        secnews.run(cfg, self.state, sender, now=start, fetcher=lambda u: empty, bootstrap_send=True)
        secnews.run(cfg, self.state, sender, now=start + timedelta(minutes=5), fetcher=lambda u: empty)
        calls.clear()
        # Published five hours ago (searches lag): still in time for a forced alert.
        news = self.rss(("공항보안단, 터미널 근무자 대상 이례적 감사", stamp(start - timedelta(hours=5))),
                        ("공항 개항 기념 행사 열려", stamp(start + timedelta(minutes=8))))

        def gemini(items, told=()):
            for it in items:
                if not it.get("forced"):
                    it["score"] = 3
            return [it for it in items if it.get("forced")]  # Gemini: not relevant, not urgent
        sent = secnews.run(cfg, self.state, sender, now=start + timedelta(minutes=10), fetcher=lambda u: news,
                           classify=gemini)
        self.assertEqual([i["title"] for i in sent], ["공항보안단, 터미널 근무자 대상 이례적 감사"])
        self.assertIn("긴급 보안 속보", calls[0][0])
        # The same story from another outlet does not go again.
        again = self.rss(("공항보안단 이례적 감사…근무자 휴대폰 확인", stamp(start + timedelta(minutes=13))))
        sent = secnews.run(cfg, self.state, sender, now=start + timedelta(minutes=15), fetcher=lambda u: again,
                           classify=lambda items, told=(): [])
        self.assertEqual(sent, [])

    def test_instant_alert_is_silent_at_night(self):
        cfg, calls, sender = self.instant_setup()
        night = datetime(2026, 10, 17, 23, 0, tzinfo=secnews.KST)
        stamp = lambda dt: dt.astimezone(timezone.utc).strftime("%a, %d %b %Y %H:%M:%S +0000")
        empty = self.rss(("Weekly security recap", stamp(night - timedelta(hours=2))))
        secnews.run(cfg, self.state, sender, now=night - timedelta(hours=2), fetcher=lambda u: empty, bootstrap_send=True)
        secnews.run(cfg, self.state, sender, now=night, fetcher=lambda u: empty)  # first instant check
        calls.clear()
        hot = self.rss(("Router zero-day actively exploited", stamp(night)))
        sent = secnews.run(cfg, self.state, sender, now=night + timedelta(minutes=5), fetcher=lambda u: hot)
        self.assertEqual(len(sent), 1)
        self.assertTrue(calls[0][1])

    def test_last_message_of_a_round_shows_the_funnel(self):
        mil = dict(CONFIG, max_items_per_run=1, max_focus_per_run=5, feeds=[{"name": "F", "url": "f"}])
        feed = self.rss(("Ransomware hits hospital", "Wed, 15 Oct 2026 01:00:00 +0000"),
                        ("Zero-day exploited", "Wed, 15 Oct 2026 01:00:00 +0000"),
                        ("Airport networks targeted by hackers", "Wed, 15 Oct 2026 01:00:00 +0000"),
                        ("Company opens new office", "Wed, 15 Oct 2026 01:00:00 +0000"))
        secnews.run(mil, self.state, self.sender, now=NOW, fetcher=lambda u: feed, bootstrap_send=True)
        self.assertNotIn("📊", self.sent[0])
        self.assertIn("📊 새 기사 4건 중 2건 통과", self.sent[-1])

    def test_focus_is_a_separate_message_with_its_own_cap(self):
        mil = dict(CONFIG, max_items_per_run=1, max_focus_per_run=5)
        feed = (b'<?xml version="1.0"?><rss version="2.0"><channel>'
                b'<item><title>Ransomware hits hospital</title><link>https://e/1</link>'
                b'<pubDate>Wed, 15 Oct 2026 01:00:00 +0000</pubDate></item>'
                b'<item><title>Zero-day exploited</title><link>https://e/2</link>'
                b'<pubDate>Wed, 15 Oct 2026 01:00:00 +0000</pubDate></item>'
                b'<item><title>Airport networks targeted by hackers</title><link>https://e/3</link>'
                b'<pubDate>Wed, 15 Oct 2026 01:00:00 +0000</pubDate></item></channel></rss>')
        mil["feeds"] = [{"name": "F", "url": "f"}]
        sent = secnews.run(mil, self.state, self.sender, now=NOW, fetcher=lambda u: feed, bootstrap_send=True)
        self.assertEqual(len(self.sent), 2)
        self.assertIn("중점 보안 속보", self.sent[0])
        self.assertIn("Airport", self.sent[0])
        self.assertIn("🛡 <b>보안 속보</b>", self.sent[1])
        self.assertEqual(len(sent), 2)  # general capped at 1, plus the focus item

    def test_ransomware_digest_and_title_dedupe(self):
        cfg = dict(CONFIG, max_ransomware_per_run=10, ransomware_countries=["KR"], ransomware_sectors=["aviation"])
        dup = (b'<?xml version="1.0"?><rss version="2.0"><channel>'
               b'<item><title>Zero-day in Fortinet exploited</title><link>https://news/1</link>'
               b'<pubDate>Wed, 15 Oct 2026 01:00:00 +0000</pubDate></item></channel></rss>')
        cfg["feeds"] = [{"name": "N", "url": "n"}, {"name": "TG", "url": "t", "type": "telegram", "security_only": True},
                        {"name": "rw", "url": "r", "type": "ransomware"}]
        pages = {"n": dup, "t": TG_PAGE, "r": RW_RECENT}
        sent = secnews.run(cfg, self.state, self.sender, now=NOW, fetcher=pages.get, bootstrap_send=True)
        titles = [i["title"] for i in sent]
        self.assertEqual(sum("Fortinet" in t for t in titles), 1)  # same headline from RSS and Telegram
        self.assertTrue(any("한국전자" in t for t in titles))
        self.assertTrue(any("acme-airlines" in t for t in titles))
        self.assertFalse(any("bakery" in t for t in titles))
        self.assertIn("랜섬웨어·유출 동향", self.sent[-1])
        self.assertLess(self.sent[-1].index("한국전자"), self.sent[-1].index("acme-airlines"))

    def test_focus_only_feed_drops_general_items(self):
        cfg = dict(CONFIG)
        feed = (b'<?xml version="1.0"?><rss version="2.0"><channel>'
                b'<item><title>Agency earns ISO privacy certification - Paper</title><link>https://g/1</link>'
                b'<pubDate>Wed, 15 Oct 2026 01:00:00 +0000</pubDate></item>'
                b'<item><title>Airport networks hit by data breach - Paper</title><link>https://g/2</link>'
                b'<pubDate>Wed, 15 Oct 2026 01:00:00 +0000</pubDate></item></channel></rss>')
        cfg["feeds"] = [{"name": "G", "url": "g", "type": "google_news", "focus_only": True}]
        sent = secnews.run(cfg, self.state, self.sender, now=NOW, fetcher=lambda u: feed, bootstrap_send=True)
        self.assertEqual([i["title"] for i in sent], ["Airport networks hit by data breach"])

    def test_digest_interval(self):
        cfg = dict(CONFIG, digest_interval_minutes=90)
        run = lambda t, **kw: secnews.run(cfg, self.state, self.sender, now=t, fetcher=fake_fetch, **kw)
        self.assertEqual(len(run(NOW, bootstrap_send=True)), 4)
        self.state.write_text(json.dumps({"seen": {}, "last_digest": NOW.timestamp()}))
        self.assertEqual(run(NOW + timedelta(minutes=75)), [])  # too early: nothing collected or sent
        self.assertEqual(json.loads(self.state.read_text())["seen"], {})
        self.assertEqual(len(run(NOW + timedelta(minutes=75), force=True)), 4)
        self.state.write_text(json.dumps({"seen": {}, "last_digest": NOW.timestamp()}))
        self.assertEqual(len(run(NOW + timedelta(minutes=89, seconds=30))), 4)  # 15-minute timer slack

    def test_failed_delivery_keeps_items_for_retry(self):
        self.run_once()
        self.state.write_text(json.dumps({"seen": {}}))
        with self.assertRaises(secnews.TelegramError):
            secnews.run(CONFIG, self.state, lambda t: False, now=NOW, fetcher=fake_fetch)
        self.assertEqual(len(self.run_once()), 4)

    def test_tracking_params_dedup(self):
        a = {"id": "x", "link": "http://Example.com/a/?utm_source=rss"}
        b = {"id": "y", "link": "https://example.com/a"}
        self.assertEqual(secnews.item_key(a), secnews.item_key(b))


class SectorTests(unittest.TestCase):
    def setUp(self):
        sectors = json.loads(Path(__file__).with_name("test_feeds.json").read_text("utf-8"))["sectors"]
        self.tagger = secnews.SectorTagger(sectors)

    def tags(self, title, **extra):
        return self.tagger.tag(dict(title=title, **extra))

    def test_tags(self):
        self.assertEqual(self.tags("AI해킹, 금융사 16곳서 개인정보 10만건 유출"), ["금융", "AI"])
        self.assertEqual(self.tags("SKT 유심 해킹 후속 조치"), ["통신"])
        self.assertEqual(self.tags("Ransomware hits hospital chain"), ["의료"])
        self.assertEqual(self.tags("Jooan IP camera firmware RCE"), ["IoT"])
        self.assertEqual(self.tags("조선중앙통신 보도"), [])
        self.assertEqual(self.tags("acme.com — akira 랜섬웨어 피해 공개", sector="Financial Services"), ["금융"])

    def test_grouped_by_sector(self):
        base = {"link": "", "source": "s", "date": NOW, "summary": ""}
        items = [dict(base, title="bank", score=1, sectors=["금융"]),
                 dict(base, title="ai bank", score=5, sectors=["금융", "AI"]),
                 dict(base, title="misc", score=4, sectors=[]),
                 dict(base, title="hospital", score=2, sectors=["의료"])]
        (msg,) = secnews.build_messages(items, NOW, "T", sector_order=["금융", "의료", "AI"])
        self.assertLess(msg.index("💰 <b>금융</b> (2)"), msg.index("🏥 <b>의료</b> (1)"))
        self.assertLess(msg.index("의료"), msg.index("📌 <b>기타</b> (1)"))  # 기타 always last
        self.assertIn("🔹 🚨 #AI <b>ai bank</b>", msg)  # urgent mark, own sector tag hidden
        self.assertNotIn("긴급", msg)

    def test_focus_categories(self):
        cats = json.loads(Path(__file__).with_name("test_feeds.json").read_text("utf-8"))["focus_sectors"]
        tagger = secnews.SectorTagger(cats, key="focus_sectors")
        first = lambda t: tagger.tag({"title": t})[0]
        self.assertEqual(first("해커, 항공사 예약 시스템 공격"), "항공사")
        self.assertEqual(first("인천공항 출입 시스템 해킹 시도"), "공항")
        self.assertEqual(first("국토부, 항공 안전 보안 지침 발표"), "항공 정책·행사")

    def test_hashtags_in_message(self):
        item = {"title": "t", "link": "", "source": "s", "date": NOW, "score": 1, "sectors": ["금융", "AI"]}
        self.assertIn("🔹 #금융 #AI <b>t</b>", secnews.format_item(item))


class TrimTests(unittest.TestCase):
    def test_same_cve_and_cap(self):
        mk = lambda t: {"title": t}
        items = [mk("CVE-2026-12345 exploited"), mk("Patch for cve-2026-12345 out"), mk("Other news"), mk("More")]
        self.assertEqual([i["title"] for i in secnews.trim(items, 0)], ["CVE-2026-12345 exploited", "Other news", "More"])
        self.assertEqual(len(secnews.trim(items, 2)), 2)



    def test_similar_headlines_collapse(self):
        items = [{"title": t, "source": s} for t, s in [
            ("당국, AI 해킹 피해 금융사 16곳 파악…정보 유출 10만건", "A"),
            ("AI해킹, 금융사 16곳서 개인정보 10만건 유출", "B"),
            ("OK저축銀 \"해킹 정보유출 고객 규모 250명으로 늘어\"", "C"),
            ("FBI, 해킹·IT 조직 40여곳 급습 해체", "D")]]
        self.assertEqual([i["source"] for i in secnews.trim(items, 0)], ["A", "C", "D"])

    def test_per_source_cap(self):
        items = [{"title": f"a{i}", "source": "A"} for i in range(5)] + [{"title": "b", "source": "B"}]
        self.assertEqual([i["title"] for i in secnews.trim(items, 0, 2)], ["a0", "a1", "b"])

    def test_fallback_sector_only_when_no_industry_matches(self):
        tagger = secnews.SectorTagger({"의료": ["hospital"]}, fallback={"SW·취약점": ["rce", "flaw"]})
        self.assertEqual(tagger.tag({"title": "NGINX fixes RCE flaw"}), ["SW·취약점"])
        self.assertEqual(tagger.tag({"title": "Hospital RCE flaw"}), ["의료"])
        self.assertEqual(tagger.tag({"title": "Vendor acquired"}), [])

    def test_source_names_are_numbers_in_actions_logs(self):
        import os
        saved = os.environ.get("GITHUB_ACTIONS")
        try:
            os.environ["GITHUB_ACTIONS"] = "true"
            self.assertEqual(secnews.feed_label({"name": "Some outlet"}, 0), "source 1")
            del os.environ["GITHUB_ACTIONS"]
            self.assertEqual(secnews.feed_label({"name": "Some outlet"}, 0), "Some outlet")
        finally:
            if saved is not None:
                os.environ["GITHUB_ACTIONS"] = saved

    def test_split_post_drops_links_and_hashtags(self):
        title, rest = secnews.split_post("US indicts 14 ransomware suspects #Cybersecurity #DOJ "
                                         "http://dlvr.it/TVxZXY")
        self.assertEqual((title, rest), ("US indicts 14 ransomware suspects", ""))
        self.assertEqual(secnews.split_post("Patch out. Fixes C# bug.\n🔗 Read: https://t.co/x")[1], "Fixes C# bug.")

    def test_split_post_drops_leading_emoji(self):
        self.assertEqual(secnews.split_post("🚨 CVE-2026-12345\nIn the Linux kernel...")[0], "CVE-2026-12345")


class LocalizeTests(unittest.TestCase):
    def item(self, title, summary=""):
        return {"title": title, "summary": summary, "link": "https://e.com/x", "source": "S",
                "date": NOW, "score": 3, "focus": False}

    def with_fakes(self, gemini, test):
        saved = secnews.gemini_translate_batch, secnews.google_translate, secnews.time.sleep
        calls = {"gemini": 0, "google": []}

        def fake_gemini(texts, key, model):
            calls["gemini"] += 1
            return gemini(texts)

        def fake_google(text):
            calls["google"].append(text)
            return "구글:" + text

        secnews.gemini_translate_batch, secnews.google_translate = fake_gemini, fake_google
        secnews.time.sleep = lambda s: None
        try:
            test()
        finally:
            secnews.gemini_translate_batch, secnews.google_translate, secnews.time.sleep = saved
        return calls

    def test_gemini_translates_the_whole_digest_in_one_request(self):
        items = [self.item("Zero-day exploited", "Attackers are using the flaw to take over servers around the world."), self.item("New backdoor found")]
        calls = self.with_fakes(lambda texts: ["제미나이:" + t for t in texts],
                                lambda: secnews.localize(items, secnews.GeminiTranslator("k")))
        self.assertEqual(calls, {"gemini": 1, "google": []})
        self.assertEqual(items[0]["display_title"], "제미나이:Zero-day exploited")
        self.assertEqual(items[0]["display_summary"], "제미나이:Attackers are using the flaw to take over servers around the world.")

    def test_classifier_translation_is_used_without_another_request(self):
        item = self.item("Zero-day exploited", "Attackers are using the flaw to take over servers around the world.")
        item.update(title_ko="제로데이 악용", summary_ko="공격자들이 전 세계 서버를 장악하고 있다.")
        calls = self.with_fakes(lambda texts: self.fail("no translation request expected"),
                                lambda: secnews.localize([item], secnews.GeminiTranslator("k")))
        self.assertEqual(calls, {"gemini": 0, "google": []})
        self.assertEqual((item["display_title"], item["display_summary"]),
                         ("제로데이 악용", "공격자들이 전 세계 서버를 장악하고 있다."))

    def test_budget_ignores_used_up_marks_from_the_old_day_boundary(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "gemini_usage.json"
            day = secnews.GeminiBudget(path, [("flash", 2)]).day
            path.write_text(json.dumps({"day": day, "used": {"flash": 2}}), encoding="utf-8")  # no "v"
            self.assertEqual(secnews.GeminiBudget(path, [("flash", 2)]).take(), "flash")

    def test_budget_keeps_real_requests_per_model_for_the_admin(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "gemini_usage.json"
            budget = secnews.GeminiBudget(path, [("model-a", 2), ("model-b", 5)])
            budget.take(); budget.take(); budget.take()
            budget.exhaust("model-b")  # marked full, nothing sent
            again = secnews.GeminiBudget(path, [("model-a", 2), ("model-b", 5)])
            self.assertEqual(again.history[again.day], {"model-a": 2, "model-b": 1})
            lines = again.summary()
            self.assertIn("사용 3회", lines[0])
            self.assertIn("model-a: 2회 / 한도 2", lines[1])
            self.assertIn("model-b: 1회 / 한도 5", lines[2])

    def test_daily_budget_moves_to_the_next_model_then_stops(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "gemini_usage.json"
            budget = secnews.GeminiBudget(path, [("a", 2), ("b", 1)])
            self.assertEqual([budget.take() for _ in range(3)], ["a", "a", "b"])
            with self.assertRaises(RuntimeError):
                budget.take()
            self.assertEqual(secnews.GeminiBudget(path, [("a", 2), ("b", 1)]).used, {"a": 2, "b": 1})

    def test_model_out_of_quota_is_skipped_for_the_day(self):
        import io
        import urllib.error
        asked = []

        def fake_urlopen(req, timeout=None):
            model = req.full_url.split("/models/")[1].split(":")[0]
            asked.append(model)
            if model == "a":
                raise urllib.error.HTTPError(req.full_url, 429, "quota", {}, io.BytesIO(b"{}"))
            body = {"candidates": [{"content": {"parts": [{"text": "[\"ok\"]"}]}}]}
            return io.BytesIO(json.dumps(body).encode())

        with tempfile.TemporaryDirectory() as d:
            saved = secnews.GEMINI_BUDGET, secnews.urllib.request.urlopen
            secnews.GEMINI_BUDGET = secnews.GeminiBudget(Path(d) / "u.json", [("a", 5), ("b", 5)])
            secnews.urllib.request.urlopen = fake_urlopen
            try:
                self.assertEqual(secnews.gemini_json("p", "k"), ["ok"])
                self.assertEqual(secnews.gemini_json("p", "k"), ["ok"])
            finally:
                secnews.GEMINI_BUDGET, secnews.urllib.request.urlopen = saved
        self.assertEqual(asked, ["a", "b", "b"])

    def test_gemini_failure_falls_back_to_google(self):
        items = [self.item("Zero-day exploited")]

        def broken(texts):
            raise OSError("429 quota")
        calls = self.with_fakes(broken, lambda: secnews.localize(items, secnews.GeminiTranslator("k")))
        self.assertEqual(calls["google"], ["Zero-day exploited"])
        self.assertEqual(items[0]["display_title"], "구글:Zero-day exploited")

    def test_article_shows_which_ai_judged_it(self):
        self.assertEqual(secnews.model_label("gemini-3.8-flash"), "Gemini 3.8 Flash")
        self.assertEqual(secnews.model_label("gemini-3.5-flash-lite-preview-09-2026"), "Gemini 3.5 Flash Lite Preview")
        it = {"title": "Airline breach", "summary": "", "link": "https://e/x", "source": "S", "date": None,
              "score": 2, "ai_model": "gemini-3.6-flash"}
        self.assertIn("🤖 Gemini 3.6 Flash", secnews.format_item(it))
        it.pop("ai_model")
        self.assertNotIn("🤖", secnews.format_item(it))

    def test_korean_item_is_not_marked_as_translated(self):
        it = {"title": "[단독] 공항 관제망 사이버공격 5년간 7.5만건", "summary": "", "link": "https://e/k",
              "title_ko": "Airport control network cyberattacks: 75,000 in five years", "summary_ko": ""}
        secnews.localize([it], None)
        self.assertEqual(it["display_title"], "[단독] 공항 관제망 사이버공격 5년간 7.5만건")
        self.assertFalse(it.get("translated"))

    def test_cve_named_only_in_the_summary_is_one_story(self):
        items = [{"title": "Critical airline booking engine flaw patched", "summary": "CVE-2026-1111 allows RCE.",
                  "source": "A"},
                 {"title": "Vendor says its firewall blocks the booking engine bug", "summary": "Covers CVE-2026-1111.",
                  "source": "B"}]
        self.assertEqual([i["source"] for i in secnews.trim(items, 10)], ["A"])

    def test_english_is_translated_and_link_kept(self):
        it = self.item("Hackers hit airport networks", "Attackers breached several systems used by the airport this week.")
        secnews.localize([it], lambda t: "번역:" + t)
        self.assertTrue(it["display_title"].startswith("번역:"))
        self.assertTrue(it["display_summary"].startswith("번역:"))
        text = secnews.format_item(it)
        self.assertIn('href="https://e.com/x"', text)
        self.assertIn("🌐 영문 기사", text)
        self.assertNotIn("translate.goog", text)  # Google's proxy is blocked in Korea
        self.assertIn("📰 출처: S", text)

    def test_summary_translated_even_when_title_is_an_id(self):
        it = self.item("CVE-2026-12345", "In the Linux kernel, the following vulnerability has been resolved: ipv6 fix.")
        secnews.localize([it], lambda t: "번역:" + t)
        self.assertEqual(it["display_title"], "CVE-2026-12345")
        self.assertTrue(it["display_summary"].startswith("번역:"))

    def test_korean_untouched_and_failure_falls_back(self):
        ko = self.item("공항 해킹 시도 포착")
        en = self.item("Zero-day in VPN")
        def boom(t):
            raise OSError("down")
        secnews.localize([ko, en], boom)
        self.assertEqual(ko["display_title"], "공항 해킹 시도 포착")
        self.assertEqual(en["display_title"], "Zero-day in VPN")
        self.assertNotIn("translated", en)


def upd(uid, chat, text=None, group_status=None):
    if group_status:
        return {"update_id": uid, "my_chat_member": {"chat": {"id": chat},
                                                     "new_chat_member": {"status": group_status}}}
    return {"update_id": uid, "message": {"chat": {"id": chat}, "text": text}}


class SubscriberTests(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.path = Path(self.dir.name) / "subscribers.json"
        self.key = secnews.subscriber_key("123:abc")
        self.sent = []

    def tearDown(self):
        self.dir.cleanup()

    def sync(self, updates):
        return secnews.sync_subscribers(self.path, updates, send=lambda c, t: self.sent.append((c, t)), key=self.key)

    def ids(self):
        return secnews.load_subscribers(self.path, self.key)["ids"]

    def approval_sync(self, updates):
        self.api_calls = getattr(self, "api_calls", [])
        return secnews.sync_subscribers(
            self.path, updates, key=self.key, admin="99",
            send=lambda c, t, m=None: self.sent.append((c, t, m)),
            api=lambda method, params: self.api_calls.append(method))

    @staticmethod
    def press(uid, data, who=99):
        return {"update_id": uid, "callback_query": {"id": f"q{uid}", "from": {"id": who}, "data": data,
                                                     "message": {"chat": {"id": 99}, "message_id": 5}}}

    def test_approval_request_then_approve(self):
        start = {"update_id": 1, "message": {"chat": {"id": 11, "first_name": "Kim", "username": "kim"},
                                             "text": "/start"}}
        self.assertEqual(self.approval_sync([start]), ([], []))
        self.assertEqual(self.ids(), [])
        self.assertEqual(self.sent[0][:2], ("11", secnews.REQUESTED))
        to_admin = self.sent[1]
        self.assertEqual(to_admin[0], "99")
        self.assertIn("Kim (@kim)", to_admin[1])
        self.assertEqual(to_admin[2]["inline_keyboard"][0][0]["callback_data"], "ok:11")
        self.sent.clear()
        self.assertEqual(self.approval_sync([self.press(2, "ok:11")]), (["11"], []))
        self.assertEqual(self.ids(), ["11"])
        self.assertIn(("11", secnews.TEXTS["welcome"], None), self.sent)
        self.assertIn("answerCallbackQuery", self.api_calls)
        self.assertIn("editMessageText", self.api_calls)

    @unittest.skipIf(secnews.AESGCM is None, "cryptography is not installed")
    def test_subscriber_file_is_aes_gcm_and_old_files_are_converted(self):
        saved = secnews.AESGCM
        secnews.AESGCM = None  # write the older format first
        try:
            secnews.add_subscribers(self.path, ["11"], self.key)
        finally:
            secnews.AESGCM = saved
        self.assertNotIn('"v"', self.path.read_text())
        backup = Path(self.dir.name) / "backup.json"
        secnews.backup_subscribers(self.path, backup, self.key)
        self.sync([{"update_id": 1, "message": {}}])  # any run saves the file again
        data = json.loads(self.path.read_text())
        self.assertEqual((data["v"], len(base64.b64decode(data["nonce"]))), (2, 12))
        self.assertNotIn('"11"', self.path.read_text())  # base64 text may contain 11 by chance, not "11"
        self.assertEqual(self.ids(), ["11"])
        self.assertTrue(secnews.backup_subscribers(self.path, backup, self.key))  # backup converted too
        self.assertEqual(json.loads(backup.read_text())["v"], 2)
        other = secnews.subscriber_key("999:other")
        self.assertEqual(secnews.load_subscribers(self.path, other)["ids"], [])  # wrong token opens nothing
        data["ct"] = base64.b64encode(b"x" + base64.b64decode(data["ct"])[1:]).decode()
        self.path.write_text(json.dumps(data))
        self.assertEqual(self.ids(), [])  # a changed byte fails the GCM tag

    def test_backup_follows_membership_changes_only(self):
        backup = Path(self.dir.name) / "backup" / "subscribers.json"
        secnews.add_subscribers(self.path, ["11"], self.key)
        self.assertTrue(secnews.backup_subscribers(self.path, backup, self.key))
        self.assertEqual(secnews.load_subscribers(backup, self.key)["ids"], ["11"])
        self.sync([{"update_id": 1, "message": {}}])  # only last_update moves; nobody joins
        self.assertFalse(secnews.backup_subscribers(self.path, backup, self.key))
        self.sync([upd(2, 33, "/start")])
        self.assertTrue(secnews.backup_subscribers(self.path, backup, self.key))
        self.assertIn("33", secnews.load_subscribers(backup, self.key)["ids"])

    def test_empty_list_does_not_overwrite_a_readable_backup(self):
        backup = Path(self.dir.name) / "backup.json"
        secnews.add_subscribers(self.path, ["11"], self.key)
        secnews.backup_subscribers(self.path, backup, self.key)
        secnews.save_subscribers(self.path, secnews.load_subscribers(Path("/nonexistent"), self.key), self.key)
        self.assertFalse(secnews.backup_subscribers(self.path, backup, self.key))
        self.assertEqual(secnews.load_subscribers(backup, self.key)["ids"], ["11"])
        other = secnews.subscriber_key("999:new-token")  # a new bot token cannot read the old backup
        secnews.save_subscribers(self.path, {"ids": ["44"], "stopped": []}, other)
        self.assertTrue(secnews.backup_subscribers(self.path, backup, other))

    def test_admin_asks_for_subscriber_count(self):
        secnews.add_subscribers(self.path, ["11", "22"], self.key)
        self.approval_sync([upd(1, 33, "/start"), upd(2, 11, "/stats"), upd(3, 99, "/stats")])
        stats = [m for m in self.sent if "구독 현황" in m[1]]
        self.assertEqual([m[0] for m in stats], ["99"])  # only the admin gets an answer
        self.assertIn("구독 중: 2명", stats[0][1])
        self.assertIn("승인 대기: 1명", stats[0][1])

    def test_admin_why_question(self):
        asked = []
        secnews.sync_subscribers(self.path, [upd(1, 99, "/why https://e.com/a"), upd(2, 11, "/why x")],
                                 key=self.key, admin="99", send=lambda c, t, m=None: self.sent.append((c, t)),
                                 why=lambda q: asked.append(q) or "answer")
        self.assertEqual(asked, ["https://e.com/a"])  # only the admin's question
        self.assertIn(("99", "answer"), self.sent)

    def test_hint_under_buttons_goes_away_with_the_result(self):
        self.approval_sync([upd(1, 11, "/start")])
        self.assertIn(secnews.APPROVE_HINT, self.sent[1][1])
        edits = []
        press = self.press(2, "ok:11")
        press["callback_query"]["message"]["text"] = "🔔 새 구독 신청\nID: 11\n\n" + secnews.APPROVE_HINT
        secnews.sync_subscribers(self.path, [press], key=self.key, admin="99", send=lambda *a: None,
                                 api=lambda method, params: edits.append(params.get("text")))
        self.assertTrue(edits[-1].startswith("🔔 새 구독 신청\nID: 11\n\n✅ 승인 완료"), edits[-1])

    def test_admin_rehearsal_changes_nothing(self):
        self.approval_sync([upd(1, 99, "/test"), upd(2, 11, "/test")])
        self.assertEqual([m[0] for m in self.sent], ["99", "99"])  # only the admin's /test counts
        self.assertEqual(self.sent[1][2]["inline_keyboard"][0][0]["callback_data"], "test:ok")
        self.sent.clear()
        self.approval_sync([self.press(3, "test:ok")])
        self.assertEqual(self.api_calls[-1], "editMessageText")  # the result replaces the buttons
        self.assertEqual(self.sent, [])
        subs = secnews.load_subscribers(self.path, self.key)
        self.assertEqual((subs["ids"], subs["pending"]), ([], {}))

    def test_double_tap_is_handled_once(self):
        self.approval_sync([self.press(1, "test:ok"), self.press(2, "test:ok")])
        self.assertEqual(self.api_calls.count("editMessageText"), 1)
        self.assertEqual(self.sent, [])

    def test_rejected_chat_can_ask_again(self):
        self.approval_sync([upd(1, 11, "/start"), self.press(2, "no:11")])
        self.assertEqual(self.ids(), [])
        self.assertIn(("11", secnews.REJECTED, None), self.sent)
        self.sent.clear()
        self.approval_sync([upd(3, 11, "/start")])
        self.assertEqual(self.ids(), [])  # still needs the admin
        self.assertIn(("11", secnews.REQUESTED, None), self.sent)
        self.approval_sync([self.press(4, "ok:11")])
        self.assertEqual(self.ids(), ["11"])

    def test_rejected_former_subscriber_needs_approval_again(self):
        secnews.add_subscribers(self.path, ["11"], self.key)
        self.approval_sync([upd(1, 11, "/stop"), upd(2, 11, "/start")])  # former: back without asking
        self.approval_sync([upd(3, 11, "/stop")])
        subs = secnews.load_subscribers(self.path, self.key)
        subs["denied"] = ["11"]
        secnews.save_subscribers(self.path, subs, self.key)
        self.approval_sync([upd(4, 11, "/start")])
        self.assertEqual(self.ids(), [])

    def test_only_the_admin_can_approve_and_chatter_is_ignored(self):
        self.approval_sync([upd(1, 11, "/start"), self.press(2, "ok:11", who=11), upd(3, 22, "hello")])
        self.assertEqual(self.ids(), [])
        self.assertEqual(list(secnews.load_subscribers(self.path, self.key)["pending"]), ["11"])

    def test_former_subscriber_and_admin_need_no_approval(self):
        secnews.add_subscribers(self.path, ["11"], self.key)
        self.approval_sync([upd(1, 11, "/stop"), upd(2, 11, "/start"), upd(3, 99, "/start")])
        self.assertEqual(sorted(self.ids()), ["11", "99"])

    def test_stranger_cannot_skip_approval_with_stop_then_start(self):
        self.approval_sync([upd(1, 33, "/stop"), upd(2, 33, "/start")])
        self.assertEqual(self.ids(), [])
        self.assertIn("33", secnews.load_subscribers(self.path, self.key)["pending"])

    def test_start_subscribes_once_and_welcomes(self):
        self.assertEqual(self.sync([upd(1, 11, "/start"), upd(2, 22, "hi")]), (["11", "22"], []))
        self.assertEqual(self.ids(), ["11", "22"])
        self.assertEqual(len(self.sent), 2)
        self.assertEqual(self.sync([upd(1, 11, "/start"), upd(2, 22, "hi")]), ([], []))  # already handled
        self.assertEqual(len(self.sent), 2)

    def test_stop_and_resubscribe(self):
        self.sync([upd(1, 11, "/start")])
        self.assertEqual(self.sync([upd(2, 11, "/stop")]), ([], ["11"]))
        self.assertEqual(self.ids(), [])
        self.assertEqual(self.sync([upd(3, 11, "thanks")]), ([], []))  # chatter does not resubscribe
        self.assertEqual(self.sync([upd(4, 11, "/start")]), (["11"], []))

    def test_group_added_and_removed(self):
        self.sync([upd(1, -100, group_status="member")])
        self.assertEqual(self.ids(), ["-100"])
        self.sync([upd(2, -100, group_status="kicked")])
        self.assertEqual(self.ids(), [])

    def test_file_is_encrypted_and_needs_the_token(self):
        self.sync([upd(1, 1234567890, "/start")])
        raw = self.path.read_text()
        self.assertNotIn("1234567890", raw)
        self.assertEqual(secnews.load_subscribers(self.path, secnews.subscriber_key("other:token"))["ids"], [])

    def test_configured_ids_fold_in_but_stopped_stay_out(self):
        self.sync([upd(1, 11, "/start"), upd(2, 11, "/stop")])
        self.assertEqual(secnews.add_subscribers(self.path, ["11", "33"], self.key), ["33"])
        self.assertEqual(self.ids(), ["33"])

    def test_mark_gone(self):
        self.sync([upd(1, 11, "/start"), upd(2, 22, "/start")])
        secnews.mark_gone(self.path, {"11"}, self.key)
        self.assertEqual(self.ids(), ["22"])

    def test_masked(self):
        self.assertEqual(secnews.masked("1234567890"), "12***90")

    def test_test_mode_sends_only_to_test_chat_and_saves_nothing(self):
        import os
        state = Path(self.dir.name) / "seen.json"
        secnews.add_subscribers(self.path, ["111", "222"], self.key)
        before = self.path.read_bytes()
        item = {"source": "S", "title": "Zero-day actively exploited", "link": "https://e/1", "id": "1",
                "date": None, "summary": "", "security_only": False, "min_score": None}
        sent_to = []
        saved = (secnews.collect, secnews.telegram_send, secnews.telegram_get_updates, dict(os.environ))
        secnews.collect = lambda config, fetcher, failed=None, counts=None: [dict(item)]
        secnews.telegram_send = lambda token, chat, text, **kw: sent_to.append(chat)
        secnews.telegram_get_updates = lambda *a, **k: self.fail("test mode must not read updates")
        os.environ.update(TELEGRAM_BOT_TOKEN="123:abc", SECNEWS_STATE=str(state), SECNEWS_ONLY_CHATS="999")
        try:
            secnews.main(["--config", str(Path(__file__).with_name("test_feeds.json"))])
        finally:
            secnews.collect, secnews.telegram_send, secnews.telegram_get_updates = saved[:3]
            os.environ.clear()
            os.environ.update(saved[3])
        self.assertEqual(set(sent_to), {"999"})
        self.assertFalse(state.exists())
        self.assertEqual(self.path.read_bytes(), before)

    def test_get_updates_pages_past_100(self):
        # 250 waiting updates: three calls, each asking from after the last one seen.
        calls = []

        class Resp:
            def __init__(self, body):
                self.body = body

            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

            def read(self):
                return self.body

        def fake_urlopen(url, timeout=None):
            calls.append(url)
            offset = int(url.split("offset=")[1].split("&")[0]) if "offset=" in url else 1
            batch = [{"update_id": i} for i in range(offset, min(offset + 100, 251))]
            return Resp(json.dumps({"ok": True, "result": batch}).encode())

        original = secnews.urllib.request.urlopen
        secnews.urllib.request.urlopen = fake_urlopen
        try:
            updates = secnews.telegram_get_updates("123:abc", after=0)
        finally:
            secnews.urllib.request.urlopen = original
        self.assertEqual([u["update_id"] for u in updates], list(range(1, 251)))
        self.assertEqual(len(calls), 3)
        self.assertIn("offset=101", calls[1])
        self.assertIn("callback_query", urllib.parse.unquote(calls[0]))  # button presses are requested

    def fetch_with(self, answers, queued):
        saved = secnews.telegram_get_updates, secnews.telegram_api, secnews.time.sleep
        calls = []
        secnews.telegram_get_updates = lambda token, after: calls.append(after) or answers.pop(0)
        secnews.telegram_api = lambda token, method, params: {"result": {"pending_update_count": queued}}
        secnews.time.sleep = lambda s: None
        try:
            return secnews.fetch_updates("t", 7), calls
        finally:
            secnews.telegram_get_updates, secnews.telegram_api, secnews.time.sleep = saved

    def test_fetch_asks_again_when_queued_updates_were_not_sent(self):
        press = {"update_id": 8, "callback_query": {}}
        got, calls = self.fetch_with([[], [press]], queued=1)
        self.assertEqual(got, [press])
        self.assertEqual(calls, [7, 7])

    def test_fetch_asks_once_when_nothing_is_queued(self):
        got, calls = self.fetch_with([[]], queued=0)
        self.assertEqual((got, calls), ([], [7]))
        got, calls = self.fetch_with([[{"update_id": 8}]], queued=1)  # just sent, not yet confirmed
        self.assertEqual(len(calls), 1)


class GeminiRetryTests(unittest.TestCase):
    def test_extra_text_after_the_json_answer_is_ignored(self):
        import io
        d = tempfile.TemporaryDirectory()
        self.addCleanup(d.cleanup)
        budget = secnews.GeminiBudget(Path(d.name) / "usage.json", [("a", 5), ("b", 5)])

        def fake(req, timeout=0):
            text = '[1, 2]\n[3]' if "/models/a:" in req.full_url else "[9]"
            return io.BytesIO(json.dumps({"candidates": [{"content": {"parts": [{"text": text}]}}]}).encode())
        saved = secnews.GEMINI_BUDGET, secnews.urllib.request.urlopen
        secnews.GEMINI_BUDGET, secnews.urllib.request.urlopen = budget, fake
        try:
            self.assertEqual(secnews.gemini_json("p", "k"), [1, 2])
        finally:
            secnews.GEMINI_BUDGET, secnews.urllib.request.urlopen = saved

    def test_a_model_that_times_out_hands_the_request_to_another(self):
        import io
        d = tempfile.TemporaryDirectory()
        self.addCleanup(d.cleanup)
        budget = secnews.GeminiBudget(Path(d.name) / "usage.json", [("a", 5), ("b", 5)])

        def fake(req, timeout=0):
            if "/models/a:" in req.full_url:
                raise TimeoutError("The read operation timed out")
            return io.BytesIO(json.dumps({"candidates": [{"content": {"parts": [{"text": "[2]"}]}}]}).encode())
        saved = secnews.GEMINI_BUDGET, secnews.urllib.request.urlopen
        secnews.GEMINI_BUDGET, secnews.urllib.request.urlopen = budget, fake
        try:
            self.assertEqual(secnews.gemini_json("p", "k"), [2])
        finally:
            secnews.GEMINI_BUDGET, secnews.urllib.request.urlopen = saved

    def test_per_minute_limits_everywhere_never_retire_a_model_for_the_day(self):
        import io
        import urllib.error
        d = tempfile.TemporaryDirectory()
        self.addCleanup(d.cleanup)
        budget = secnews.GeminiBudget(Path(d.name) / "usage.json", [("a", 5), ("b", 5), ("c", 5), ("d", 5)])

        def fake(req, timeout=0):
            body = b'{"error": {"details": [{"violations": [{"quotaId": "GenerateRequestsPerMinutePerProject"}]}]}}'
            raise urllib.error.HTTPError(req.full_url, 429, "Too Many Requests", {}, io.BytesIO(body))
        saved = secnews.GEMINI_BUDGET, secnews.urllib.request.urlopen, secnews.time.sleep
        secnews.GEMINI_BUDGET, secnews.urllib.request.urlopen, secnews.time.sleep = budget, fake, lambda s: None
        try:
            with self.assertRaises(urllib.error.HTTPError):
                secnews.gemini_json("p", "k")
            self.assertTrue(all(budget.used.get(m, 0) < 5 for m in "abcd"))  # all still usable later today
        finally:
            secnews.GEMINI_BUDGET, secnews.urllib.request.urlopen, secnews.time.sleep = saved

    def test_overloaded_model_hands_the_request_to_another(self):
        import io
        import urllib.error
        d = tempfile.TemporaryDirectory()
        self.addCleanup(d.cleanup)
        budget = secnews.GeminiBudget(Path(d.name) / "usage.json", [("a", 5), ("b", 5), ("c", 5)])
        asked = []

        def fake(req, timeout=0):
            model = req.full_url.split("/models/")[1].split(":")[0]
            asked.append(model)
            if model == "a":
                raise urllib.error.HTTPError(req.full_url, 503, "Service Unavailable", {}, None)
            return io.BytesIO(json.dumps({"candidates": [{"content": {"parts": [{"text": "[1]"}]}}]}).encode())
        saved = secnews.GEMINI_BUDGET, secnews.urllib.request.urlopen, secnews.time.sleep
        secnews.GEMINI_BUDGET, secnews.urllib.request.urlopen, secnews.time.sleep = budget, fake, lambda s: None
        try:
            self.assertEqual(secnews.gemini_json("p", "k"), [1])
            self.assertEqual(asked, ["a", "b"])
            asked.clear()
            secnews.gemini_json("p", "k")
            self.assertEqual(asked[0], "a")  # still tried first next time: busy is not used up
        finally:
            secnews.GEMINI_BUDGET, secnews.urllib.request.urlopen, secnews.time.sleep = saved


    def test_translations_and_alerts_take_lite_first_leaving_flash_to_digests(self):
        d = tempfile.TemporaryDirectory()
        self.addCleanup(d.cleanup)
        budget = secnews.GeminiBudget(Path(d.name) / "usage.json", [("flash", 2), ("flash-lite", 9)])
        self.assertEqual(budget.take(lite_first=True), "flash-lite")
        self.assertEqual(budget.take(), "flash")
        self.assertEqual(budget.take(), "flash")
        self.assertEqual(budget.take(), "flash-lite")  # flash used up: digests fall back to lite

    def test_per_minute_limit_is_busy_but_a_daily_limit_retires_the_model(self):
        import io
        import urllib.error
        d = tempfile.TemporaryDirectory()
        self.addCleanup(d.cleanup)
        budget = secnews.GeminiBudget(Path(d.name) / "usage.json", [("a", 5), ("b", 5), ("c", 5)])
        asked = []

        def fake(req, timeout=0):
            model = req.full_url.split("/models/")[1].split(":")[0]
            asked.append(model)
            if model == "a":
                body = b'{"error": {"details": [{"violations": [{"quotaId": "GenerateRequestsPerMinutePerProject"}]}]}}'
                raise urllib.error.HTTPError(req.full_url, 429, "Too Many Requests", {}, io.BytesIO(body))
            if model == "b":
                body = b'{"error": {"details": [{"violations": [{"quotaId": "GenerateRequestsPerDayPerProject"}]}]}}'
                raise urllib.error.HTTPError(req.full_url, 429, "Too Many Requests", {}, io.BytesIO(body))
            return io.BytesIO(json.dumps({"candidates": [{"content": {"parts": [{"text": "[1]"}]}}]}).encode())
        saved = secnews.GEMINI_BUDGET, secnews.urllib.request.urlopen, secnews.time.sleep
        secnews.GEMINI_BUDGET, secnews.urllib.request.urlopen, secnews.time.sleep = budget, fake, lambda s: None
        try:
            self.assertEqual(secnews.gemini_json("p", "k"), [1])
            self.assertEqual(asked, ["a", "b", "c"])
            self.assertLess(budget.used["a"], 5)  # a minute's limit: still usable later today
            self.assertEqual(budget.used["b"], 5)  # the day's limit: retired until tomorrow
        finally:
            secnews.GEMINI_BUDGET, secnews.urllib.request.urlopen, secnews.time.sleep = saved


class QuietLogTests(unittest.TestCase):
    def test_public_log_shows_summary_and_holds_the_rest(self):
        import contextlib
        import io
        saved = secnews.QUIET, list(secnews.HELD)
        secnews.QUIET, secnews.HELD[:] = True, []
        out = io.StringIO()
        try:
            with contextlib.redirect_stderr(out):
                secnews.log("source 3: 50 items")
                secnews.log("5 recipient(s)")
                secnews.log("warning: source 7 failed: timeout")
                secnews.log("sent 2 of 31 new items")
            self.assertEqual(out.getvalue().splitlines(),
                             ["5 recipient(s)", "warning: source 7 failed: timeout", "sent 2 of 31 new items"])
            with contextlib.redirect_stderr(out):
                secnews.show_held_log()  # a failed run prints everything
            self.assertIn("source 3: 50 items", out.getvalue())
        finally:
            secnews.QUIET, secnews.HELD[:] = saved


class WatchdogTests(unittest.TestCase):
    def test_minutes_since_last_run(self):
        sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "tools"))
        import watchdog
        now = datetime(2026, 10, 17, 10, 0, tzinfo=timezone.utc)
        runs = [{"created_at": "2026-10-17T09:20:00Z"}, {"created_at": "2026-10-17T09:55:00Z"}]
        self.assertEqual(watchdog.minutes_since_last_run(runs, now), 5)
        self.assertIsNone(watchdog.minutes_since_last_run([], now))
        self.assertIn("40분째", watchdog.message(40))


class ScheduleTests(unittest.TestCase):
    def test_on_the_hour(self):
        cfg = {"digest_on_the_hour": True}
        last = datetime(2026, 10, 16, 9, 2, tzinfo=timezone.utc).timestamp()
        due = lambda h, m: secnews.due({"last_digest": last}, cfg, datetime(2026, 10, 16, h, m, tzinfo=timezone.utc))
        self.assertFalse(due(9, 55))
        self.assertTrue(due(10, 0))
        self.assertTrue(due(10, 7))  # a late GitHub schedule still sends once in that hour
        self.assertTrue(secnews.due(None, cfg, NOW))


class MessageTests(unittest.TestCase):
    def test_sections(self):
        base = {"link": "https://e.com", "source": "s", "date": NOW, "summary": ""}
        items = [dict(base, title="C", score=1), dict(base, title="A", score=5)]
        (msg,) = secnews.build_messages(items, NOW, "TITLE")
        self.assertTrue(msg.startswith("TITLE"))
        self.assertLess(msg.index("긴급"), msg.index("주요"))

    def test_long_urls_do_not_split_messages(self):
        item = {"title": "짧은 제목", "link": "https://news.google.com/rss/articles/" + "x" * 400,
                "source": "s", "date": NOW, "score": 1, "summary": ""}
        self.assertEqual(len(secnews.build_messages([item] * 20, NOW)), 1)

    def test_split_long_digest(self):
        item = {"title": "x" * 300, "link": "https://e.com", "source": "s", "date": NOW, "score": 3}
        msgs = secnews.build_messages([item] * 40)
        self.assertGreater(len(msgs), 1)
        self.assertTrue(all(secnews.visible_len(m) <= secnews.TELEGRAM_LIMIT for m in msgs))
        self.assertTrue(all(secnews.entity_count(m) <= secnews.MAX_ENTITIES for m in msgs))

    def test_env_file(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "env"
            p.write_text("# comment\nexport TELEGRAM_BOT_TOKEN='1:abc'\nTELEGRAM_CHAT_IDS=1,2\n")
            self.assertEqual(secnews.load_env_file(p), {"TELEGRAM_BOT_TOKEN": "1:abc", "TELEGRAM_CHAT_IDS": "1,2"})
            self.assertEqual(secnews.load_env_file(Path(d) / "missing"), {})

    def test_all_chat_ids_merges_config_and_secret(self):
        self.assertEqual(secnews.all_chat_ids({"chat_ids": ["1", 2]}, "2, 3"), ["1", "2", "3"])
        self.assertEqual(secnews.all_chat_ids({}, ""), [])

    def test_chat_ids(self):
        self.assertEqual(secnews.parse_chat_ids("123, -100456\n@chan"), ["123", "-100456", "@chan"])


if __name__ == "__main__":
    unittest.main()

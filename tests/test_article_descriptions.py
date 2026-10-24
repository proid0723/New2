import io
from email.message import Message
import html
import unittest
from unittest import mock

import secnews


class ArticleDescriptionTests(unittest.TestCase):
    title = "공항 출입 절차 점검 결과 발표"
    description = "직원들은 회수되지 않은 신분증으로 제한된 장소를 오갔다. 담당 부서는 관련 기록을 보관하지 않았다."

    def summary(self, body, heading=None, metadata=True):
        heading = self.title if heading is None else heading
        tags = (f'<meta property="og:title" content="{html.escape(heading)}">' if metadata else "")
        raw = (tags + f'<meta property="og:description" content="{self.description}">' + body).encode()
        response = io.BytesIO(raw)
        response.headers = Message()
        with mock.patch.object(secnews, "urlopen_public", return_value=response):
            return secnews.page_summary({"title": self.title, "link": "https://airport.example/article"})

    def test_distinctly_worded_intro_is_accepted_when_correlated_with_article_body_and_headline(self):
        self.assertEqual(self.summary(f"<article><h1>{self.title}</h1><p>{self.description}</p></article>"), self.description)

    def test_metadata_alone_or_visible_footer_cannot_verify_a_summary(self):
        for body in ("", f"<footer>{self.description}</footer>",
                     f"<article><h1>{self.title}</h1><footer>{self.description}</footer></article>",
                     f"<article><h1>{self.title}</h1><script>{self.description}</script></article>",
                     f"<article><h1>{self.title}</h1><aside>{self.description}</aside></article>"):
            with self.subTest(body=body):
                self.assertEqual(self.summary(body), "")

    def test_unrelated_article_and_truncated_body_are_rejected(self):
        unrelated = f"<article><h1>새로운 운항 시간표</h1><p>{self.description}</p></article>"
        self.assertEqual(self.summary(unrelated, heading="새로운 운항 시간표"), "")
        self.assertEqual(self.summary(f"<article><h1>{self.title}</h1><p>{self.description[:35]}</p></article>"), "")

    def test_visible_markup_and_spacing_do_not_prevent_body_corroboration(self):
        body = self.description.replace("신분증", "<strong>신분증</strong>")
        self.assertEqual(self.summary(f"<article><h1>{self.title}</h1><p>{body}</p></article>", metadata=False), self.description)


if __name__ == "__main__":
    unittest.main()

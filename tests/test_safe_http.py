import io
from email.message import Message
import socket
import ssl
import unittest
from unittest import mock
import urllib.error
import urllib.request

from tools import safe_http


class SafeHTTPTests(unittest.TestCase):
    def setUp(self):
        safe_http._DNS.clear()
        patch = mock.patch.object(safe_http.urllib.request, "getproxies", return_value={})
        patch.start()
        self.addCleanup(patch.stop)
        self.address = (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("8.8.8.8", 443))
        patch = mock.patch.object(safe_http.socket, "getaddrinfo", return_value=[self.address])
        self.resolve = patch.start()
        self.addCleanup(patch.stop)

    def response(self, body, length=None):
        result = io.BytesIO(body)
        result.headers = Message()
        if length is not None:
            result.headers["Content-Length"] = str(length)
        return result

    def test_private_urls_and_invalid_schemes_are_rejected_before_transport(self):
        urls = ["http://127.0.0.1/a", "http://169.254.169.254/a", "http://10.0.0.1/a", "http://100.64.0.1/a",
                "http://[::1]/a", "http://[::ffff:127.0.0.1]/a", "http://[2002:7f00:1::]/a",
                "http://[fec0::1]/a", "http://[100::1]/a",
                "file:///private", "https://user:password@example.com/a", "http://localhost/a",
                "https://airport.local/a", "https://example.com:8443/a", "https://example.com/a\nheader"]
        with mock.patch.object(safe_http, "_opener") as opener:
            for url in urls:
                with self.subTest(url=url), self.assertRaises(safe_http.URLPolicyError):
                    safe_http.urlopen_public(url)
        opener.assert_not_called()

    def test_private_dns_and_mixed_answers_are_rejected(self):
        for rows in ([self.address[:-1] + (("10.0.0.1", 443),)],
                     [self.address, self.address[:-1] + (("127.0.0.1", 443),)]):
            safe_http._DNS.clear()
            self.resolve.return_value = rows
            with mock.patch.object(safe_http, "_opener") as factory, self.assertRaises(safe_http.URLPolicyError):
                safe_http.urlopen_public("https://airport.example/a")
            factory.return_value.open.assert_not_called()

    def test_numeric_connection_is_pinned_without_a_second_dns_lookup(self):
        sock = mock.Mock()
        with mock.patch.object(safe_http.socket, "socket", return_value=sock):
            connection = safe_http._PinnedHTTP("airport.example", port=443, timeout=5,
                                               deadline=safe_http.time.monotonic() + 5)
            connection.connect()
        self.resolve.assert_called_once()
        sock.connect.assert_called_once_with(("8.8.8.8", 443))
        self.assertEqual(connection.host, "airport.example")

    def test_tls_keeps_certificate_checks_and_original_hostname(self):
        context = ssl.create_default_context()
        self.assertTrue(context.check_hostname)
        self.assertEqual(context.verify_mode, ssl.CERT_REQUIRED)
        sock, wrapped = mock.Mock(), mock.Mock()
        with mock.patch.object(safe_http.socket, "socket", return_value=sock), \
             mock.patch.object(ssl.SSLContext, "wrap_socket", return_value=wrapped) as wrap:
            connection = safe_http._PinnedHTTPS("airport.example", timeout=5, context=context,
                                                deadline=safe_http.time.monotonic() + 5)
            connection.connect()
        wrap.assert_called_once_with(sock, server_hostname="airport.example")
        self.assertIs(connection.sock, wrapped)

    def test_real_urllib_opener_integrates_with_pinned_https_and_verified_context(self):
        response = self.response(b"ok")
        response.status, response.code, response.reason = 200, 200, "OK"
        response.info = lambda: response.headers
        connection = mock.Mock()
        connection.sock = None
        connection.getresponse.return_value = response
        with mock.patch.object(safe_http, "_PinnedHTTPS", return_value=connection) as factory:
            self.assertEqual(safe_http.urlopen_public("https://airport.example/a").read(), b"ok")
        context = factory.call_args.kwargs["context"]
        self.assertTrue(context.check_hostname)
        self.assertEqual(context.verify_mode, ssl.CERT_REQUIRED)
        self.assertEqual(factory.call_args.args[0], "airport.example")
        self.assertEqual(connection.request.call_args.args[:2], ("GET", "/a"))

    def test_configured_proxy_is_refused_without_bypassing_it(self):
        with mock.patch.object(safe_http.urllib.request, "getproxies", return_value={"https": "http://proxy.example:8080"}), \
             mock.patch.object(safe_http, "_opener") as opener, self.assertRaises(safe_http.URLPolicyError):
            safe_http.urlopen_public("https://airport.example/a")
        opener.assert_not_called()
        self.resolve.assert_not_called()

    def test_size_cap_and_truncated_metadata_reads(self):
        for length in (None, 100):
            with mock.patch.object(safe_http, "_opener") as factory:
                factory.return_value.open.return_value = self.response(b"x" * 100, length)
                with self.assertRaises(safe_http.URLPolicyError):
                    safe_http.urlopen_public("https://airport.example/a", max_bytes=10)
        with mock.patch.object(safe_http, "_opener") as factory:
            factory.return_value.open.return_value = self.response(b"x" * 100, 100)
            with safe_http.urlopen_public("https://airport.example/a", max_bytes=10, truncate=True) as response:
                self.assertEqual(response.read(), b"x" * 10)

    def test_redirect_cannot_enter_internal_network_or_downgrade_https(self):
        for target in ("http://127.0.0.1/a", "https://10.0.0.1/a", "file:///private", "http://airport.example/a"):
            headers = Message()
            headers["Location"] = target
            error = urllib.error.HTTPError("https://airport.example/a", 302, "Found", headers, None)
            with mock.patch.object(safe_http, "_opener") as factory:
                factory.return_value.open.side_effect = error
                with self.subTest(target=target), self.assertRaises(safe_http.URLPolicyError):
                    safe_http.urlopen_public("https://airport.example/a")
                self.assertEqual(factory.return_value.open.call_count, 1)

    def test_redirect_target_dns_is_revalidated_and_authentication_is_not_forwarded(self):
        headers = Message()
        headers["Location"] = "https://other.example/article"
        error = urllib.error.HTTPError("https://airport.example/a", 302, "Found", headers, None)
        with mock.patch.object(safe_http, "_opener") as factory:
            factory.return_value.open.side_effect = [error, self.response(b"ok")]
            request = urllib.request.Request("https://airport.example/a", headers={"Authorization": "unit-token", "Cookie": "unit-cookie"})
            self.assertEqual(safe_http.urlopen_public(request).read(), b"ok")
            second = factory.return_value.open.call_args_list[1].args[0]
            self.assertNotIn("Authorization", second.headers)
            self.assertNotIn("Cookie", second.headers)
            self.assertEqual(self.resolve.call_count, 2)
        safe_http._DNS.clear()
        self.resolve.side_effect = [[self.address], [self.address[:-1] + (("10.0.0.1", 443),)]]
        with mock.patch.object(safe_http, "_opener") as factory:
            factory.return_value.open.side_effect = error
            with self.assertRaises(safe_http.URLPolicyError):
                safe_http.urlopen_public("https://airport.example/a")
            self.assertEqual(factory.return_value.open.call_count, 1)

    def test_body_io_uses_one_deadline_instead_of_resetting_per_chunk(self):
        clock = [0.0]
        class Slow(io.BytesIO):
            def read1(self, size):
                clock[0] += 0.6
                return b"x"
        response = Slow()
        response.headers = Message()
        with mock.patch.object(safe_http.time, "monotonic", side_effect=lambda: clock[0]), \
             mock.patch.object(safe_http, "_opener") as factory:
            factory.return_value.open.return_value = response
            with self.assertRaises(TimeoutError):
                safe_http.urlopen_public("https://airport.example/a", timeout=1)
        self.assertLessEqual(clock[0], 1.2)


if __name__ == "__main__":
    unittest.main()

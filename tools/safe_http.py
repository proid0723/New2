"""Bounded public-content HTTP with validated, pinned DNS and explicit redirect checks."""
import http.client
import io
import ipaddress
import socket
import ssl
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

MAX_RESPONSE = 8 * 1024 * 1024
_DNS = {}
_LOCK = threading.Lock()


class URLPolicyError(ValueError):
    pass


def _global(address):
    ip = ipaddress.ip_address(address)
    if ip.version == 6 and (ip.sixtofour or ip.teredo):
        return False
    if ip.version == 6 and ip.ipv4_mapped:
        ip = ip.ipv4_mapped
    return (ip.is_global and not ip.is_multicast and not ip.is_reserved
            and not getattr(ip, "is_site_local", False))


def normalize_url(url):
    if not isinstance(url, str) or len(url) > 8192 or any(ord(c) < 33 or ord(c) == 127 for c in url):
        raise URLPolicyError("invalid public URL")
    try:
        parsed = urllib.parse.urlsplit(url)
        if parsed.scheme.lower() not in ("http", "https") or not parsed.hostname or parsed.username is not None:
            raise URLPolicyError("only public HTTP URLs without credentials are allowed")
        host = parsed.hostname.rstrip(".").encode("idna").decode("ascii").lower()
        port = parsed.port or (443 if parsed.scheme.lower() == "https" else 80)
        if port != (443 if parsed.scheme.lower() == "https" else 80):
            raise URLPolicyError("nonstandard content ports are not allowed")
        if (host == "localhost" or host.endswith((".localhost", ".local", ".internal")) or "%" in host):
            raise URLPolicyError("local content addresses are not allowed")
        try:
            ipaddress.ip_address(host)
        except ValueError:
            pass
        else:
            if not _global(host):
                raise URLPolicyError("nonpublic content addresses are not allowed")
        authority = f"[{host}]" if ":" in host else host
        path = urllib.parse.quote(parsed.path or "/", safe="/%:@!$&'()*+,;=-._~")
        query = urllib.parse.quote(parsed.query, safe="=&%?/:+@!$'()*+,;-._~")
        return urllib.parse.urlunsplit((parsed.scheme.lower(), authority, path, query, ""))
    except (ValueError, UnicodeError) as error:
        if isinstance(error, URLPolicyError):
            raise
        raise URLPolicyError("invalid public URL") from None


def _addresses(host, port):
    key = (host, port)
    now = time.monotonic()
    with _LOCK:
        cached = _DNS.get(key)
        if cached and cached[0] > now:
            return cached[1]
    addresses = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    if not addresses or any(not _global(row[4][0]) for row in addresses):
        raise URLPolicyError("content hostname resolves to a nonpublic address")
    with _LOCK:
        if len(_DNS) >= 1024:
            _DNS.clear()
        _DNS[key] = (now + 60, addresses)
    return addresses


def _connect(host, port, timeout, deadline, source_address=None):
    last_error = None
    for family, kind, protocol, _, address in _addresses(host, port):
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("public HTTP time budget reached")
        connection = socket.socket(family, kind, protocol)
        try:
            connection.settimeout(min(timeout, remaining))
            if source_address:
                connection.bind(source_address)
            connection.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            connection.connect(address)  # numeric sockaddr: no second hostname lookup/rebinding
            return connection
        except OSError as error:
            last_error = error
            connection.close()
    if last_error:
        raise last_error
    raise OSError("no public content address is available")


class _PinnedHTTP(http.client.HTTPConnection):
    def __init__(self, *args, deadline, **kwargs):
        self.deadline = deadline
        super().__init__(*args, **kwargs)

    def connect(self):
        if self._tunnel_host:
            raise URLPolicyError("proxy tunneling is not supported by the pinned content transport")
        self.sock = _connect(self.host, self.port, self.timeout, self.deadline, self.source_address)


class _PinnedHTTPS(http.client.HTTPSConnection):
    def __init__(self, *args, deadline, **kwargs):
        self.deadline = deadline
        super().__init__(*args, **kwargs)

    def connect(self):
        if self._tunnel_host:
            raise URLPolicyError("proxy tunneling is not supported by the pinned content transport")
        sock = _connect(self.host, self.port, self.timeout, self.deadline, self.source_address)
        try:
            remaining = self.deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("public HTTP time budget reached")
            sock.settimeout(min(self.timeout, remaining))
            self.sock = self._context.wrap_socket(sock, server_hostname=self.host)
        except BaseException:
            sock.close()
            raise


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


def _opener(deadline):
    class HTTP(urllib.request.HTTPHandler):
        def http_open(self, request):
            return self.do_open(lambda *a, **kw: _PinnedHTTP(*a, deadline=deadline, **kw), request)
    class HTTPS(urllib.request.HTTPSHandler):
        def https_open(self, request):
            return self.do_open(lambda *a, **kw: _PinnedHTTPS(*a, deadline=deadline, **kw), request,
                                context=self._context)
    # This transport is used only after rejecting configured proxies below. Never silently
    # bypass an inherited proxy: it cannot provide the pinned target connection we require.
    return urllib.request.build_opener(urllib.request.ProxyHandler({}), HTTP(),
                                      HTTPS(context=ssl.create_default_context()), _NoRedirect())


def _read(response, cap, deadline, truncate):
    length = response.headers.get("Content-Length") if getattr(response, "headers", None) else None
    if length and length.isdigit() and int(length) > cap and not truncate:
        raise URLPolicyError("public response exceeds the byte limit")
    result = bytearray()
    read = getattr(response, "read1", response.read)
    while len(result) < cap + (not truncate):
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("public HTTP time budget reached")
        sock = getattr(getattr(getattr(response, "fp", None), "raw", None), "_sock", None)
        if sock is not None:
            sock.settimeout(remaining)
        part = read(min(65536, cap + (not truncate) - len(result)))
        if not part:
            break
        result.extend(part)
        if len(result) > cap:
            raise URLPolicyError("public response exceeds the byte limit")
    return bytes(result)


class Response(io.BytesIO):
    def __init__(self, body, headers, url):
        super().__init__(body)
        self.headers, self.url = headers, url

    def geturl(self):
        return self.url


def urlopen_public(request, timeout=20, max_bytes=MAX_RESPONSE, truncate=False):
    """Public content only. Configured proxies are refused, never bypassed.
    DNS obeys the OS resolver timeout; connection/redirect/body I/O share one deadline."""
    timeout = max(0.01, float(timeout))
    cap = max(1, min(MAX_RESPONSE, int(max_bytes)))
    deadline = time.monotonic() + timeout
    original = request if isinstance(request, urllib.request.Request) else urllib.request.Request(request)
    url = normalize_url(original.full_url)
    proxies = urllib.request.getproxies()
    if any(proxies.get(kind) for kind in ("http", "https", "all")):
        raise URLPolicyError("configured proxy cannot guarantee pinned public-content connections")
    headers = {k: v for k, v in original.header_items() if k.lower() != "host"}
    data, method = original.data, original.get_method()
    opener = _opener(deadline)
    for hop in range(6):
        parsed = urllib.parse.urlsplit(url)
        _addresses(parsed.hostname, parsed.port or (443 if parsed.scheme == "https" else 80))
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("public HTTP time budget reached")
        req = urllib.request.Request(url, data=data, headers=headers, method=method)
        try:
            with opener.open(req, timeout=remaining) as response:
                return Response(_read(response, cap, deadline, truncate), response.headers, url)
        except urllib.error.HTTPError as error:
            if error.code not in (301, 302, 303, 307, 308) or not error.headers.get("Location") or hop == 5:
                raise
            target = normalize_url(urllib.parse.urljoin(url, error.headers["Location"]))
            error.close()
            destination = urllib.parse.urlsplit(target)
            if parsed.scheme == "https" and destination.scheme != "https":
                raise URLPolicyError("HTTPS content redirects cannot downgrade transport security")
            if (destination.scheme, destination.netloc) != (parsed.scheme, parsed.netloc):
                headers = {k: v for k, v in headers.items()
                           if k.lower() not in ("authorization", "cookie", "x-goog-api-key")}
            if error.code == 303 or error.code in (301, 302) and method == "POST":
                data, method = None, "GET"
                headers = {k: v for k, v in headers.items() if k.lower() not in ("content-type", "content-length")}
            url = target
    raise URLPolicyError("too many content redirects")

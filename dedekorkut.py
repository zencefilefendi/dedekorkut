#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Dede Korkut - Operasyonel Ag Tarama ve Istihbarat Platformu (v4.0 Sentinel)

Ozellikler:
  * Pasif sniffing (Ghost Protocol)
  * Asenkron port tarama + servis tespiti
  * HTTP/HTTPS tam fingerprinting (Server, X-Powered-By, redirect chain, security headers)
  * TLS/SSL sertifika otopsisi (issuer, SAN, expiry, weak cipher)
  * DNS reconnaissance (PTR, MX, NS, TXT, A/AAAA)
  * Harici JSON tabanli zafiyet veritabani (regex motoru)
  * Shodan OSINT entegrasyonu
  * Stealth modu (jitter, port randomization, UA rotation)
  * JSON / CSV / HTML / Rich Table cikti formatlari
  * Yapilandirilabilir log seviyeleri (-v, -vv, --quiet, --no-color)
"""

from __future__ import annotations

import argparse
import asyncio
import csv
import dataclasses
import html
import ipaddress
import json
import logging
import os
import random
import re
import socket
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

# ----- ZORUNLU: rich -----
try:
    from rich.console import Console
    from rich.logging import RichHandler
    from rich.panel import Panel
    from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn
    from rich.table import Table
except ImportError:
    print("[!] Kritik kutuphane eksik: 'rich'. Yuklemek icin: pip install rich")
    sys.exit(1)

# ----- OPSIYONEL: scapy (pasif sniff) -----
try:
    import logging as _lg
    _lg.getLogger("scapy.runtime").setLevel(_lg.ERROR)
    from scapy.all import IP, TCP, UDP, sniff  # type: ignore
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

# ----- OPSIYONEL: dnspython -----
try:
    import dns.asyncresolver  # type: ignore
    import dns.resolver  # type: ignore
    DNSPYTHON_AVAILABLE = True
except ImportError:
    DNSPYTHON_AVAILABLE = False


__version__ = "4.0-sentinel"

BANNER = r"""[bold red]
    ____           __        __ __           __        __
   / __ \___  ____/ /__     / //_/___  _____/ /____  / /_
  / / / / _ \/ __  / _ \   / ,< / __ \/ ___/ //_/ / / / __/
 / /_/ /  __/ /_/ /  __/  / /| / /_/ / /  / ,< / /_/ / /_
/_____/\___/\__,_/\___/  /_/ |_\____/_/  /_/|_|\__,_/\__/
[/bold red][bold cyan]> v4.0 Sentinel | Async Recon + TLS Autopsy + DNS + Stealth + Multi-format Output[/bold cyan]"""


# =============================================================================
# LOG SISTEMI
# =============================================================================
def build_logger(verbosity: int, quiet: bool, no_color: bool) -> Tuple[Console, logging.Logger]:
    """Verbosity seviyesine gore Rich-uyumlu logger insa eder.

    verbosity: 0 (WARNING) | 1 (INFO) | 2+ (DEBUG)
    quiet:     log seviyesini ERROR'a dusurur, banner'i susturmaz
    """
    console = Console(no_color=no_color, force_terminal=not no_color)
    if quiet:
        level = logging.ERROR
    elif verbosity >= 2:
        level = logging.DEBUG
    elif verbosity == 1:
        level = logging.INFO
    else:
        level = logging.WARNING

    handler = RichHandler(
        console=console,
        show_time=verbosity >= 1,
        show_path=verbosity >= 2,
        rich_tracebacks=True,
        markup=True,
    )
    logging.basicConfig(level=level, handlers=[handler], format="%(message)s", force=True)
    return console, logging.getLogger("dedekorkut")


# =============================================================================
# VERI MODELLERI (dataclasses)
# =============================================================================
@dataclass
class TlsInfo:
    subject: str = ""
    issuer: str = ""
    san: List[str] = field(default_factory=list)
    not_before: str = ""
    not_after: str = ""
    days_to_expiry: int = 0
    self_signed: bool = False
    version: str = ""
    cipher: str = ""

    def summary(self) -> str:
        if not self.subject:
            return ""
        flags = []
        if self.self_signed:
            flags.append("self-signed")
        if 0 < self.days_to_expiry < 30:
            flags.append(f"expires in {self.days_to_expiry}d")
        elif self.days_to_expiry <= 0:
            flags.append("EXPIRED")
        flag_str = f" [{', '.join(flags)}]" if flags else ""
        return f"{self.subject} | {self.version}{flag_str}"


@dataclass
class RedirectHop:
    status: int
    location: str
    server: str = ""


@dataclass
class HttpInfo:
    status: int = 0
    server: str = ""
    powered_by: str = ""
    title: str = ""
    redirect: str = ""
    final_url: str = ""
    redirect_chain: List[RedirectHop] = field(default_factory=list)
    security_headers: Dict[str, str] = field(default_factory=dict)
    missing_security_headers: List[str] = field(default_factory=list)
    cors_origin: str = ""
    cors_credentials: bool = False


@dataclass
class Finding:
    plugin: str
    severity: str
    title: str
    detail: str = ""
    evidence: str = ""


@dataclass
class PortResult:
    ip: str
    port: int
    status: str = "OPEN"
    service: str = ""
    banner: str = ""
    cves: List[Dict[str, str]] = field(default_factory=list)
    tls: Optional[TlsInfo] = None
    http: Optional[HttpInfo] = None
    findings: List[Finding] = field(default_factory=list)
    rtt_ms: float = 0.0


@dataclass
class DnsInfo:
    host: str
    ptr: str = ""
    a: List[str] = field(default_factory=list)
    aaaa: List[str] = field(default_factory=list)
    mx: List[str] = field(default_factory=list)
    ns: List[str] = field(default_factory=list)
    txt: List[str] = field(default_factory=list)


@dataclass
class ScanReport:
    target: str
    started_at: str
    finished_at: str = ""
    duration_sec: float = 0.0
    targets_resolved: List[str] = field(default_factory=list)
    ports_scanned: List[int] = field(default_factory=list)
    results: List[PortResult] = field(default_factory=list)
    dns: List[DnsInfo] = field(default_factory=list)
    shodan: Optional[Dict[str, Any]] = None
    stats: Dict[str, Any] = field(default_factory=dict)
    version: str = __version__


# =============================================================================
# SCAN CONTEXT (global state replacement)
# =============================================================================
class ScanContext:
    """Thread-safe sayac ve paylasimli state. Globalleri ortadan kaldirir."""

    def __init__(self) -> None:
        self._lock = asyncio.Lock()
        self.packets_sent: int = 0
        self.open_ports: int = 0
        self.errors: int = 0
        self.t0: float = time.monotonic()

    async def inc_sent(self) -> None:
        async with self._lock:
            self.packets_sent += 1

    async def inc_open(self) -> None:
        async with self._lock:
            self.open_ports += 1

    async def inc_error(self) -> None:
        async with self._lock:
            self.errors += 1

    def elapsed(self) -> float:
        return time.monotonic() - self.t0


# =============================================================================
# ZAFIYET VERITABANI
# =============================================================================
DEFAULT_VULN_DB: Dict[str, List[Dict[str, str]]] = {
    "openssh": [
        {"regex": r"openssh_3\.[0-7]", "cve": "CVE-2006-5051", "severity": "critical", "desc": "Signal handler race -> RCE"},
        {"regex": r"openssh_7\.2p2", "cve": "CVE-2018-15473", "severity": "medium", "desc": "Username enumeration"},
        {"regex": r"openssh_9\.[0-7]p1", "cve": "CVE-2024-6387", "severity": "critical", "desc": "regreSSHion RCE"},
    ],
    "apache": [
        {"regex": r"apache/2\.4\.(4[0-9]|49)", "cve": "CVE-2021-41773", "severity": "critical", "desc": "Path traversal + RCE"},
    ],
    "vsftpd": [
        {"regex": r"vsftpd_2\.3\.4", "cve": "BACKDOOR-2011", "severity": "critical", "desc": "Trojan backdoor"},
    ],
}


class VulnerabilityDB:
    """Harici JSON dosyasindan veya gomulu varsayilandan zafiyet imzalari yukler."""

    def __init__(self, rules: Dict[str, List[Dict[str, str]]], log: logging.Logger):
        self.log = log
        self.compiled: List[Tuple[str, re.Pattern[str], Dict[str, str]]] = []
        for category, items in rules.items():
            if category.startswith("_"):
                continue
            for item in items:
                pattern = item.get("regex")
                if not pattern:
                    continue
                try:
                    self.compiled.append((category, re.compile(pattern, re.IGNORECASE), item))
                except re.error as exc:
                    self.log.warning("Hatali regex atlandi (%s): %s", category, exc)
        self.log.info("VulnDB yuklendi: %d kategori, %d imza", len(rules) - sum(1 for k in rules if k.startswith("_")), len(self.compiled))

    @classmethod
    def load(cls, path: Optional[str], log: logging.Logger) -> "VulnerabilityDB":
        if path:
            p = Path(path)
            if not p.exists():
                log.warning("VulnDB dosyasi bulunamadi (%s) - varsayilan gomulu DB kullaniliyor", path)
                return cls(DEFAULT_VULN_DB, log)
            try:
                data = json.loads(p.read_text(encoding="utf-8"))
                return cls(data, log)
            except (OSError, json.JSONDecodeError) as exc:
                log.error("VulnDB okunamadi: %s - varsayilana donuluyor", exc)
                return cls(DEFAULT_VULN_DB, log)
        # auto-discover yan dosya
        sibling = Path(__file__).parent / "vuln_db.json"
        if sibling.exists():
            try:
                return cls(json.loads(sibling.read_text(encoding="utf-8")), log)
            except (OSError, json.JSONDecodeError) as exc:
                log.warning("vuln_db.json okunamadi: %s", exc)
        return cls(DEFAULT_VULN_DB, log)

    def match(self, *fragments: str) -> List[Dict[str, str]]:
        """Verilen tum string fragmanlarini birlestirip imzalarla esler."""
        haystack = " ".join(f for f in fragments if f).lower().replace(" ", "_")
        hits: List[Dict[str, str]] = []
        seen: set = set()
        for category, pattern, item in self.compiled:
            if pattern.search(haystack):
                key = item.get("cve", category)
                if key in seen:
                    continue
                seen.add(key)
                hits.append({
                    "category": category,
                    "cve": item.get("cve", ""),
                    "severity": item.get("severity", "info"),
                    "desc": item.get("desc", ""),
                })
        return hits


# =============================================================================
# PLUGIN ARCHITECTURE
# =============================================================================
@dataclass
class PluginContext:
    """Plugin'lere sunulan ortak servisler (DI bunchu)."""
    timeout: float
    log: logging.Logger
    user_agent: str
    pick_ua: Any  # callable -> str


class ScanPlugin:
    """Tum plugin'lerin tureyecegi taban sinif. Subclass'larda override edin."""

    name: str = ""
    description: str = ""
    version: str = "0.1"

    def applies_to(self, result: "PortResult") -> bool:
        """True donerse run() cagrilir. Default: hicbir porta uygulanmaz."""
        return False

    async def run(self, result: "PortResult", ctx: PluginContext) -> List[Finding]:
        """Bulgu listesini dondurur (bos liste de geçerli)."""
        return []


class PluginRegistry:
    """plugins/ klasorunden otomatik kesfedip yukler. Manuel register() da destekler."""

    def __init__(self, log: logging.Logger):
        self.log = log
        self.plugins: List[ScanPlugin] = []
        self.disabled: set = set()

    def disable(self, names: Iterable[str]) -> None:
        self.disabled.update(n.strip().lower() for n in names if n)

    def register(self, plugin: ScanPlugin) -> None:
        if not plugin.name:
            self.log.warning("Isimsiz plugin atlandi: %s", type(plugin).__name__)
            return
        if plugin.name.lower() in self.disabled:
            self.log.info("Plugin devre disi: %s", plugin.name)
            return
        self.plugins.append(plugin)
        self.log.debug("Plugin yuklendi: %s v%s - %s", plugin.name, plugin.version, plugin.description)

    def discover(self, plugins_dir: Optional[Path]) -> None:
        candidates: List[Path] = []
        if plugins_dir and plugins_dir.exists():
            candidates.append(plugins_dir)
        sibling = Path(__file__).parent / "plugins"
        if sibling.exists() and sibling not in candidates:
            candidates.append(sibling)
        if not candidates:
            self.log.debug("Plugin klasoru bulunamadi")
            return

        import importlib.util

        # Plugin'lerin 'from dedekorkut import ...' yapabilmesi icin __main__'i alias et
        if "dedekorkut" not in sys.modules:
            sys.modules["dedekorkut"] = sys.modules.get("__main__", sys.modules[__name__])

        for pdir in candidates:
            for pyfile in sorted(pdir.glob("*.py")):
                if pyfile.name.startswith("_"):
                    continue
                modname = f"dedekorkut_plugin_{pyfile.stem}"
                try:
                    spec = importlib.util.spec_from_file_location(modname, pyfile)
                    if not spec or not spec.loader:
                        continue
                    module = importlib.util.module_from_spec(spec)
                    sys.modules[modname] = module
                    spec.loader.exec_module(module)
                except Exception as exc:  # noqa: BLE001 - kotu plugin tum scani bozmasin
                    self.log.warning("Plugin yuklenemedi (%s): %s", pyfile.name, exc)
                    continue
                # Modulde ScanPlugin'den turemis tum siniflari topla
                for attr in vars(module).values():
                    if (
                        isinstance(attr, type)
                        and issubclass(attr, ScanPlugin)
                        and attr is not ScanPlugin
                    ):
                        try:
                            self.register(attr())
                        except Exception as exc:  # noqa: BLE001
                            self.log.warning("Plugin instance hatasi (%s): %s", attr.__name__, exc)
        self.log.info("Plugin sistemi: %d aktif", len(self.plugins))

    async def run_all(self, result: "PortResult", ctx: PluginContext) -> None:
        for plugin in self.plugins:
            try:
                if not plugin.applies_to(result):
                    continue
                findings = await plugin.run(result, ctx)
                for f in findings or ():
                    if isinstance(f, Finding):
                        result.findings.append(f)
            except asyncio.CancelledError:
                raise
            except Exception as exc:  # noqa: BLE001
                self.log.debug("Plugin %s hata verdi: %s", plugin.name, exc)


# =============================================================================
# STEALTH ENGINE
# =============================================================================
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:124.0) Gecko/20100101 Firefox/124.0",
    "curl/8.5.0",
    "DedeKorkut-Sentinel/4.0",
]


@dataclass
class StealthConfig:
    enabled: bool = False
    jitter_min: float = 0.05
    jitter_max: float = 0.40
    randomize_ports: bool = False
    rotate_ua: bool = False

    @classmethod
    def from_args(cls, args: argparse.Namespace) -> "StealthConfig":
        if not args.stealth:
            return cls()
        return cls(
            enabled=True,
            jitter_min=args.jitter_min,
            jitter_max=args.jitter_max,
            randomize_ports=True,
            rotate_ua=True,
        )

    async def jitter(self) -> None:
        if self.enabled and self.jitter_max > 0:
            await asyncio.sleep(random.uniform(self.jitter_min, self.jitter_max))

    def pick_ua(self) -> str:
        if self.enabled and self.rotate_ua:
            return random.choice(USER_AGENTS)
        return "DedeKorkut-Sentinel/4.0"

    def order_ports(self, ports: Sequence[int]) -> List[int]:
        out = list(ports)
        if self.enabled and self.randomize_ports:
            random.shuffle(out)
        return out


# =============================================================================
# TLS INSPECTOR
# =============================================================================
class TlsInspector:
    """Async-friendly TLS handshake & sertifika otopsisi."""

    def __init__(self, timeout: float, log: logging.Logger):
        self.timeout = timeout
        self.log = log

    async def inspect(self, host: str, port: int) -> Optional[TlsInfo]:
        loop = asyncio.get_running_loop()
        try:
            return await asyncio.wait_for(
                loop.run_in_executor(None, self._inspect_blocking, host, port),
                timeout=self.timeout + 2,
            )
        except asyncio.TimeoutError:
            self.log.debug("TLS timeout: %s:%d", host, port)
            return None
        except Exception as exc:  # noqa: BLE001 - inspeksiyon disinda zincire yansimasin
            self.log.debug("TLS hata %s:%d -> %s", host, port, exc)
            return None

    def _inspect_blocking(self, host: str, port: int) -> Optional[TlsInfo]:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE  # sertifikayi yine de almak istiyoruz
        with socket.create_connection((host, port), timeout=self.timeout) as raw:
            with ctx.wrap_socket(raw, server_hostname=host) as tls:
                cert = tls.getpeercert()
                cipher = tls.cipher() or ("", "", 0)
                version = tls.version() or ""
        if not cert:
            return TlsInfo(version=version, cipher=cipher[0])

        def _flatten(tuples: Sequence[Sequence[Sequence[str]]]) -> str:
            parts = []
            for rdn in tuples or ():
                for k, v in rdn:
                    parts.append(f"{k}={v}")
            return ", ".join(parts)

        subject = _flatten(cert.get("subject", ()))
        issuer = _flatten(cert.get("issuer", ()))
        san = [v for k, v in cert.get("subjectAltName", ()) if k.lower() == "dns"]
        not_before = cert.get("notBefore", "")
        not_after = cert.get("notAfter", "")
        days = 0
        if not_after:
            try:
                exp = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                days = (exp - datetime.now(timezone.utc)).days
            except ValueError:
                pass
        return TlsInfo(
            subject=subject,
            issuer=issuer,
            san=san,
            not_before=not_before,
            not_after=not_after,
            days_to_expiry=days,
            self_signed=(subject == issuer and bool(subject)),
            version=version,
            cipher=cipher[0],
        )


# =============================================================================
# HTTP FINGERPRINTER
# =============================================================================
SECURITY_HEADERS = [
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Referrer-Policy",
    "Permissions-Policy",
]


class HttpFingerprinter:
    """Tam HTTP yanit parse'i: status, server, security headers, title, redirect chain, CORS."""

    MAX_REDIRECTS = 5

    def __init__(self, timeout: float, stealth: StealthConfig, log: logging.Logger):
        self.timeout = timeout
        self.stealth = stealth
        self.log = log

    async def fingerprint(self, ip: str, port: int, use_tls: bool) -> Optional[HttpInfo]:
        scheme = "https" if use_tls else "http"
        url = f"{scheme}://{ip}:{port}/" if ":" not in ip else f"{scheme}://[{ip}]:{port}/"
        loop = asyncio.get_running_loop()
        try:
            return await asyncio.wait_for(
                loop.run_in_executor(None, self._fetch_blocking, url),
                timeout=self.timeout * (self.MAX_REDIRECTS + 1) + 2,
            )
        except asyncio.TimeoutError:
            return None
        except Exception as exc:  # noqa: BLE001
            self.log.debug("HTTP hata %s -> %s", url, exc)
            return None

    def _build_opener(self) -> Tuple[urllib.request.OpenerDirector, ssl.SSLContext]:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        # Redirect'leri elle takip ediyoruz; opener'in otomatigini devre disi
        opener = urllib.request.build_opener(
            urllib.request.HTTPSHandler(context=ctx),
            _NoRedirect(),
        )
        return opener, ctx

    def _fetch_blocking(self, start_url: str) -> HttpInfo:
        info = HttpInfo()
        opener, _ = self._build_opener()
        current = start_url
        for hop_idx in range(self.MAX_REDIRECTS + 1):
            req = urllib.request.Request(current, method="GET", headers={
                "User-Agent": self.stealth.pick_ua(),
                "Accept": "*/*",
                "Connection": "close",
                "Origin": "https://example.com",  # CORS testi icin
            })
            try:
                resp = opener.open(req, timeout=self.timeout)
            except urllib.error.HTTPError as e:
                resp = e  # Hata yanitlari da analiz edilir (401/403/500 vb.)
            except (urllib.error.URLError, OSError) as exc:
                self.log.debug("HTTP %s -> %s", current, exc)
                break

            status = getattr(resp, "status", None) or getattr(resp, "code", 0)
            headers = resp.headers if resp.headers else {}
            server = headers.get("Server", "") if headers else ""
            location = headers.get("Location", "") if headers else ""

            # Sadece son hop'a kadar 'redirect_chain'e hop'lari kaydet
            if status in (301, 302, 303, 307, 308) and location and hop_idx < self.MAX_REDIRECTS:
                info.redirect_chain.append(RedirectHop(status=status, location=location, server=server))
                try:
                    resp.read(0)
                    resp.close()
                except Exception:  # noqa: BLE001
                    pass
                current = urllib.parse.urljoin(current, location)
                continue

            # Son yanit -> tum detaylari topla
            info.status = status
            info.server = server
            info.powered_by = headers.get("X-Powered-By", "")
            info.redirect = location
            info.final_url = current
            info.cors_origin = headers.get("Access-Control-Allow-Origin", "")
            info.cors_credentials = headers.get("Access-Control-Allow-Credentials", "").lower() == "true"
            for h in SECURITY_HEADERS:
                val = headers.get(h, "") if headers else ""
                if val:
                    info.security_headers[h] = val[:120]
                else:
                    info.missing_security_headers.append(h)
            try:
                body = resp.read(8192).decode("utf-8", errors="ignore")
            except Exception:  # noqa: BLE001
                body = ""
            finally:
                try:
                    resp.close()
                except Exception:  # noqa: BLE001
                    pass
            m = re.search(r"<title[^>]*>(.*?)</title>", body, re.IGNORECASE | re.DOTALL)
            if m:
                info.title = re.sub(r"\s+", " ", m.group(1)).strip()[:120]
            return info

        # Redirect limit asildi
        info.final_url = current
        return info


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Redirect'leri urllib'e degil bize biraktirir - chain'i kendimiz yonetiyoruz."""

    def http_error_301(self, req, fp, code, msg, headers):  # noqa: D401
        return fp

    http_error_302 = http_error_303 = http_error_307 = http_error_308 = http_error_301


# =============================================================================
# DNS RECON
# =============================================================================
class DnsRecon:
    """PTR/A/AAAA/MX/NS/TXT sorgulari. dnspython varsa onu, yoksa socket'i kullanir."""

    def __init__(self, timeout: float, log: logging.Logger):
        self.timeout = timeout
        self.log = log

    async def recon(self, host: str) -> DnsInfo:
        info = DnsInfo(host=host)
        loop = asyncio.get_running_loop()
        try:
            info.ptr = await asyncio.wait_for(
                loop.run_in_executor(None, self._reverse, host),
                timeout=self.timeout,
            )
        except Exception:  # noqa: BLE001
            pass

        if not DNSPYTHON_AVAILABLE:
            return info

        resolver = dns.asyncresolver.Resolver()
        resolver.lifetime = self.timeout
        resolver.timeout = self.timeout

        async def _query(name: str, rtype: str) -> List[str]:
            try:
                ans = await resolver.resolve(name, rtype)
                return [r.to_text().strip('"') for r in ans]
            except Exception:  # noqa: BLE001
                return []

        # IP ise A/MX/NS/TXT anlamsiz; sadece hostname ise calistir
        if not self._is_ip(host):
            info.a, info.aaaa, info.mx, info.ns, info.txt = await asyncio.gather(
                _query(host, "A"),
                _query(host, "AAAA"),
                _query(host, "MX"),
                _query(host, "NS"),
                _query(host, "TXT"),
            )
        return info

    def _reverse(self, host: str) -> str:
        try:
            return socket.gethostbyaddr(host)[0]
        except (socket.herror, socket.gaierror):
            return ""

    @staticmethod
    def _is_ip(value: str) -> bool:
        try:
            ipaddress.ip_address(value)
            return True
        except ValueError:
            return False


# =============================================================================
# SHODAN OSINT
# =============================================================================
class ShodanClient:
    def __init__(self, api_key: str, log: logging.Logger, timeout: float = 8.0):
        self.api_key = api_key
        self.log = log
        self.timeout = timeout

    def fetch(self, target_ip: str) -> Optional[Dict[str, Any]]:
        if not self.api_key:
            return None
        url = f"https://api.shodan.io/shodan/host/{target_ip}?key={self.api_key}"
        req = urllib.request.Request(url, headers={"User-Agent": f"DedeKorkut/{__version__}"})
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                if resp.status == 200:
                    return json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as e:
            if e.code == 404:
                self.log.info("Shodan: %s icin kayit yok", target_ip)
            else:
                self.log.warning("Shodan HTTP %d (%s)", e.code, target_ip)
        except urllib.error.URLError as e:
            self.log.warning("Shodan baglanti hatasi: %s", e.reason)
        except json.JSONDecodeError:
            self.log.warning("Shodan: gecersiz JSON yanit")
        return None


# =============================================================================
# SERVICE PROBES (SMB, RDP, jenerik)
# =============================================================================
class ServiceProber:
    def __init__(self, timeout: float, stealth: StealthConfig, log: logging.Logger):
        self.timeout = timeout
        self.stealth = stealth
        self.log = log

    async def grab(self, ip: str, port: int) -> Tuple[str, str]:
        """Bir port icin servis_etiketi, banner ciftini dondurur."""
        if port == 445:
            return "smb", await self._smb(ip)
        if port == 3389:
            return "rdp", await self._rdp(ip)
        return await self._generic(ip, port)

    async def _smb(self, ip: str) -> str:
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, 445), timeout=self.timeout
            )
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:  # noqa: BLE001
                pass
            del reader
            return "SMB/CIFS aktif (kimlik dogrulama gerekli)"
        except (asyncio.TimeoutError, OSError) as exc:
            self.log.debug("SMB probe basarisiz %s: %s", ip, exc)
            return ""

    async def _rdp(self, ip: str) -> str:
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, 3389), timeout=self.timeout
            )
            # X.224 connection request
            writer.write(b"\x03\x00\x00\x13\x0e\xe0\x00\x00\x00\x00\x00\x01\x00\x08\x00\x03\x00\x00\x00")
            await writer.drain()
            data = await asyncio.wait_for(reader.read(64), timeout=self.timeout)
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:  # noqa: BLE001
                pass
            if data and data[:3] == b"\x03\x00\x00":
                return "RDP (Terminal Services - X.224 OK, TLS/NLA yanit verdi)"
            return "RDP servis acik (protokol cevabi belirsiz)"
        except (asyncio.TimeoutError, OSError) as exc:
            self.log.debug("RDP probe basarisiz %s: %s", ip, exc)
            return ""

    async def _generic(self, ip: str, port: int) -> Tuple[str, str]:
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port), timeout=self.timeout
            )
            try:
                # Once pasif bekle (FTP/SSH/SMTP gibi sunucular banner gonderir)
                data = await asyncio.wait_for(reader.read(512), timeout=self.timeout)
                if not data:
                    # Banner yoksa hafif bir prob gonder
                    writer.write(b"\r\n")
                    await writer.drain()
                    data = await asyncio.wait_for(reader.read(512), timeout=self.timeout)
            finally:
                writer.close()
                try:
                    await writer.wait_closed()
                except Exception:  # noqa: BLE001
                    pass
            if not data:
                return self._guess_service(port), ""
            banner = data.decode("utf-8", errors="ignore").strip().splitlines()[0][:200]
            return self._guess_service(port), banner
        except (asyncio.TimeoutError, OSError):
            return self._guess_service(port), ""

    @staticmethod
    def _guess_service(port: int) -> str:
        return {
            21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
            80: "http", 110: "pop3", 143: "imap", 443: "https", 465: "smtps",
            587: "smtp-sub", 993: "imaps", 995: "pop3s", 3306: "mysql",
            5432: "postgres", 6379: "redis", 8080: "http-alt", 8443: "https-alt",
            27017: "mongodb",
        }.get(port, "unknown")


# =============================================================================
# PASIF SNIFFING (Ghost Protocol)
# =============================================================================
class PassiveSniffer:
    def __init__(self, console: Console, log: logging.Logger):
        self.console = console
        self.log = log
        self.count = 0

    def run(self, interface: Optional[str], timeout: int) -> None:
        if not SCAPY_AVAILABLE:
            self.log.error("Pasif dinleme icin 'scapy' yuklenmelidir: pip install scapy")
            return
        if os.name != "nt" and os.geteuid() != 0:
            self.log.error("Pasif dinleme yuksek yetki (sudo) gerektirir")
            return
        self.log.warning("Ghost Protocol devrede - arayuz=%s sure=%ds", interface or "auto", timeout)
        try:
            sniff(iface=interface, prn=self._cb, timeout=timeout, store=0)
        except PermissionError:
            self.log.error("Yetki reddedildi (sudo gerekli)")
        except OSError as exc:
            self.log.error("Arayuz hatasi: %s", exc)
        self.log.warning("Sniff bitti. Toplam paket: %d", self.count)

    def _cb(self, pkt: Any) -> None:
        if not pkt.haslayer(IP):
            return
        self.count += 1
        src, dst = pkt[IP].src, pkt[IP].dst
        if pkt.haslayer(TCP):
            self.console.print(
                f"[green][PASS][/green] {src} ──TCP──> {dst}  "
                f"[{pkt[TCP].sport}->{pkt[TCP].dport} flags={pkt[TCP].flags}]"
            )
        elif pkt.haslayer(UDP):
            self.console.print(
                f"[green][PASS][/green] {src} ──UDP──> {dst}  "
                f"[{pkt[UDP].sport}->{pkt[UDP].dport}]"
            )


# =============================================================================
# ASYNC PORT SCANNER
# =============================================================================
class AsyncScanner:
    def __init__(
        self,
        ctx: ScanContext,
        prober: ServiceProber,
        http_fp: HttpFingerprinter,
        tls: TlsInspector,
        vulndb: VulnerabilityDB,
        stealth: StealthConfig,
        plugins: PluginRegistry,
        timeout: float,
        concurrency: int,
        log: logging.Logger,
    ):
        self.ctx = ctx
        self.prober = prober
        self.http_fp = http_fp
        self.tls = tls
        self.vulndb = vulndb
        self.stealth = stealth
        self.plugins = plugins
        self.timeout = timeout
        self.sem = asyncio.Semaphore(concurrency)
        self.log = log
        self.plugin_ctx = PluginContext(
            timeout=timeout,
            log=log,
            user_agent=stealth.pick_ua(),
            pick_ua=stealth.pick_ua,
        )

    async def scan(self, targets: List[str], ports: List[int], progress, task_id) -> List[PortResult]:
        ordered_ports = self.stealth.order_ports(ports)
        tasks = [
            self._scan_one(ip, port, progress, task_id)
            for ip in targets
            for port in ordered_ports
        ]
        results: List[PortResult] = []
        for coro in asyncio.as_completed(tasks):
            r = await coro
            if r is not None:
                results.append(r)
        return results

    async def _scan_one(self, ip: str, port: int, progress, task_id) -> Optional[PortResult]:
        async with self.sem:
            await self.stealth.jitter()
            await self.ctx.inc_sent()
            t0 = time.monotonic()

            # 1) TCP connect
            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(ip, port), timeout=self.timeout
                )
                writer.close()
                try:
                    await writer.wait_closed()
                except Exception:  # noqa: BLE001
                    pass
                del reader
            except asyncio.TimeoutError:
                progress.update(task_id, advance=1)
                return None
            except OSError:
                progress.update(task_id, advance=1)
                return None

            await self.ctx.inc_open()
            rtt = (time.monotonic() - t0) * 1000

            # 2) Servis tespiti
            service, banner = await self.prober.grab(ip, port)
            result = PortResult(ip=ip, port=port, service=service, banner=banner, rtt_ms=round(rtt, 1))

            # 3) HTTP / TLS fingerprint
            http_ports = {80, 591, 5000, 8000, 8008, 8080, 8081, 8088, 8888, 9000, 9090}
            https_ports = {443, 832, 981, 1311, 4443, 7000, 8443, 9443}
            no_http = {21, 22, 23, 25, 53, 110, 143, 445, 3389, 3306, 5432, 6379, 27017}

            if port in https_ports:
                result.http = await self.http_fp.fingerprint(ip, port, use_tls=True)
                result.tls = await self.tls.inspect(ip, port)
            elif port in http_ports:
                result.http = await self.http_fp.fingerprint(ip, port, use_tls=False)
            elif service in ("smtps", "imaps", "pop3s"):
                result.tls = await self.tls.inspect(ip, port)
            elif port not in no_http and not banner:
                # Fallback: bilinmeyen/non-standard port + bos banner -> HTTP'yi dene
                result.http = await self.http_fp.fingerprint(ip, port, use_tls=False)
                if result.http and 200 <= result.http.status < 600 and result.service == "unknown":
                    result.service = "http"

            # 4) CVE eslestirme (tum metinleri birlestir)
            fragments = [banner, service]
            if result.http:
                fragments += [result.http.server, result.http.powered_by]
            if result.tls:
                fragments += [result.tls.version or "", "self-signed" if result.tls.self_signed else ""]
                if result.tls.days_to_expiry <= 0 and result.tls.not_after:
                    fragments.append("expired")
            result.cves = self.vulndb.match(*fragments)

            # 5) Plugin'ler (sira: HTTP/TLS/CVE'den sonra; bulgular birikir)
            await self.plugins.run_all(result, self.plugin_ctx)

            progress.update(task_id, advance=1)
            return result


# =============================================================================
# OUTPUT WRITERS
# =============================================================================
SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, "": 5}
SEVERITY_COLOR = {"critical": "red", "high": "bright_red", "medium": "yellow", "low": "cyan", "info": "white"}


def _render_table(report: ScanReport, console: Console) -> None:
    table = Table(title=f"Dede Korkut Sentinel - {report.target}", border_style="green", show_lines=False)
    table.add_column("IP", style="cyan", no_wrap=True)
    table.add_column("Port", style="bold red", justify="right")
    table.add_column("Svc", style="white")
    table.add_column("Banner / Server", style="magenta", max_width=42)
    table.add_column("TLS", style="blue", max_width=28)
    table.add_column("HTTP", style="white", max_width=26)
    table.add_column("CVE", style="yellow", max_width=40)

    results = sorted(report.results, key=lambda r: (r.ip, r.port))
    for r in results:
        banner = r.banner or "-"
        if r.http and r.http.server:
            banner = f"[bold]{r.http.server}[/bold] | {banner}"

        tls_s = r.tls.summary() if r.tls else "-"

        http_s = "-"
        if r.http:
            missing = len(r.http.missing_security_headers)
            http_s = f"{r.http.status} sec[-{missing}]"
            if r.http.redirect_chain:
                http_s += f" ↻{len(r.http.redirect_chain)}"
            if r.http.title:
                http_s += f"\n{r.http.title[:30]}"

        lines: List[str] = []
        for c in sorted(r.cves, key=lambda x: SEVERITY_RANK.get(x.get("severity", ""), 9)):
            color = SEVERITY_COLOR.get(c.get("severity", "info"), "white")
            lines.append(f"[{color}]{c['cve']}[/{color}] {c.get('desc', '')[:32]}")
        for f in sorted(r.findings, key=lambda x: SEVERITY_RANK.get(x.severity, 9)):
            color = SEVERITY_COLOR.get(f.severity, "white")
            lines.append(f"[{color}]•[/{color}] [{f.plugin}] {f.title[:38]}")
        cve_s = "\n".join(lines) if lines else "[dim]temiz[/dim]"

        table.add_row(r.ip, str(r.port), r.service or "?", banner, tls_s, http_s, cve_s)
    console.print(table)


def _report_to_dict(report: ScanReport) -> Dict[str, Any]:
    d = asdict(report)
    return d


def write_json(report: ScanReport, path: Path) -> None:
    path.write_text(json.dumps(_report_to_dict(report), indent=2, ensure_ascii=False), encoding="utf-8")


def write_csv(report: ScanReport, path: Path) -> None:
    with path.open("w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow([
            "ip", "port", "service", "banner",
            "http_server", "http_status", "http_final_url", "http_redirect_hops",
            "tls_subject", "tls_expiry_days",
            "cves", "findings", "top_severity",
        ])
        for r in report.results:
            severities = [c.get("severity", "") for c in r.cves] + [f.severity for f in r.findings]
            top = min(severities, key=lambda s: SEVERITY_RANK.get(s, 9)) if severities else ""
            findings_str = ";".join(f"{f.plugin}:{f.severity}:{f.title}" for f in r.findings)
            w.writerow([
                r.ip,
                r.port,
                r.service,
                r.banner,
                r.http.server if r.http else "",
                r.http.status if r.http else "",
                r.http.final_url if r.http else "",
                len(r.http.redirect_chain) if r.http else 0,
                r.tls.subject if r.tls else "",
                r.tls.days_to_expiry if r.tls else "",
                ";".join(c["cve"] for c in r.cves),
                findings_str,
                top,
            ])


def write_html(report: ScanReport, path: Path) -> None:
    """Tek dosyalik, dis baglanti gerektirmeyen HTML raporu."""
    rows = []
    for r in sorted(report.results, key=lambda x: (x.ip, x.port)):
        all_sev = [c.get("severity", "info") for c in r.cves] + [f.severity for f in r.findings]
        top_sev = min(all_sev, key=lambda s: SEVERITY_RANK.get(s, 9), default="info") if all_sev else "info"
        row_cls = f"sev-{top_sev}" if (r.cves or r.findings) else "sev-clean"
        parts = []
        for c in sorted(r.cves, key=lambda x: SEVERITY_RANK.get(x.get("severity", ""), 9)):
            parts.append(
                f"<span class='cve {c.get('severity','info')}'>{html.escape(c['cve'])}</span> "
                f"<span class='dim'>{html.escape(c.get('desc',''))}</span>"
            )
        for f in sorted(r.findings, key=lambda x: SEVERITY_RANK.get(x.severity, 9)):
            ev = f" <span class='dim'>{html.escape(f.evidence[:80])}</span>" if f.evidence else ""
            parts.append(
                f"<span class='cve {f.severity}'>{html.escape(f.plugin)}</span> "
                f"<span>{html.escape(f.title)}</span>{ev}"
            )
        cves_html = "<br>".join(parts) or "<span class='dim'>temiz</span>"
        tls_html = ""
        if r.tls:
            flags = []
            if r.tls.self_signed:
                flags.append("self-signed")
            if r.tls.days_to_expiry <= 0:
                flags.append("EXPIRED")
            elif r.tls.days_to_expiry < 30:
                flags.append(f"expires {r.tls.days_to_expiry}d")
            tls_html = (
                f"{html.escape(r.tls.version or '')}<br>"
                f"<span class='dim'>{html.escape(r.tls.subject[:60])}</span>"
                + (f"<br><span class='warn'>{', '.join(flags)}</span>" if flags else "")
            )
        http_html = ""
        if r.http:
            missing = ", ".join(r.http.missing_security_headers[:4]) if r.http.missing_security_headers else "ok"
            http_html = (
                f"<b>{r.http.status}</b> {html.escape(r.http.server[:40])}<br>"
                f"<span class='dim'>missing sec hdr: {html.escape(missing)}</span>"
            )
            if r.http.redirect_chain:
                hops = " → ".join(f"{h.status}→{html.escape(h.location[:40])}" for h in r.http.redirect_chain)
                http_html += f"<br><span class='dim'>↻ {hops}</span>"
            if r.http.cors_origin == "*" and r.http.cors_credentials:
                http_html += "<br><span class='warn'>CORS: * + creds</span>"
        rows.append(f"""
        <tr class="{row_cls}">
          <td class='mono'>{html.escape(r.ip)}</td>
          <td class='port'>{r.port}</td>
          <td>{html.escape(r.service)}</td>
          <td>{html.escape(r.banner)[:160]}</td>
          <td>{tls_html}</td>
          <td>{http_html}</td>
          <td>{cves_html}</td>
        </tr>""")

    dns_html = ""
    if report.dns:
        dns_rows = []
        for d in report.dns:
            dns_rows.append(
                f"<tr><td class='mono'>{html.escape(d.host)}</td>"
                f"<td>{html.escape(d.ptr or '-')}</td>"
                f"<td>{', '.join(map(html.escape, d.a))}</td>"
                f"<td>{', '.join(map(html.escape, d.mx))}</td>"
                f"<td>{', '.join(map(html.escape, d.ns))}</td>"
                f"<td>{', '.join(html.escape(t[:60]) for t in d.txt)}</td></tr>"
            )
        dns_html = f"""
        <h2>DNS Reconnaissance</h2>
        <table><thead><tr><th>Host</th><th>PTR</th><th>A</th><th>MX</th><th>NS</th><th>TXT</th></tr></thead>
        <tbody>{''.join(dns_rows)}</tbody></table>"""

    css = """
    body { font-family: 'JetBrains Mono', Consolas, monospace; background:#0f1419; color:#e6e1cf; margin:0; padding:24px; }
    h1 { color:#ff3333; border-bottom:1px solid #333; padding-bottom:8px; }
    h2 { color:#39bae6; margin-top:32px; }
    .meta { color:#5c6773; margin-bottom:16px; }
    table { width:100%; border-collapse:collapse; margin-top:8px; font-size:13px; }
    th { background:#1f2430; color:#ffd580; text-align:left; padding:8px; border-bottom:2px solid #ff3333; }
    td { padding:8px; border-bottom:1px solid #1f2430; vertical-align:top; }
    tr.sev-critical { background:rgba(255,51,51,0.12); }
    tr.sev-high     { background:rgba(255,128,64,0.10); }
    tr.sev-medium   { background:rgba(255,214,102,0.08); }
    tr.sev-low      { background:rgba(102,217,239,0.06); }
    .mono { font-family: monospace; color:#39bae6; }
    .port { color:#ff7733; font-weight:bold; }
    .dim  { color:#5c6773; font-size:12px; }
    .warn { color:#ff7733; font-weight:bold; }
    .cve { font-weight:bold; padding:1px 6px; border-radius:3px; }
    .cve.critical { background:#ff3333; color:#fff; }
    .cve.high     { background:#ff7733; color:#fff; }
    .cve.medium   { background:#ffd580; color:#000; }
    .cve.low      { background:#66d9ef; color:#000; }
    .cve.info     { background:#5c6773; color:#fff; }
    .stats { display:flex; gap:24px; }
    .stats div { background:#1f2430; padding:12px 16px; border-radius:6px; border-left:3px solid #ff3333; }
    .stats b { color:#39bae6; }
    """
    stats_html = "".join(
        f"<div>{html.escape(k)}<br><b>{html.escape(str(v))}</b></div>"
        for k, v in report.stats.items()
    )
    shodan_html = ""
    if report.shodan:
        s = report.shodan
        shodan_html = f"""
        <h2>Shodan OSINT</h2>
        <div class='dim'>org: {html.escape(str(s.get('org', '')))} | isp: {html.escape(str(s.get('isp', '')))} | ports: {html.escape(str(s.get('ports', [])))}</div>"""

    doc = f"""<!doctype html><html lang="tr"><head><meta charset="utf-8">
    <title>Dede Korkut Sentinel - {html.escape(report.target)}</title>
    <style>{css}</style></head><body>
    <h1>Dede Korkut Sentinel Report</h1>
    <div class="meta">
      <b>Hedef:</b> {html.escape(report.target)} &nbsp;|&nbsp;
      <b>Baslangic:</b> {html.escape(report.started_at)} &nbsp;|&nbsp;
      <b>Sure:</b> {report.duration_sec:.2f}s &nbsp;|&nbsp;
      <b>Surum:</b> {html.escape(report.version)}
    </div>
    <div class="stats">{stats_html}</div>
    {shodan_html}
    <h2>Port / Servis Bulgular</h2>
    <table><thead><tr>
      <th>IP</th><th>Port</th><th>Servis</th><th>Banner</th><th>TLS</th><th>HTTP</th><th>CVE</th>
    </tr></thead><tbody>{''.join(rows)}</tbody></table>
    {dns_html}
    </body></html>"""
    path.write_text(doc, encoding="utf-8")


# =============================================================================
# HEDEF AYRISTIRMA
# =============================================================================
def parse_targets(spec: str, log: logging.Logger) -> Tuple[List[str], str]:
    """spec -> (cozulmus_ip_listesi, orijinal_hostname_veya_spec)."""
    spec = spec.strip()
    if "/" in spec:
        try:
            net = ipaddress.ip_network(spec, strict=False)
            return [str(ip) for ip in net.hosts()], spec
        except ValueError as exc:
            log.error("Gecersiz CIDR: %s (%s)", spec, exc)
            sys.exit(2)
    try:
        ipaddress.ip_address(spec)
        return [spec], spec
    except ValueError:
        pass
    try:
        infos = socket.getaddrinfo(spec, None, type=socket.SOCK_STREAM)
        ips = sorted({i[4][0] for i in infos if i[4][0]})
        log.info("Cozumlendi: %s -> %s", spec, ", ".join(ips))
        return ips, spec
    except socket.gaierror as exc:
        log.error("Hedef cozulemedi: %s (%s)", spec, exc)
        sys.exit(2)


def parse_ports(spec: str, log: logging.Logger) -> List[int]:
    """'22,80,443' veya '1-1024,3389' formatlarini destekler."""
    ports: set = set()
    for chunk in spec.split(","):
        chunk = chunk.strip()
        if not chunk:
            continue
        if "-" in chunk:
            try:
                lo, hi = (int(x) for x in chunk.split("-", 1))
                if not (1 <= lo <= hi <= 65535):
                    raise ValueError
                ports.update(range(lo, hi + 1))
            except ValueError:
                log.error("Gecersiz port araligi: %s", chunk)
                sys.exit(2)
        else:
            try:
                p = int(chunk)
                if not 1 <= p <= 65535:
                    raise ValueError
                ports.add(p)
            except ValueError:
                log.error("Gecersiz port: %s", chunk)
                sys.exit(2)
    return sorted(ports)


# =============================================================================
# CLI / MAIN
# =============================================================================
def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="dedekorkut",
        description=f"Dede Korkut v{__version__} - Operasyonel Ag Tarama ve Istihbarat Platformu",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    target = p.add_argument_group("Hedef")
    target.add_argument("-t", "--target", help="Hedef IP, domain veya CIDR (orn: 10.0.0.0/24)")
    target.add_argument("-p", "--ports", default="21,22,25,53,80,110,143,443,445,3306,3389,8080,8443",
                        help="Portlar (virgul ve/veya '-' araligi)")

    mode = p.add_argument_group("Mod")
    mode.add_argument("--passive", action="store_true", help="Ghost Protocol: paket gondermeden ag dinle")
    mode.add_argument("--passive-duration", type=int, default=30, help="Pasif dinleme suresi (sn)")
    mode.add_argument("--passive-iface", default=None, help="Pasif dinleme arayuzu (varsayilan auto)")
    mode.add_argument("--dns", action="store_true", help="Hedef icin DNS recon calistir")
    mode.add_argument("--shodan-key", help="Shodan API anahtari (OSINT)")

    perf = p.add_argument_group("Performans")
    perf.add_argument("--timeout", type=float, default=2.0, help="Soket zaman asimi (sn)")
    perf.add_argument("-c", "--concurrency", type=int, default=150, help="Eszamanli baglanti")

    stealth = p.add_argument_group("Stealth")
    stealth.add_argument("--stealth", action="store_true", help="Stealth modu (jitter + randomization + UA rotation)")
    stealth.add_argument("--jitter-min", type=float, default=0.05, help="Jitter alt sinir (sn)")
    stealth.add_argument("--jitter-max", type=float, default=0.40, help="Jitter ust sinir (sn)")

    intel = p.add_argument_group("Istihbarat")
    intel.add_argument("--vuln-db", help="Harici vuln_db.json yolu (default: yan dosya veya gomulu)")

    plug = p.add_argument_group("Plugin")
    plug.add_argument("--plugins-dir", help="Plugin klasoru (default: ./plugins yaninda)")
    plug.add_argument("--no-plugins", action="store_true", help="Plugin sistemini tamamen kapat")
    plug.add_argument("--disable-plugin", action="append", default=[], metavar="NAME",
                      help="Belirli plugin'i devre disi birak (birden fazla kez kullanilabilir)")
    plug.add_argument("--list-plugins", action="store_true", help="Yuklu plugin'leri listele ve cik")

    out = p.add_argument_group("Cikti")
    out.add_argument("-o", "--output", help="Cikti dosyasi (uzantiya gore .json/.csv/.html)")
    out.add_argument("--format", choices=["auto", "json", "csv", "html"], default="auto",
                     help="Cikti formati (auto: dosya uzantisindan)")

    log = p.add_argument_group("Loglama")
    log.add_argument("-v", "--verbose", action="count", default=0, help="-v INFO, -vv DEBUG")
    log.add_argument("-q", "--quiet", action="store_true", help="Sadece hatalari goster")
    log.add_argument("--no-color", action="store_true", help="ANSI renkleri devre disi")
    log.add_argument("--no-banner", action="store_true", help="ASCII banner'i atla")
    log.add_argument("-V", "--version", action="version", version=f"dedekorkut {__version__}")

    return p


def resolve_output_format(args: argparse.Namespace) -> Optional[str]:
    if not args.output:
        return None
    if args.format != "auto":
        return args.format
    ext = Path(args.output).suffix.lower().lstrip(".")
    return ext if ext in {"json", "csv", "html"} else "json"


async def run_active_scan(args: argparse.Namespace, console: Console, log: logging.Logger) -> ScanReport:
    targets, original = parse_targets(args.target, log)
    ports = parse_ports(args.ports, log)
    stealth = StealthConfig.from_args(args)
    vulndb = VulnerabilityDB.load(args.vuln_db, log)

    ctx = ScanContext()
    prober = ServiceProber(args.timeout, stealth, log)
    http_fp = HttpFingerprinter(args.timeout, stealth, log)
    tls = TlsInspector(args.timeout, log)

    plugins = PluginRegistry(log)
    if not args.no_plugins:
        plugins.disable(args.disable_plugin)
        plugins.discover(Path(args.plugins_dir) if args.plugins_dir else None)
    scanner = AsyncScanner(ctx, prober, http_fp, tls, vulndb, stealth, plugins,
                           args.timeout, args.concurrency, log)

    started_at = datetime.now(timezone.utc).isoformat()
    report = ScanReport(
        target=original,
        started_at=started_at,
        targets_resolved=targets,
        ports_scanned=ports,
    )

    # Shodan OSINT (opsiyonel, ana taramayi bloklamayan)
    if args.shodan_key:
        log.info("Shodan OSINT katmani devrede")
        client = ShodanClient(args.shodan_key, log)
        loop = asyncio.get_running_loop()
        report.shodan = await loop.run_in_executor(None, client.fetch, targets[0])
        if report.shodan:
            log.info("Shodan: %d port, org=%s", len(report.shodan.get("ports", [])), report.shodan.get("org", "?"))

    # DNS recon (opsiyonel)
    if args.dns:
        log.info("DNS recon calistiriliyor (dnspython=%s)", DNSPYTHON_AVAILABLE)
        dns_engine = DnsRecon(args.timeout * 2, log)
        report.dns = await asyncio.gather(*(dns_engine.recon(t) for t in [original] + targets[:5]))

    # Ana tarama
    with Progress(
        SpinnerColumn(spinner_name="dots2", style="cyan"),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(style="red", complete_style="green"),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        TextColumn("[dim]({task.completed}/{task.total})[/dim]"),
        TextColumn("[bold cyan]{task.elapsed:.1f}s[/bold cyan]"),
        console=console,
        transient=False,
        disable=args.quiet,
    ) as progress:
        total = len(targets) * len(ports)
        task_id = progress.add_task(
            f"[bold yellow]Tarama {len(targets)} hedef x {len(ports)} port"
            + (" [stealth]" if stealth.enabled else ""),
            total=total,
        )
        report.results = await scanner.scan(targets, ports, progress, task_id)

    report.duration_sec = round(ctx.elapsed(), 2)
    report.finished_at = datetime.now(timezone.utc).isoformat()
    report.stats = {
        "Probe gonderildi": ctx.packets_sent,
        "Acik portlar": len(report.results),
        "CVE eslesmesi": sum(len(r.cves) for r in report.results),
        "Plugin bulgusu": sum(len(r.findings) for r in report.results),
        "Aktif plugin": len(plugins.plugins),
        "Hedef sayisi": len(targets),
        "Port sayisi": len(ports),
        "Stealth": "aktif" if stealth.enabled else "kapali",
    }
    return report


def main() -> None:
    args = build_parser().parse_args()
    console, log = build_logger(args.verbose, args.quiet, args.no_color)

    if not args.no_banner and not args.quiet:
        console.print(Panel(BANNER, border_style="red"))

    if args.list_plugins:
        registry = PluginRegistry(log)
        registry.disable(args.disable_plugin)
        registry.discover(Path(args.plugins_dir) if args.plugins_dir else None)
        table = Table(title="Yuklu Plugin'ler", border_style="cyan")
        table.add_column("Ad", style="bold cyan")
        table.add_column("Versiyon", style="white")
        table.add_column("Aciklama", style="dim")
        for p in registry.plugins:
            table.add_row(p.name, p.version, p.description)
        console.print(table)
        return

    if args.passive:
        PassiveSniffer(console, log).run(args.passive_iface, args.passive_duration)
        return

    if not args.target:
        log.error("Hedef belirtilmedi. Kullanim: -t <ip|domain|cidr> veya --passive")
        sys.exit(1)

    try:
        report = asyncio.run(run_active_scan(args, console, log))
    except KeyboardInterrupt:
        log.warning("Operasyon kullanici komutuyla kesildi")
        sys.exit(130)

    if not args.quiet:
        _render_table(report, console)
        console.print(
            f"\n[bold white]Tamamlandi:[/bold white] {report.duration_sec:.2f}s | "
            f"Probe={report.stats['Probe gonderildi']} | "
            f"Acik={report.stats['Acik portlar']} | "
            f"CVE={report.stats['CVE eslesmesi']} | "
            f"Plugin={report.stats['Plugin bulgusu']} ({report.stats['Aktif plugin']} aktif)"
        )

    out_format = resolve_output_format(args)
    if out_format and args.output:
        out_path = Path(args.output)
        try:
            {"json": write_json, "csv": write_csv, "html": write_html}[out_format](report, out_path)
            log.warning("Rapor yazildi: %s (%s)", out_path, out_format)
        except OSError as exc:
            log.error("Cikti yazilamadi: %s", exc)
            sys.exit(3)


if __name__ == "__main__":
    main()

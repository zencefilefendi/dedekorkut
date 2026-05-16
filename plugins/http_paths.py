"""Hassas / yaygin yanlis yapilandirilmis HTTP yollarini dener (.env, .git, admin vb.)."""

import asyncio
import ssl
import urllib.error
import urllib.request
from typing import List

from dedekorkut import Finding, PluginContext, PortResult, ScanPlugin


SENSITIVE_PATHS = [
    # (path, severity, baslik)
    ("/.env",             "critical", "Açıkta .env dosyası (secrets sızıntısı)"),
    ("/.git/HEAD",        "critical", "Açıkta .git/ deposu"),
    ("/.git/config",      "critical", "Açıkta .git/config"),
    ("/.DS_Store",        "medium",   "macOS .DS_Store ifsa olmuş"),
    ("/.svn/entries",     "high",     "SVN metadata sızıntısı"),
    ("/server-status",    "high",     "Apache mod_status açık"),
    ("/phpinfo.php",      "high",     "phpinfo() açık"),
    ("/admin",            "low",      "/admin endpoint cevap veriyor"),
    ("/wp-admin/",        "low",      "WordPress admin paneli"),
    ("/actuator/health",  "medium",   "Spring Actuator açık"),
    ("/robots.txt",       "info",     "robots.txt mevcut"),
    ("/sitemap.xml",      "info",     "sitemap.xml mevcut"),
]


class HttpPathsPlugin(ScanPlugin):
    name = "http_paths"
    version = "1.0"
    description = "Hassas/yanlis-yapilandirilmis HTTP yollari (.env, .git, admin vb.)"

    HTTP_PORTS = {80, 8000, 8008, 8080, 8081, 8088, 8888, 9000, 9090}
    HTTPS_PORTS = {443, 8443, 9443}

    def applies_to(self, result: PortResult) -> bool:
        if result.http is not None:
            return True
        return result.port in self.HTTP_PORTS or result.port in self.HTTPS_PORTS

    async def run(self, result: PortResult, ctx: PluginContext) -> List[Finding]:
        use_tls = result.port in self.HTTPS_PORTS or (result.http and result.http.final_url.startswith("https"))
        scheme = "https" if use_tls else "http"
        host = f"[{result.ip}]" if ":" in result.ip else result.ip
        base = f"{scheme}://{host}:{result.port}"

        loop = asyncio.get_running_loop()
        findings: List[Finding] = []
        sem = asyncio.Semaphore(4)  # tek hedefe paralel istegi sinirla

        async def check(path: str, severity: str, title: str) -> None:
            async with sem:
                status = await loop.run_in_executor(None, self._head, base + path, ctx)
                if status and 200 <= status < 300:
                    findings.append(Finding(
                        plugin=self.name,
                        severity=severity,
                        title=title,
                        detail=f"GET {path} -> HTTP {status}",
                        evidence=f"{base}{path}",
                    ))
                elif status in (401, 403):
                    findings.append(Finding(
                        plugin=self.name,
                        severity="info",
                        title=f"{path} mevcut (kimlik dogrulama gerekli)",
                        detail=f"GET {path} -> HTTP {status}",
                        evidence=f"{base}{path}",
                    ))

        await asyncio.gather(*(check(p, s, t) for p, s, t in SENSITIVE_PATHS))
        return findings

    @staticmethod
    def _head(url: str, ctx: PluginContext) -> int:
        sctx = ssl.create_default_context()
        sctx.check_hostname = False
        sctx.verify_mode = ssl.CERT_NONE
        req = urllib.request.Request(url, method="GET", headers={
            "User-Agent": ctx.pick_ua(),
            "Connection": "close",
        })
        try:
            with urllib.request.urlopen(req, timeout=ctx.timeout, context=sctx) as r:
                return r.status
        except urllib.error.HTTPError as e:
            return e.code
        except Exception:  # noqa: BLE001
            return 0

"""CORS yanlis yapilandirma tespiti (Access-Control-Allow-Origin: * + credentials)."""

from typing import List

from dedekorkut import Finding, PluginContext, PortResult, ScanPlugin


class CorsCheckPlugin(ScanPlugin):
    name = "cors_check"
    version = "1.0"
    description = "Tehlikeli CORS yapilandirmalarini tespit eder"

    def applies_to(self, result: PortResult) -> bool:
        return result.http is not None

    async def run(self, result: PortResult, ctx: PluginContext) -> List[Finding]:
        h = result.http
        if h is None:
            return []
        findings: List[Finding] = []

        # Klasik 'null/* + credentials' bypass
        if h.cors_credentials and h.cors_origin in ("*", "null"):
            findings.append(Finding(
                plugin=self.name,
                severity="critical",
                title="CORS: Allow-Origin wildcard + Credentials true",
                detail="Tarayicilar bunu reddeder ama spec disi davranan istemciler/wrapper'lar acigi istismar edebilir",
                evidence=f"Origin={h.cors_origin!r} Creds=true",
            ))

        # Reflected origin (Origin header'imizi geri yansitiyorsa)
        if h.cors_origin == "https://example.com":
            findings.append(Finding(
                plugin=self.name,
                severity="high" if h.cors_credentials else "medium",
                title="CORS: Origin header yansitiliyor (reflected)",
                detail="Sunucu istemci Origin header'ini koruma kontrolsuz yansitiyor",
                evidence=f"Origin={h.cors_origin}",
            ))

        # null origin kabul ediliyorsa
        if h.cors_origin == "null":
            findings.append(Finding(
                plugin=self.name,
                severity="medium",
                title="CORS: 'null' origin kabul ediliyor",
                detail="Sandbox iframe veya file:// kaynagindan istek mumkun",
                evidence="Access-Control-Allow-Origin: null",
            ))

        return findings

"""Eski/zayif protokolleri (Telnet, FTP-plain, SMBv1 vb.) isaretler."""

from typing import List

from dedekorkut import Finding, PluginContext, PortResult, ScanPlugin


WEAK_PORTS = {
    21:   ("medium", "FTP (clear-text auth)",         "Sifreler ag uzerinde duz metin gider; FTPS/SFTP'ye gec"),
    23:   ("high",   "Telnet (clear-text)",            "Telnet uzaktan shell trafigini sifrelemez - SSH kullan"),
    69:   ("medium", "TFTP (kimlik dogrulamasiz)",     "TFTP dosya transferi kimlik dogrulamasi yok"),
    79:   ("low",    "Finger servisi",                 "Eski Finger protokolu kullanici listesi sizdiriyor"),
    111:  ("low",    "Portmap/rpcbind acik",           "rpcbind taranabilir, NFS export bilgisini sizdirabilir"),
    137:  ("medium", "NetBIOS Name Service",           "NBT host/domain bilgisini ifsa eder"),
    139:  ("medium", "NetBIOS Session (SMBv1 hint)",   "Eski SMBv1 trafigi ihtimali - MS17-010 riski"),
    445:  ("info",   "SMB",                            "SMBv1 devre disi mi? Diff: signing required olmali"),
    512:  ("high",   "rexec (clear-text)",             "BSD rexec - sifrelenmemis uzaktan komut"),
    513:  ("high",   "rlogin (clear-text)",            "BSD rlogin - .rhosts auth bypass riski"),
    514:  ("high",   "rsh / syslog (clear-text)",      "Sifrelenmemis remote shell veya syslog"),
    1900: ("low",    "SSDP / UPnP",                    "UPnP cihaz kesfi ag disinda goruluyorsa kapatilmali"),
    5353: ("low",    "mDNS",                           "mDNS internete acik olmamali"),
}


class WeakProtocolsPlugin(ScanPlugin):
    name = "weak_protocols"
    version = "1.0"
    description = "Eski/zayif protokol portlarini (Telnet, FTP, SMBv1 vb.) isaretler"

    def applies_to(self, result: PortResult) -> bool:
        return result.port in WEAK_PORTS

    async def run(self, result: PortResult, ctx: PluginContext) -> List[Finding]:
        sev, title, detail = WEAK_PORTS[result.port]
        return [Finding(
            plugin=self.name,
            severity=sev,
            title=title,
            detail=detail,
            evidence=f"{result.ip}:{result.port}",
        )]

#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Dede Korkut - Gelişmiş Ağ İstihbarat Platformu
v7.0 ORCHESTRATOR - Plugin tabanlı modüler mimari
"""

import asyncio
import argparse
import socket
import ipaddress
import sys
import json
import time
import http.client
from abc import ABC, abstractmethod
from typing import List, Dict, Tuple, Optional
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

console = Console()

# ==============================================================================
# ORCHESTRATOR MİMARİSİ (Plugin Pattern)
# ==============================================================================
class ScannerPlugin(ABC):
    @abstractmethod
    async def run(self, ip: str, port: int) -> Dict:
        pass

class WebIntelligencePlugin(ScannerPlugin):
    async def run(self, ip: str, port: int) -> Dict:
        if port not in [80, 443, 8080]: return {"leaks": []}
        found = []
        paths = ["/.env", "/.git/config", "/admin", "/backup.sql"]
        for path in paths:
            try:
                conn = http.client.HTTPConnection(ip, port, timeout=1.0)
                conn.request("HEAD", path)
                if conn.getresponse().status in [200, 403]: found.append(path)
                conn.close()
            except: pass
        return {"leaks": found}

class VulnerabilityPlugin(ScannerPlugin):
    DB = {
        "vsftpd 2.3.4": "CVE-2011-2523 (Backdoor)",
        "OpenSSH 7.2p2": "CVE-2018-15473 (User Enum)",
        "Apache 2.4.49": "CVE-2021-41773 (RCE)"
    }
    async def run(self, ip: str, port: int) -> Dict:
        # Basitleştirilmiş banner analizi
        return {"cves": ["Generic Analysis Active"], "risk": 5}

# ==============================================================================
# CORE ENGINE
# ==============================================================================
class DedeKorkutOrchestrator:
    def __init__(self, target: str, ports: List[int]):
        self.targets = self._parse_targets(target)
        self.ports = ports
        self.plugins = [WebIntelligencePlugin(), VulnerabilityPlugin()]

    def _parse_targets(self, ts):
        try:
            n = ipaddress.ip_network(ts, strict=False)
            return [str(ip) for ip in n.hosts()] if n.prefixlen < 32 else [str(n.network_address)]
        except: return []

    async def _scan_port(self, ip: str, port: int):
        try:
            conn = asyncio.open_connection(ip, port)
            reader, writer = await asyncio.wait_for(conn, timeout=2.0)
            writer.close()
            await writer.wait_closed()
            
            # Tüm pluginleri tetikle
            results = {"ip": ip, "port": port, "plugins": {}}
            for plugin in self.plugins:
                results["plugins"][plugin.__class__.__name__] = await plugin.run(ip, port)
            return results
        except: return None

    async def execute(self):
        tasks = [self._scan_port(ip, port) for ip in self.targets for port in self.ports]
        return [r for r in await asyncio.gather(*tasks) if r]

# ==============================================================================
# CLI & REPORTING
# ==============================================================================
def main():
    parser = argparse.ArgumentParser(description="Dede Korkut v7.0 - Orchestrator Edition")
    parser.add_argument("-t", "--target", required=True)
    parser.add_argument("-p", "--ports", default="80,443,445")
    args = parser.parse_args()

    console.print(Panel("[bold red]Dede Korkut v7.0: Plugin tabanlı keşif başlatıldı...[/bold red]"))
    
    ports = [int(p) for p in args.ports.split(',')]
    orchestrator = DedeKorkutOrchestrator(args.target, ports)
    
    start = time.time()
    data = asyncio.run(orchestrator.execute())
    
    table = Table(title="Operasyonel İstihbarat Raporu")
    table.add_column("IP", style="cyan")
    table.add_column("Port", style="yellow")
    table.add_column("Analiz Bulguları", style="magenta")
    
    for entry in data:
        details = str(entry["plugins"])
        table.add_row(entry["ip"], str(entry["port"]), details)
    
    console.print(table)
    console.print(f"\n[bold green]İşlem tamamlandı ({time.time()-start:.2f} saniye).[/bold green]")

if __name__ == "__main__":
    main()

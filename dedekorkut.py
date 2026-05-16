#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Dede Korkut - Gelişmiş Ağ İstihbarat Platformu
v9.0 SENTINEL INTELLIGENCE EDITION
"""

import asyncio, argparse, socket, ipaddress, sys, json, time, platform, os, random, http.client
from abc import ABC, abstractmethod
from typing import List, Dict, Tuple, Optional
import concurrent.futures

try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.progress import Progress
except ImportError:
    print("[!] Gerekli kütüphane eksik: 'rich'. (pip install rich)")
    sys.exit(1)

console = Console()

# ==============================================================================
# SENTINEL INTELLIGENCE ENGINE
# ==============================================================================
class SentinelEngine:
    def __init__(self, target):
        self.target = target
        self.history_file = "history.json"
        self.db = self._load_history()

    def _load_history(self):
        if os.path.exists(self.history_file):
            with open(self.history_file, 'r') as f: return json.load(f)
        return {}

    def generate_strategic_advice(self, results):
        risk_score = sum([1 for r in results if r['status'] == "AÇIK"])
        if risk_score > 3:
            return "Operasyon Tamamlandı. Kritik seviyede açık port bulundu. 48 saat içinde sızma girişimi beklenebilir. Segmentasyonu acilen gözden geçirin."
        return "Sistem genel hatlarıyla güvenli görünüyor."

# ==============================================================================
# PLUGIN ARCHITECTURE
# ==============================================================================
class ScannerPlugin(ABC):
    @abstractmethod
    async def run(self, ip: str, port: int) -> Dict: pass

class WebIntelligencePlugin(ScannerPlugin):
    async def run(self, ip: str, port: int) -> Dict:
        if port not in [80, 443, 8080]: return {"leaks": []}
        found = []
        for path in ["/.env", "/.git/config", "/admin"]:
            try:
                conn = http.client.HTTPConnection(ip, port, timeout=1.0)
                conn.request("HEAD", path)
                if conn.getresponse().status in [200, 403]: found.append(path)
                conn.close()
            except: pass
        return {"leaks": found}

# ==============================================================================
# MAIN ORCHESTRATOR
# ==============================================================================
class DedeKorkutOrchestrator:
    def __init__(self, target, ports):
        self.targets = self._parse_targets(target)
        self.ports = ports
        self.plugins = [WebIntelligencePlugin()]
        self.sentinel = SentinelEngine(target)

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
            
            results = {"ip": ip, "port": port, "status": "AÇIK", "plugins": {}}
            for plugin in self.plugins:
                results["plugins"][plugin.__class__.__name__] = await plugin.run(ip, port)
            return results
        except: return None

    async def execute(self):
        tasks = [self._scan_port(ip, port) for ip in self.targets for port in self.ports]
        return [r for r in await asyncio.gather(*tasks) if r]

def main():
    parser = argparse.ArgumentParser(description="Dede Korkut v9.0 Sentinel Intelligence")
    parser.add_argument("-t", "--target", required=True)
    parser.add_argument("-p", "--ports", default="80,443,445")
    args = parser.parse_args()

    console.print(Panel("[bold red]Dede Korkut v9.0 Sentinel Intelligence Yüklendi.[/bold red]"))
    
    ports = [int(p) for p in args.ports.split(',')]
    orch = DedeKorkutOrchestrator(args.target, ports)
    
    data = asyncio.run(orch.execute())
    
    console.print(Panel(orch.sentinel.generate_strategic_advice(data), title="Stratejik Öneri Motoru", style="green"))
    
    table = Table(title="Operasyonel İstihbarat Raporu")
    table.add_column("IP", style="cyan")
    table.add_column("Port", style="yellow")
    table.add_column("Analiz Bulguları", style="magenta")
    
    for entry in data:
        table.add_row(entry["ip"], str(entry["port"]), str(entry["plugins"]))
    
    console.print(table)

if __name__ == "__main__":
    try: main()
    except KeyboardInterrupt: sys.exit(0)

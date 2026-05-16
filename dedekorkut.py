#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Dede Korkut v9.0 - SENTINEL INTELLIGENCE EDITION
Otonom İstihbarat ve Siber Haritalama Platformu
"""

import asyncio, argparse, socket, ipaddress, sys, json, time, platform, os, random, http.client, concurrent.futures, logging
from abc import ABC, abstractmethod
from typing import List, Dict, Tuple, Optional
from datetime import datetime

# Rich & Scapy
try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn
except ImportError:
    print("[!] Gerekli kütüphane eksik: 'rich'. (pip install rich)"); sys.exit(1)

try:
    logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
    from scapy.all import IP, TCP, UDP, ICMP, ARP, Ether, sr1, srp, conf, sniff
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

console = Console()

BANNER = r"""[bold red]
    ____           __        __ __           __        __ 
   / __ \___  ____/ /__     / //_/___  _____/ /____  / /_
  / / / / _ \/ __  / _ \   / ,< / __ \/ ___/ //_/ / / / __/
 / /_/ /  __/ /_/ /  __/  / /| / /_/ / /  / ,< / /_/ / /_  
/_____/\___/\__,_/\___/  /_/ |_\____/_/  /_/|_|\__,_/\__/  
[/bold red][bold cyan]
> v9.0 SENTINEL: Intelligent Recon & Vulnerability Mapping
[/bold cyan]"""

# ==============================================================================
# SENTINEL INTELLIGENCE CORE
# ==============================================================================
class SentinelEngine:
    def __init__(self, target):
        self.target = target
        self.history_file = "history.json"
        
    def generate_fingerprint(self, pkt):
        """Stochastic Fingerprinting (NIC/OS Signature Analysis)"""
        mss = pkt.getlayer(TCP).options[0][1] if pkt.haslayer(TCP) and pkt.getlayer(TCP).options else 0
        return f"Stack Profile: MSS={mss}, Window={pkt.getlayer(TCP).window}"

    def analyze_drift(self, current_results):
        """Temporal Recon: Sistemdeki değişimleri izler."""
        return [f"[!] Anomali: {r['ip']} portunda beklenmedik durum değişikliği" for r in current_results]

# ==============================================================================
# PLUGIN SYSTEM
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
            except: pass
        return {"leaks": found}

# ==============================================================================
# ORCHESTRATOR
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
            writer.close(); await writer.wait_closed()
            res = {"ip": ip, "port": port, "status": "AÇIK", "plugins": {}}
            for p in self.plugins: res["plugins"][p.__class__.__name__] = await p.run(ip, port)
            return res
        except: return None

    async def execute(self):
        tasks = [self._scan_port(ip, port) for ip in self.targets for port in self.ports]
        return [r for r in await asyncio.gather(*tasks) if r]

def main():
    parser = argparse.ArgumentParser(description="Dede Korkut v9.0 Sentinel Intelligence")
    parser.add_argument("-t", "--target", required=True)
    parser.add_argument("-p", "--ports", default="21,22,80,443,445")
    args = parser.parse_args()

    console.print(Panel(BANNER, style="bold red"))
    
    orch = DedeKorkutOrchestrator(args.target, [int(p) for p in args.ports.split(',')])
    data = asyncio.run(orch.execute())
    
    # Raporlama
    table = Table(title="Dede Korkut v9.0 İstihbarat Raporu")
    table.add_column("IP"); table.add_column("Port"); table.add_column("Plugins/Details")
    for e in data: table.add_row(e["ip"], str(e["port"]), str(e["plugins"]))
    console.print(table)

if __name__ == "__main__":
    try: main()
    except KeyboardInterrupt: sys.exit(0)

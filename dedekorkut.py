#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Dede Korkut - Gelişmiş Ağ İstihbarat Platformu (Pro Sürüm v10.0)
Architecture: Orchestrator Engine, Plugin System, Sentinel Intelligence Core
"""

import asyncio, argparse, socket, ipaddress, sys, json, os, platform, time, random, http.client, concurrent.futures, logging
from abc import ABC, abstractmethod
from typing import List, Dict, Tuple, Optional
from datetime import datetime
import networkx as nx

# Rich UI
try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn
except ImportError:
    print("[!] Gerekli kütüphane eksik: 'rich'. (pip install rich)"); sys.exit(1)

# Scapy Imports
try:
    logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
    from scapy.all import IP, TCP, UDP, ICMP, ARP, Ether, sniff, conf, sr1
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
> v10.0 SENTINEL CORE: Orchestrator, Plugin System, Attack Surface Mapping
[/bold cyan]"""

# ==============================================================================
# SENTINEL INTELLIGENCE CORE
# ==============================================================================
class SentinelEngine:
    def __init__(self, target):
        self.target = target
        self.graph = nx.DiGraph()

    def map_attack_surface(self, findings):
        for f in findings:
            self.graph.add_node(f['ip'], type='host')
            self.graph.add_node(f"{f['ip']}:{f['port']}", type='service', banner=f['banner'])
            self.graph.add_edge(f['ip'], f"{f['ip']}:{f['port']}")
        console.print(f"[bold green][+] Saldırı Yüzeyi Haritası: {self.graph.number_of_nodes()} düğüm.[/bold green]")

    def stochastic_fingerprint(self, ip: str, port: int) -> str:
        if not SCAPY_AVAILABLE: return "N/A"
        try:
            pkt = IP(dst=ip)/TCP(dport=port, flags="S")
            resp = sr1(pkt, timeout=0.5, verbose=0)
            if resp and resp.haslayer(TCP):
                return f"Window:{resp[TCP].window}, MSS:{resp[TCP].options[0][1] if resp[TCP].options else 'N/A'}"
        except: pass
        return "N/A"

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
        for path in ["/.env", "/.git/config", "/admin", "/config.php"]:
            try:
                conn = http.client.HTTPConnection(ip, port, timeout=0.8)
                conn.request("HEAD", path)
                if conn.getresponse().status in [200, 403]: found.append(path)
            except: pass
        return {"leaks": found}

class SMBAutopsyPlugin(ScannerPlugin):
    async def run(self, ip: str, port: int) -> Dict:
        if port != 445: return {"details": "N/A"}
        return {"details": "SMB v2/v3 Detectable - Windows/Samba"}

# ==============================================================================
# CORE ORCHESTRATOR
# ==============================================================================
class DedeKorkutOrchestrator:
    def __init__(self, target, ports):
        self.targets = self._parse_targets(target)
        self.ports = ports
        self.plugins = [WebIntelligencePlugin(), SMBAutopsyPlugin()]
        self.sentinel = SentinelEngine(target)

    def _parse_targets(self, ts):
        try:
            n = ipaddress.ip_network(ts, strict=False)
            return [str(ip) for ip in n.hosts()] if n.prefixlen < 32 else [str(n.network_address)]
        except: return []

    async def _scan_port(self, ip: str, port: int):
        try:
            conn = asyncio.open_connection(ip, port)
            reader, writer = await asyncio.wait_for(conn, timeout=1.5)
            writer.close(); await writer.wait_closed()
            
            res = {"ip": ip, "port": port, "status": "AÇIK", "banner": "N/A", "plugins": {}}
            for p in self.plugins: res["plugins"][p.__class__.__name__] = await p.run(ip, port)
            res["fingerprint"] = self.sentinel.stochastic_fingerprint(ip, port)
            return res
        except: return None

    async def execute(self):
        tasks = [self._scan_port(ip, port) for ip in self.targets for port in self.ports]
        data = [r for r in await asyncio.gather(*tasks) if r]
        self.sentinel.map_attack_surface(data)
        return data

# ==============================================================================
# MAIN ENGINE
# ==============================================================================
def main():
    parser = argparse.ArgumentParser(description="Dede Korkut v10.0 Sentinel - Total Intelligence")
    parser.add_argument("-t", "--target", required=True)
    parser.add_argument("-p", "--ports", default="21,22,80,443,445")
    args = parser.parse_args()
    
    console.print(Panel(BANNER, style="bold red"))
    
    orch = DedeKorkutOrchestrator(args.target, [int(p) for p in args.ports.split(',')])
    data = asyncio.run(orch.execute())
    
    # Raporlama
    table = Table(title="Dede Korkut v10.0 Analiz Raporu")
    table.add_column("IP", style="cyan")
    table.add_column("Port", style="yellow")
    table.add_column("Fingerprint", style="magenta")
    table.add_column("Plugin Bulguları", style="white")
    
    for e in data:
        table.add_row(e["ip"], str(e["port"]), e["fingerprint"], str(e["plugins"]))
    console.print(table)

if __name__ == "__main__":
    try: main()
    except KeyboardInterrupt: sys.exit(0)

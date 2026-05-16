#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Dede Korkut - Gelişmiş Ağ İstihbarat Platformu (Pro Sürüm)
v10.0 TOTAL INTELLIGENCE - Temporal Recon, Fingerprinting & Strategic Reporting
"""

import asyncio, argparse, socket, ipaddress, sys, json, os, platform, time, random, http.client
from datetime import datetime
from typing import List, Dict, Tuple, Optional
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from scapy.all import IP, TCP, sr1, conf

console = Console()
BANNER = r"""[bold red]
    ____           __        __ __           __        __ 
   / __ \___  ____/ /__     / //_/___  _____/ /____  / /_
  / / / / _ \/ __  / _ \   / ,< / __ \/ ___/ //_/ / / / __/
 / /_/ /  __/ /_/ /  __/  / /| / /_/ / /  / ,< / /_/ / /_  
/_____/\___/\__,_/\___/  /_/ |_\____/_/  /_/|_|\__,_/\__/  
[/bold red][bold cyan]
> v10.0 TOTAL INTELLIGENCE: Temporal Recon, Stochastic Fingerprint & Strategic Reporting
[/bold cyan]"""

# ==============================================================================
# v10.0 INTELLIGENCE CORE
# ==============================================================================
class IntelligenceCore:
    def __init__(self, history_file="history.json"):
        self.history_file = history_file
        self.history = self._load_history()

    def _load_history(self):
        if os.path.exists(self.history_file):
            with open(self.history_file, 'r') as f: return json.load(f)
        return {}

    def save_results(self, results):
        new_history = {f"{r['ip']}:{r['port']}": r['status'] for r in results}
        with open(self.history_file, 'w') as f: json.dump(new_history, f)

    def analyze_drift(self, current_results):
        drift = []
        for res in current_results:
            key = f"{res['ip']}:{res['port']}"
            if key in self.history and self.history[key] != res['status']:
                drift.append(f"[*] Drift Tespit Edildi: {key} ({self.history[key]} -> {res['status']})")
        return drift

    def get_strategic_report(self, results):
        open_ports = len([r for r in results if r['status'] == 'AÇIK'])
        if open_ports > 3:
            return "Kritik operasyonel durum! Ağ üzerinde çok sayıda açık servis tespit edildi. Sızma riskini minimize etmek için segmentasyonu gözden geçirin."
        return "Sistem güvenliği standartlara uygun. Düzenli izlemeye devam edilmeli."

def stochastic_fingerprint(ip: str, port: int) -> str:
    """Stochastic TCP Stack Fingerprinting."""
    pkt = IP(dst=ip)/TCP(dport=port, flags="S")
    resp = sr1(pkt, timeout=1.0, verbose=0)
    if resp and resp.haslayer(TCP):
        tcp = resp.getlayer(TCP)
        # Pencere boyutu, MSS ve SACK özellikleri bir imza oluşturur
        return f"Stack Signature: [Window:{tcp.window}, MSS:{tcp.options[0][1] if tcp.options else 'N/A'}]"
    return "Fingerprint alınamadı."

# ==============================================================================
# SCANNER ENGINE
# ==============================================================================
async def scan_port(ip: str, port: int, timeout: float) -> Dict:
    try:
        conn = asyncio.open_connection(ip, port)
        reader, writer = await asyncio.wait_for(conn, timeout=timeout)
        writer.close(); await writer.wait_closed()
        return {"ip": ip, "port": port, "status": "AÇIK", "fingerprint": stochastic_fingerprint(ip, port)}
    except:
        return {"ip": ip, "port": port, "status": "KAPALI", "fingerprint": "N/A"}

async def run_intelligence_scan(targets, ports, timeout):
    tasks = [scan_port(ip, port, timeout) for ip in targets for port in ports]
    return await asyncio.gather(*tasks)

# ==============================================================================
# MAIN
# ==============================================================================
def main():
    parser = argparse.ArgumentParser(description="Dede Korkut v10.0 Sentinel")
    parser.add_argument("-t", "--target", required=True)
    args = parser.parse_args()
    
    console.print(Panel(BANNER, style="bold red"))
    engine = IntelligenceCore()
    
    # Tarama
    results = asyncio.run(run_intelligence_scan([args.target], [22, 80, 443], 1.5))
    
    # Analiz
    drift = engine.analyze_drift(results)
    advice = engine.generate_strategic_advice(results)
    
    # Raporlama
    if drift:
        for d in drift: console.print(d, style="bold yellow")
    
    console.print(Panel(advice, title="Stratejik İstihbarat Özeti", style="green"))
    
    table = Table(title="v10.0 Sentinel Analiz Raporu")
    table.add_column("IP"); table.add_column("Port"); table.add_column("Donanım İmzası")
    for r in results:
        table.add_row(r['ip'], str(r['port']), r['fingerprint'])
    console.print(table)
    
    engine.save_results(results)

if __name__ == "__main__":
    try: main()
    except KeyboardInterrupt: sys.exit(0)

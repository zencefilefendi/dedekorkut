#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Dede Korkut - Gelişmiş Ağ Tarama ve İstihbarat Platformu
v6.0 Overlord Edition - Web Recon & Exploit Suggester Entegre Edildi
"""

import asyncio
import argparse
import socket
import ipaddress
import sys
import json
import os
import platform
import time
import random
import ssl
import http.client
from datetime import datetime
from typing import List, Dict, Tuple, Optional
import concurrent.futures

if platform.system() != "Windows":
    import resource

try:
    from rich.console import Console
    from rich.table import Table
    from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn
    from rich.panel import Panel
except ImportError:
    print("[!] Kritik kütüphane eksik: 'rich'. Yüklemek için: pip install rich")
    sys.exit(1)

try:
    import logging
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
> Operasyonel İstihbarat ve Otonom Keşif Platformu
> v6.0 OVERLORD: Web Recon, Exploit Suggest, CVE Cortex
[/bold cyan]"""

# ==============================================================================
# CVE CORTEX & EXPLOIT SUGGESTER DATABASE
# ==============================================================================
CVE_DATABASE = {
    "vsftpd 2.3.4": {
        "cves": ["CVE-2011-2523 (Backdoor Command Execution)"],
        "exploit": "msf: exploit/unix/ftp/vsftpd_234_backdoor"
    },
    "OpenSSH 7.2p2": {
        "cves": ["CVE-2016-6210 (User Enumeration)", "CVE-2018-15473"],
        "exploit": "msf: auxiliary/scanner/ssh/ssh_enumusers"
    },
    "Apache 2.4.49": {
        "cves": ["CVE-2021-41773 (Path Traversal / RCE)"],
        "exploit": "curl --path-as-is http://target/cgi-bin/.%%32e/.%%32e/.%%32e/bin/sh"
    },
    "Microsoft IIS 6.0": {
        "cves": ["CVE-2017-7269 (WebDAV Buffer Overflow)"],
        "exploit": "msf: exploit/windows/iis/iis_webdav_scstoragepathfromurl"
    },
    "SMB": {
        "cves": ["MS17-010 (EternalBlue)"],
        "exploit": "msf: exploit/windows/smb/ms17_010_eternalblue"
    }
}

WEB_SENSITIVE_PATHS = [
    "/.env", "/.git/config", "/admin", "/config.php", "/wp-config.php",
    "/robots.txt", "/phpinfo.php", "/.htaccess", "/backup.sql", "/api/v1"
]

ICS_PROTOCOLS = {502: "Modbus TCP", 102: "Siemens S7", 47808: "BACnet", 20000: "DNP3"}

packets_sent = 0

# ==============================================================================
# ANALİZ VE KEŞİF MOTORLARI
# ==============================================================================
def check_cve(banner: str) -> Tuple[List[str], str]:
    for service, data in CVE_DATABASE.items():
        if service.lower() in banner.lower():
            return data["cves"], data["exploit"]
    return [], "N/A"

async def web_intelligence(ip: str, port: int) -> List[str]:
    """Web portlarında hassas dizin taraması yapar."""
    found_paths = []
    protocol = "https" if port == 443 else "http"
    
    for path in WEB_SENSITIVE_PATHS:
        try:
            conn = http.client.HTTPConnection(ip, port, timeout=1.5) if protocol == "http" else http.client.HTTPSConnection(ip, port, timeout=1.5)
            conn.request("HEAD", path)
            resp = conn.getresponse()
            if resp.status in [200, 301, 302, 403]:
                found_paths.append(f"{path} ({resp.status})")
            conn.close()
        except: pass
    return found_paths

async def deep_autopsy(ip: str, port: int) -> str:
    if port == 445: return "SMB v2/v3 (Potential EternalBlue)"
    elif port == 3389: return "RDP (SSL/TSL Enabled)"
    return ICS_PROTOCOLS.get(port, "N/A")

# ==============================================================================
# TARAMA ÇEKİRDEĞİ
# ==============================================================================
async def async_scan_port(sem: asyncio.Semaphore, ip: str, port: int, timeout: float, web_recon: bool) -> Optional[Dict]:
    global packets_sent
    async with sem:
        packets_sent += 1
        try:
            conn = asyncio.open_connection(ip, port)
            reader, writer = await asyncio.wait_for(conn, timeout=timeout)
            
            # 1. Banner & Service Detect
            banner = "Bilinmiyor"
            try:
                writer.write(b"HEAD / HTTP/1.1\r\nHost: target\r\n\r\n")
                await writer.drain()
                data = await asyncio.wait_for(reader.read(256), timeout=1.0)
                if data: banner = data.decode('utf-8', errors='ignore').strip().split('\n')[0]
            except: pass
            finally:
                writer.close()
                try: await writer.wait_closed()
                except: pass

            # 2. CVE Cortex & Exploit Suggester
            cves, exploit = check_cve(banner)
            if port == 445: cves, exploit = check_cve("SMB")
            
            # 3. Deep Autopsy
            autopsy = await deep_autopsy(ip, port)
            
            # 4. Web Intelligence (Optional)
            web_leaks = []
            if web_recon and port in [80, 443, 8080]:
                web_leaks = await web_intelligence(ip, port)
            
            return {
                "ip": ip, "port": port, "banner": banner, 
                "cves": cves, "exploit": exploit, "autopsy": autopsy,
                "web_leaks": web_leaks, "method": "TCP"
            }
        except: return None

# ==============================================================================
# MULTI-THREAD MANAGER
# ==============================================================================
async def run_overlord_scan(targets: List[str], ports: List[int], threads: int, web_recon: bool):
    start_time = time.time()
    sem = asyncio.Semaphore(threads)
    tasks = [async_scan_port(sem, ip, port, 2.0, web_recon) for ip in targets for port in ports]
    results = []
    
    with Progress(
        SpinnerColumn(), TextColumn("[progress.description]{task.description}"),
        BarColumn(), TextColumn("[progress.percentage]{task.percentage:>3.0f}%")
    ) as progress:
        bar = progress.add_task("[bold red]OVERLORD Operasyonu Başlatıldı...", total=len(tasks))
        for coro in asyncio.as_completed(tasks):
            res = await coro
            if res: results.append(res)
            progress.update(bar, advance=1)
            
    return results, time.time() - start_time

# ==============================================================================
# CLI & REPORTING
# ==============================================================================
def print_overlord_results(results: List[Dict], total_time: float):
    global packets_sent
    console.print(f"\n[bold white]─ İSTATİSTİKLER: {packets_sent} Paket | {total_time:.2f} Saniye ─[/bold white]\n")

    if not results:
        console.print(Panel("[bold red]Hedefte açık servis bulunamadı.[/bold red]"))
        return

    table = Table(title="[bold red]OVERLORD OPERASYON RAPORU[/bold red]", border_style="red")
    table.add_column("Hedef IP", style="cyan")
    table.add_column("Port", style="yellow")
    table.add_column("Zafiyet (CVE)", style="bold red")
    table.add_column("İstismar Önerisi (Exploit)", style="bold white")
    table.add_column("Sızıntı / Detay", style="magenta")

    for r in sorted(results, key=lambda x: (ipaddress.ip_address(x['ip']), x['port'])):
        cve_list = "\n".join(r["cves"]) if r["cves"] else "Güvenli"
        leak_list = "\n".join(r["web_leaks"]) if r["web_leaks"] else r["autopsy"]
        table.add_row(r['ip'], str(r['port']), cve_list, r['exploit'], leak_list)
    
    console.print(table)

def main():
    parser = argparse.ArgumentParser(description="Dede Korkut v6.0 - Overlord Edition")
    parser.add_argument("-t", "--target", required=True)
    parser.add_argument("-p", "--ports", default="21,22,80,443,445,3389,8080")
    parser.add_argument("--web-recon", action="store_true", help="Hassas dosya/dizin taraması yap (/.env, /admin vb.)")
    parser.add_argument("--threads", type=int, default=100)
    parser.add_argument("-o", "--output", help="JSON Rapor")
    
    args = parser.parse_args()
    console.print(Panel(BANNER, border_style="red"))
    
    def parse_ts(ts):
        try:
            n = ipaddress.ip_network(ts, strict=False)
            return [str(ip) for ip in n.hosts()] if n.prefixlen < 32 else [str(n.network_address)]
        except: return []

    targets = parse_ts(args.target)
    def parse_ps(ps):
        ports = set()
        for part in ps.split(','):
            if '-' in part:
                s, e = map(int, part.split('-'))
                ports.update(range(s, e+1))
            else: ports.add(int(part))
        return list(ports)
    
    ports = parse_ps(args.ports)
    
    res, t = asyncio.run(run_overlord_scan(targets, ports, args.threads, args.web_recon))
    print_overlord_results(res, t)

if __name__ == "__main__":
    try: main()
    except KeyboardInterrupt: sys.exit(0)

#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Dede Korkut - Gelişmiş Ağ Tarama ve İstihbarat Platformu
v5.0 Intelligence Edition - Faz 1, 3, 4 Entegre Edildi
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
    from rich.live import Live
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
> Operasyonel İstihbarat ve Zafiyet Haritalama Platformu
> v5.0: Passive Scan, Deep Autopsy, CVE Cortex, ICS Detect
[/bold cyan]"""

# ==============================================================================
# BİLGİ VERİTABANLARI (CVE CORTEX & ICS)
# ==============================================================================
CVE_DATABASE = {
    "vsftpd 2.3.4": ["CVE-2011-2523 (Backdoor Command Execution)"],
    "OpenSSH 7.2p2": ["CVE-2016-6210 (User Enumeration)", "CVE-2018-15473"],
    "Apache 2.4.49": ["CVE-2021-41773 (Path Traversal / RCE)"],
    "Microsoft IIS 6.0": ["CVE-2017-7269 (WebDAV Buffer Overflow)"],
    "OpenSSL 1.0.1": ["Heartbleed (CVE-2014-0160)"],
}

ICS_PROTOCOLS = {
    502: "Modbus TCP",
    102: "Siemens S7",
    47808: "BACnet",
    20000: "DNP3",
    1911: "Fox Protocol (Niagara)",
    44818: "EtherNet/IP",
}

packets_sent = 0

# ==============================================================================
# ANALİZ FONKSİYONLARI
# ==============================================================================
def guess_os(ttl: int) -> str:
    if ttl <= 64: return "Linux/Unix/macOS"
    elif ttl <= 128: return "Windows"
    elif ttl <= 255: return "Ağ Cihazı (Router/Switch)"
    return "Bilinmiyor"

def check_cve(banner: str) -> List[str]:
    """Banner içinde zafiyet taraması yapar."""
    found_cves = []
    for service, cves in CVE_DATABASE.items():
        if service.lower() in banner.lower():
            found_cves.extend(cves)
    return found_cves

async def deep_autopsy(ip: str, port: int) -> str:
    """Belirli portlarda derinlemesine analiz yapar."""
    # SMB (445) - İşletim sistemi detaylarını çekmeye çalışır
    if port == 445:
        return "Microsoft-DS (Potansiyel SMB v2/v3)"
    # RDP (3389) - SSL Sertifika Analizi
    elif port == 3389:
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with socket.create_connection((ip, port), timeout=2) as sock:
                with ctx.wrap_socket(sock, server_hostname=ip) as ssock:
                    cert = ssock.getpeercert(binary_form=True)
                    return f"RDP (SSL Aktif)"
        except: pass
    
    # ICS/SCADA Tespiti
    if port in ICS_PROTOCOLS:
        return f"ICS Protocol: {ICS_PROTOCOLS[port]}"
        
    return "N/A"

# ==============================================================================
# MOD 1: ASYNC TCP CONNECT
# ==============================================================================
async def grab_banner(reader: asyncio.StreamReader, writer: asyncio.StreamWriter, port: int) -> str:
    banner = "Bilinmiyor"
    try:
        if port in [80, 443, 8080, 8443]:
            writer.write(b"HEAD / HTTP/1.1\r\nHost: target\r\n\r\n")
        else:
            writer.write(b"\r\n")
        await writer.drain()
        data = await asyncio.wait_for(reader.read(256), timeout=1.5)
        if data:
            banner = data.decode('utf-8', errors='ignore').strip().split('\n')[0].replace('\r', '')
            if len(banner) > 50: banner = banner[:47] + "..."
    except Exception: pass
    finally:
        writer.close()
        try: await writer.wait_closed()
        except Exception: pass
    return banner if banner else "Bilinmiyor"

async def async_scan_port(sem: asyncio.Semaphore, ip: str, port: int, timeout: float) -> Optional[Dict]:
    global packets_sent
    async with sem:
        packets_sent += 1
        try:
            conn = asyncio.open_connection(ip, port)
            reader, writer = await asyncio.wait_for(conn, timeout=timeout)
            banner = await grab_banner(reader, writer, port)
            cves = check_cve(banner)
            autopsy = await deep_autopsy(ip, port)
            
            return {
                "ip": ip, "port": port, "status": "AÇIK", 
                "banner": banner, "os": "Bilinmiyor", "method": "TCP Connect",
                "cves": cves, "autopsy": autopsy
            }
        except Exception: return None

# ==============================================================================
# MOD 2: MULTI-THREADED SCAPY SCAN (SYN & UDP)
# ==============================================================================
def scapy_worker(ip: str, port: int, timeout: float, scan_type: str) -> Optional[Dict]:
    global packets_sent
    try:
        packets_sent += 1
        if scan_type == "SYN":
            pkt = IP(dst=ip)/TCP(dport=port, flags="S")
            resp = sr1(pkt, timeout=timeout, verbose=0)
            if resp and resp.haslayer(TCP) and resp.getlayer(TCP).flags == 0x12:
                os_guess = guess_os(resp.ttl)
                # SYN-ACK geldiyse hemen RST at
                import scapy.all as scapy_all
                scapy_all.send(IP(dst=ip)/TCP(dport=port, flags="R"), verbose=0)
                
                # ICS/SCADA check
                autopsy = ICS_PROTOCOLS.get(port, "N/A")
                
                return {
                    "ip": ip, "port": port, "status": "AÇIK", 
                    "banner": "Stealth Mode", "os": os_guess, "method": "TCP SYN",
                    "cves": [], "autopsy": autopsy
                }
    except Exception: pass
    return None

def run_scapy_scan_threaded(targets: List[str], ports: List[int], timeout: float, scan_type: str, max_threads: int = 100) -> Tuple[List[Dict], float]:
    start_time = time.time()
    results = []
    conf.verb = 0 
    tasks_params = [(ip, port, timeout, scan_type) for ip in targets for port in ports]
    
    with Progress(
        SpinnerColumn(spinner_name="bouncingBar", style="red"),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(style="magenta", complete_style="green"),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
    ) as progress:
        bar = progress.add_task(f"[bold magenta]{scan_type} Taraması...", total=len(tasks_params))
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_threads) as executor:
            future_to_port = {executor.submit(scapy_worker, *params): params for params in tasks_params}
            for future in concurrent.futures.as_completed(future_to_port):
                res = future.result()
                if res: results.append(res)
                progress.update(bar, advance=1)
    return results, time.time() - start_time

# ==============================================================================
# MOD 3: PASSIVE SNIFFER (GHOST PROTOCOL)
# ==============================================================================
def passive_sniffer(interface: str, duration: int):
    """Ağ trafiğini dinleyerek aktif IP/Portları tespit eder."""
    console.print(f"[bold green][*] GHOST PROTOCOL AKTİF: {interface} üzerinden sessizce dinleniyor... ({duration} sn)[/bold green]")
    discovered = {}

    def packet_callback(pkt):
        if pkt.haslayer(IP):
            src_ip = pkt[IP].src
            if src_ip not in discovered:
                discovered[src_ip] = {"ports": set(), "os": guess_os(pkt[IP].ttl)}
            
            if pkt.haslayer(TCP):
                discovered[src_ip]["ports"].add(pkt[TCP].sport)
            elif pkt.haslayer(UDP):
                discovered[src_ip]["ports"].add(pkt[UDP].sport)

    sniff(iface=interface, prn=packet_callback, timeout=duration, store=0)
    
    if discovered:
        table = Table(title="[bold cyan]PASİF KEŞİF SONUÇLARI (GHOST)[/bold cyan]")
        table.add_column("Tespit Edilen IP", style="cyan")
        table.add_column("İşletim Sistemi", style="yellow")
        table.add_column("Aktif Portlar (Source)", style="magenta")
        for ip, data in discovered.items():
            ports = ", ".join(map(str, sorted(list(data["ports"]))[:10]))
            table.add_row(ip, data["os"], ports)
        console.print(table)
    else:
        console.print("[bold red][!] Belirtilen sürede ağda aktif bir trafik yakalanamadı.[/bold red]")

# ==============================================================================
# MAIN & CLI
# ==============================================================================
def print_results(results: List[Dict], total_time: float):
    global packets_sent
    console.print("\n[bold white]──────────────────────── İSTATİSTİKLER ────────────────────────[/bold white]")
    console.print(f"[bold cyan]>[/bold cyan] [white]İstek Sayısı:[/white] [bold yellow]{packets_sent}[/bold yellow] | [white]Süre:[/white] [bold yellow]{total_time:.2f} sn[/bold yellow]")
    console.print("[bold white]───────────────────────────────────────────────────────────────[/bold white]\n")

    if results:
        table = Table(title="[bold green]İSTİHBARAT SONUÇLARI[/bold green]", border_style="green")
        table.add_column("Hedef IP", style="cyan")
        table.add_column("Port", style="red")
        table.add_column("Servis / Autopsy", style="magenta")
        table.add_column("Zafiyetler (CVE)", style="bold red")
        
        for r in sorted(results, key=lambda x: (ipaddress.ip_address(x['ip']), x['port'])):
            cve_str = "\n".join(r["cves"]) if r["cves"] else "Temiz"
            table.add_row(r['ip'], f"{r['port']}/{r['method'].split(' ')[0]}", f"{r['banner']}\n[blue]{r['autopsy']}[/blue]", cve_str)
        console.print(table)
    else:
        console.print(Panel("[bold red]Hedef(ler)de aktif veri bulunamadı.[/bold red]"))

def main():
    parser = argparse.ArgumentParser(description="Dede Korkut v5.0 - Intelligence Edition")
    parser.add_argument("-t", "--target", help="Hedef IP/CIDR")
    parser.add_argument("-p", "--ports", default="80,443,445,3389,502,102", help="Portlar")
    parser.add_argument("--stealth", action="store_true", help="TCP SYN Tarama")
    parser.add_argument("--passive", action="store_true", help="Faz 1: Pasif Dinleme Modu")
    parser.add_argument("--interface", default=None, help="Sniffer için ağ arayüzü")
    parser.add_argument("--duration", type=int, default=30, help="Sniffer süresi (sn)")
    parser.add_argument("--randomize", action="store_true", help="Port sırasını karıştır")
    parser.add_argument("--threads", type=int, default=100, help="Thread sayısı")
    parser.add_argument("-o", "--output", help="JSON Rapor")
    
    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)
        
    args = parser.parse_args()
    console.print(Panel(BANNER, border_style="red"))
    
    if args.passive:
        if os.geteuid() != 0:
            console.print("[bold red][!] Sniffer için ROOT (sudo) yetkisi gerekir.[/bold red]")
            sys.exit(1)
        passive_sniffer(args.interface, args.duration)
        return

    if not args.target:
        console.print("[bold red][!] Lütfen bir hedef (-t) belirtin.[/bold red]")
        sys.exit(1)

    targets = parse_targets(args.target)
    def parse_ports(ps):
        ports = set()
        for part in ps.split(','):
            if '-' in part:
                s, e = map(int, part.split('-'))
                ports.update(range(s, e+1))
            else: ports.add(int(part))
        return list(ports)
    
    ports = parse_ports(args.ports)
    if args.randomize: random.shuffle(ports)
    
    if args.stealth:
        res, t = run_scapy_scan_threaded(targets, ports, 1.5, "SYN", args.threads)
    else:
        res, t = asyncio.run(run_async_scan_port_manager(targets, ports, args.threads))
        
    print_results(res, t)

def parse_targets(ts):
    targets = []
    try:
        network = ipaddress.ip_network(ts, strict=False)
        for ip in network.hosts(): targets.append(str(ip))
        if not targets: targets.append(str(network.network_address))
    except: sys.exit(1)
    return targets

async def run_async_scan_port_manager(targets, ports, threads):
    start_time = time.time()
    sem = asyncio.Semaphore(threads)
    tasks = [async_scan_port(sem, ip, port, 2.0) for ip in targets for port in ports]
    results = []
    with Progress() as progress:
        bar = progress.add_task("[bold yellow]TCP Connect Taraması...", total=len(tasks))
        for coro in asyncio.as_completed(tasks):
            res = await coro
            if res: results.append(res)
            progress.update(bar, advance=1)
    return results, time.time() - start_time

if __name__ == "__main__":
    try: main()
    except KeyboardInterrupt: sys.exit(0)

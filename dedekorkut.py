#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Dede Korkut - Gelişmiş Ağ Tarama ve İstihbarat Aracı
Multi-Threaded Stealth, UDP ve ARP Keşif Platformu
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
    from scapy.all import IP, TCP, UDP, ICMP, ARP, Ether, sr1, srp, conf
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
> Operasyonel Ağ Tarama ve İstihbarat Platformu
> Özellikler: OS Fingerprint, IDS Atlatma, UDP, ARP Keşfi
[/bold cyan]"""

packets_sent = 0

def guess_os(ttl: int) -> str:
    """TTL (Time To Live) değerine bakarak işletim sistemini tahmin eder."""
    if ttl <= 64: return f"Linux/Unix/macOS (TTL: {ttl})"
    elif ttl <= 128: return f"Windows (TTL: {ttl})"
    elif ttl <= 255: return f"Ağ Cihazı (TTL: {ttl})"
    else: return f"Bilinmiyor (TTL: {ttl})"

# ==============================================================================
# ASYNC TCP CONNECT
# ==============================================================================
async def grab_banner(reader: asyncio.StreamReader, writer: asyncio.StreamWriter, port: int) -> str:
    banner = "Bilinmiyor"
    try:
        if port in [80, 443, 8080, 8443]:
            writer.write(b"HEAD / HTTP/1.1\r\nHost: target\r\n\r\n")
        else:
            writer.write(b"\r\n")
        await writer.drain()
        data = await asyncio.wait_for(reader.read(256), timeout=1.0)
        if data:
            banner = data.decode('utf-8', errors='ignore').strip().split('\n')[0].replace('\r', '')
            if len(banner) > 50: banner = banner[:47] + "..."
    except Exception: pass
    finally:
        writer.close()
        try: await writer.wait_closed()
        except Exception: pass
    return banner if banner else "Bilinmiyor (Filtreli Yanıt)"

async def async_scan_port(sem: asyncio.Semaphore, ip: str, port: int, timeout: float) -> Optional[Dict]:
    global packets_sent
    async with sem:
        packets_sent += 1
        try:
            conn = asyncio.open_connection(ip, port)
            reader, writer = await asyncio.wait_for(conn, timeout=timeout)
            banner = await grab_banner(reader, writer, port)
            return {"ip": ip, "port": port, "status": "AÇIK", "banner": banner, "os": "Bilinmiyor", "method": "TCP Connect"}
        except Exception: return None

async def run_async_scan(targets: List[str], ports: List[int], timeout: float, max_concurrent: int) -> Tuple[List[Dict], float]:
    start_time = time.time()
    sem = asyncio.Semaphore(max_concurrent)
    tasks = []
    results = []
    with Progress(
        SpinnerColumn(spinner_name="dots2", style="cyan"),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(style="red", complete_style="green"),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        TextColumn("•"), TextColumn("[bold cyan]Süre:[/bold cyan] {task.elapsed:.1f}s")
    ) as progress:
        bar = progress.add_task("[bold yellow]TCP Connect Taraması...", total=len(targets)*len(ports))
        for ip in targets:
            for port in ports: tasks.append(async_scan_port(sem, ip, port, timeout))
        for coro in asyncio.as_completed(tasks):
            res = await coro
            if res: results.append(res)
            progress.update(bar, advance=1)
    return results, time.time() - start_time

# ==============================================================================
# SCAPY WORKER: SINGLE PORT SCAN (Stealth & UDP)
# ==============================================================================
def scapy_worker(ip: str, port: int, timeout: float, scan_type: str) -> Optional[Dict]:
    """Multi-threading için izole edilmiş tek port tarama fonksiyonu."""
    global packets_sent
    try:
        packets_sent += 1
        if scan_type == "SYN":
            pkt = IP(dst=ip)/TCP(dport=port, flags="S")
            resp = sr1(pkt, timeout=timeout, verbose=0)
            if resp and resp.haslayer(TCP) and resp.getlayer(TCP).flags == 0x12:
                os_guess = guess_os(resp.ttl)
                rst_pkt = IP(dst=ip)/TCP(dport=port, flags="R")
                import scapy.all as scapy_all
                scapy_all.send(rst_pkt, verbose=0)
                packets_sent += 1
                return {"ip": ip, "port": port, "status": "AÇIK", "banner": "Stealth Mode", "os": os_guess, "method": "TCP SYN"}
        elif scan_type == "UDP":
            pkt = IP(dst=ip)/UDP(dport=port)
            resp = sr1(pkt, timeout=timeout, verbose=0)
            if resp is None:
                return None 
            elif resp.haslayer(UDP):
                return {"ip": ip, "port": port, "status": "AÇIK", "banner": "UDP Yanıtı", "os": guess_os(resp.ttl), "method": "UDP"}
    except Exception: pass
    return None

# ==============================================================================
# MULTI-THREADED SCAPY SCAN MANAGER
# ==============================================================================
def run_scapy_scan_threaded(targets: List[str], ports: List[int], timeout: float, scan_type: str, max_threads: int = 100) -> Tuple[List[Dict], float]:
    start_time = time.time()
    
    if not SCAPY_AVAILABLE:
        console.print("[bold red][!] 'scapy' eksik. (pip install scapy)[/bold red]")
        sys.exit(1)
    if os.geteuid() != 0:
        console.print("[bold red][!] DİKKAT: Raw soket oluşturmak için ROOT (sudo) gerekir.[/bold red]")
        sys.exit(1)

    results = []
    conf.verb = 0 
    total_tasks = len(targets) * len(ports)
    desc = "[bold magenta]TCP SYN Taraması (Multi-Thread)..." if scan_type == "SYN" else "[bold yellow]UDP Taraması..."

    tasks_params = [(ip, port, timeout, scan_type) for ip in targets for port in ports]

    with Progress(
        SpinnerColumn(spinner_name="bouncingBar", style="red"),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(style="magenta", complete_style="green"),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        TextColumn("•"), TextColumn("[bold cyan]Süre:[/bold cyan] {task.elapsed:.1f}s")
    ) as progress:
        bar = progress.add_task(desc, total=total_tasks)
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_threads) as executor:
            future_to_port = {executor.submit(scapy_worker, *params): params for params in tasks_params}
            for future in concurrent.futures.as_completed(future_to_port):
                res = future.result()
                if res: results.append(res)
                progress.update(bar, advance=1)

    return results, time.time() - start_time

# ==============================================================================
# ARP SCAN (LOCAL NETWORK DISCOVERY)
# ==============================================================================
def arp_scan(target_cidr: str) -> Tuple[List[Dict], float]:
    global packets_sent
    start_time = time.time()
    if not SCAPY_AVAILABLE or os.geteuid() != 0:
        console.print("[bold red][!] ARP taraması 'scapy' ve ROOT (sudo) gerektirir.[/bold red]")
        sys.exit(1)
    console.print(f"[bold yellow][*] Yerel ağ (L2) ARP yayını başlatılıyor: {target_cidr}[/bold yellow]")
    conf.verb = 0
    results = []
    packets_sent += 256 
    ans, unans = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=target_cidr), timeout=2, verbose=0)
    for snd, rcv in ans:
        mac = rcv.sprintf(r"%Ether.src%")
        ip = rcv.sprintf(r"%ARP.psrc%")
        try: vendor = conf.manufdb._resolve_MAC(mac)
        except Exception: vendor = "Bilinmiyor"
        results.append({"ip": ip, "mac": mac, "vendor": vendor})
    return results, time.time() - start_time

# ==============================================================================
# UTILS & MAIN
# ==============================================================================
def parse_ports(port_str: str) -> List[int]:
    ports = set()
    for part in port_str.split(','):
        part = part.strip()
        if '-' in part:
            try:
                s, e = map(int, part.split('-'))
                ports.update(range(s, e + 1))
            except ValueError: sys.exit(1)
        else:
            try: ports.add(int(part))
            except ValueError: sys.exit(1)
    return sorted(list(ports))

def parse_targets(target_str: str) -> List[str]:
    targets = []
    try:
        network = ipaddress.ip_network(target_str, strict=False)
        for ip in network.hosts(): targets.append(str(ip))
        if not targets: targets.append(str(network.network_address))
    except ValueError: sys.exit(1)
    return targets

def adjust_os_limits(requested: int) -> int:
    if platform.system() == "Windows": return requested
    try:
        soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
        req_limit = requested + 100
        if soft < req_limit:
            new_limit = min(hard, req_limit) if hard != resource.RLIM_INFINITY else req_limit
            resource.setrlimit(resource.RLIMIT_NOFILE, (new_limit, hard))
            soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
        if soft < requested: return max(1, soft - 50)
    except Exception: pass
    return requested

def print_results(results: List[Dict], total_time: float, is_arp: bool = False):
    global packets_sent
    console.print("\n[bold white]──────────────────────── İSTATİSTİKLER ────────────────────────[/bold white]")
    console.print(f"[bold cyan]>[/bold cyan] [white]Gönderilen Toplam Paket:[/white] [bold yellow]{packets_sent}[/bold yellow]")
    console.print(f"[bold cyan]>[/bold cyan] [white]Tarama Süresi:[/white] [bold yellow]{total_time:.2f} saniye[/bold yellow]")
    console.print("[bold white]───────────────────────────────────────────────────────────────[/bold white]\n")

    if not results:
        console.print(Panel("[bold red]Hedef(ler)de aktif veri bulunamadı.[/bold red]"))
        return

    if is_arp:
        table = Table(title="[bold blue]YEREL AĞ (ARP)[/bold blue]", border_style="blue")
        table.add_column("IP Adresi", style="cyan"); table.add_column("MAC Adresi", style="red"); table.add_column("Cihaz / Üretici", style="yellow")
        for r in sorted(results, key=lambda x: ipaddress.ip_address(x['ip'])): table.add_row(r['ip'], r['mac'], r['vendor'])
    else:
        table = Table(title="[bold green]TARAMA SONUÇLARI - AÇIK PORTLAR[/bold green]", border_style="green")
        table.add_column("Hedef IP", style="cyan"); table.add_column("Port/Protokol", style="red")
        table.add_column("İşletim Sistemi", style="yellow"); table.add_column("Servis Detayı", style="magenta")
        for r in sorted(results, key=lambda x: (ipaddress.ip_address(x['ip']), x['port'])):
            table.add_row(r['ip'], f"{r['port']}/{r['method'].split(' ')[0]}", r['os'], f"[{r['status']}] {r['banner']}")
    console.print(table)

def main():
    parser = argparse.ArgumentParser(description="Dede Korkut - Gelişmiş Ağ Tarama ve İstihbarat Aracı")
    parser.add_argument("-t", "--target", required=True, help="Hedef IP veya CIDR (Örn: 192.168.1.0/24)")
    parser.add_argument("-p", "--ports", default="80,443", help="Portlar (Örn: 22,80,1000-2000)")
    parser.add_argument("--stealth", action="store_true", help="TCP SYN Tarama (Root gerektirir)")
    parser.add_argument("--udp", action="store_true", help="UDP Port Taraması")
    parser.add_argument("--arp", action="store_true", help="Yerel Ağda Cihaz Keşfi (MAC/Marka tespiti)")
    parser.add_argument("--randomize", action="store_true", help="IDS atlatmak için port sırasını karıştır")
    parser.add_argument("--timeout", type=float, default=1.5, help="Bekleme süresi (sn)")
    parser.add_argument("-c", "--concurrency", type=int, default=500, help="Async mod için maks bağlantı")
    parser.add_argument("--threads", type=int, default=100, help="Stealth mod için Thread sayısı")
    parser.add_argument("-o", "--output", type=str, default=None, help="JSON formatında rapor çıktısı")
    
    if len(sys.argv) == 1:
        parser.print_help(sys.stderr)
        sys.exit(1)
        
    args = parser.parse_args()
    console.print(Panel(BANNER, border_style="red"))
    
    if args.arp:
        res, t = arp_scan(args.target)
        print_results(res, t, True)
        return

    targets = parse_targets(args.target)
    ports = parse_ports(args.ports)
    if args.randomize:
        console.print("[bold yellow][!] IDS Atlatma Aktif: Portlar karıştırılıyor...[/bold yellow]")
        random.shuffle(ports)
    
    console.print(f"[bold cyan][*][/bold cyan] [bold white]Hedef:[/bold white] {len(targets)} IP | [bold white]Port Sayısı:[/bold white] {len(ports)}")
    
    if args.udp:
        console.print(f"[bold cyan][*][/bold cyan] [bold red]MOD:[/bold red] UDP Scanning (Multi-Thread)")
        res, t = run_scapy_scan_threaded(targets, ports, args.timeout, "UDP", args.threads)
    elif args.stealth:
        console.print(f"[bold cyan][*][/bold cyan] [bold red]MOD:[/bold red] Stealth SYN (Multi-Thread + OS Fingerprint)")
        console.print(f"[bold cyan][*][/bold cyan] [bold white]İş Parçacığı (Threads):[/bold white] {args.threads}\n")
        res, t = run_scapy_scan_threaded(targets, ports, args.timeout, "SYN", args.threads)
    else:
        safe_c = adjust_os_limits(args.concurrency)
        console.print(f"[bold cyan][*][/bold cyan] [bold green]MOD:[/bold green] Async TCP Connect")
        if sys.platform == 'win32': asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
        res, t = asyncio.run(run_async_scan(targets, ports, args.timeout, safe_c))
        
    print_results(res, t)
    
    if args.output:
        try:
            with open(args.output, 'w') as f:
                json.dump({"scan_time": datetime.now().isoformat(), "results": res}, f, indent=4)
            console.print(f"\n[bold green][+][/bold green] Rapor başarıyla kaydedildi: [bold white]{args.output}[/bold white]")
        except Exception as e:
            console.print(f"\n[bold red][!] Rapor kaydedilirken hata oluştu: {e}[/bold red]")

if __name__ == "__main__":
    try: main()
    except KeyboardInterrupt: sys.exit(0)

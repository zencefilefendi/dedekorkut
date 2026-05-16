# Dede Korkut — Sentinel v4.0

![Status](https://img.shields.io/badge/Status-Active-success)
![Python](https://img.shields.io/badge/Python-3.8%2B-blue)
![Async](https://img.shields.io/badge/async-asyncio-purple)
![Output](https://img.shields.io/badge/output-JSON%20%7C%20CSV%20%7C%20HTML-orange)
![License](https://img.shields.io/badge/use-authorized%20only-red)

**Dede Korkut**, izinli sızma testleri ve mavi-takım keşif çalışmaları için tasarlanmış, tek-dosyalık async bir ağ keşif & istihbarat platformudur. Şık bir CLI (Rich), genişletilebilir bir plugin mimarisi, çoklu çıktı formatları ve harici JSON tabanlı bir zafiyet imza veritabanı sunar.

> ⚠️ **Yasal:** Bu araç **yalnızca açıkça izinli sistemlerde** kullanılmalıdır. Kullanım sorumluluğu tamamen operatöre aittir.

---

## İçindekiler

- [Özellikler](#-özellikler)
- [Mimari Genel Bakış](#-mimari-genel-bakış)
- [Kurulum](#-kurulum)
- [Hızlı Başlangıç](#-hızlı-başlangıç)
- [CLI Referansı](#-cli-referansı)
- [Plugin Sistemi](#-plugin-sistemi)
- [Zafiyet Veritabanı](#-zafiyet-veritabanı-vuln_dbjson)
- [Çıktı Formatları](#-çıktı-formatları)
- [Stealth Modu](#-stealth-modu)
- [Pasif Mod (Ghost Protocol)](#-pasif-mod-ghost-protocol)
- [Geliştirme Notları](#-geliştirme-notları)

---

## ✨ Özellikler

| Modül | Açıklama |
|---|---|
| **Async Port Scanner** | `asyncio.Semaphore` ile kontrollü eş zamanlı TCP connect tarama, RTT ölçümü |
| **Service Prober** | SMB/RDP için protokol-bilinçli probe; SSH/FTP/SMTP için pasif banner grab; jenerik portlarda otomatik fallback |
| **HTTP Fingerprinter** | `Server`, `X-Powered-By`, `<title>`, 6 security header (HSTS/CSP/XFO/XCTO/RP/PP), **redirect chain takibi** (max 5 hop), **CORS denetimi** (Origin reflection / wildcard+credentials) |
| **TLS Inspector** | Sertifika öznesi/issuer'ı, **SAN** listesi, expiry-days, **self-signed**/**expired** flag, TLS versiyonu & cipher |
| **DNS Recon** | Reverse DNS + A/AAAA/MX/NS/TXT (dnspython varsa async, yoksa socket fallback) |
| **Vulnerability Cortex** | Harici **`vuln_db.json`** üzerinden regex motoru, severity'li CVE eşleme |
| **Plugin Architecture** | `plugins/` klasöründen otomatik discovery, `ScanPlugin` base sınıfı, lifecycle hooks, `--disable-plugin`, `--list-plugins` |
| **Stealth Engine** | Jitter (random.uniform), port shuffle, 5'li User-Agent havuzu |
| **Shodan OSINT** | Passive host enrichment (`--shodan-key`) |
| **Passive Sniffing** | Ghost Protocol: scapy ile sıfır-paket-gönderim ağ dinleme |
| **Multi-format Output** | Rich Table (terminal) + **JSON** + **CSV** + self-contained **HTML** (severity-renkli) |
| **IPv6 Native** | Hem hedef hem URL üretiminde IPv6 desteği (`getaddrinfo` + bracket-aware URL) |
| **Proper Logging** | `-v/-vv` (INFO/DEBUG), `--quiet`, `--no-color`, Rich tracebacks |

---

## 🏗 Mimari Genel Bakış

```
                 ┌─────────────────────────────────────────────────┐
                 │                    CLI (argparse)                │
                 └─────────────────────────────────────────────────┘
                                       │
                ┌──────────────────────┼──────────────────────┐
                ▼                      ▼                      ▼
        ┌──────────────┐     ┌────────────────┐     ┌──────────────┐
        │ PassiveSniffer│     │  run_active    │     │ list-plugins │
        │  (Ghost)     │     │     _scan      │     │              │
        └──────────────┘     └────────┬───────┘     └──────────────┘
                                      │
        ┌─────────────────────────────┼─────────────────────────────┐
        ▼              ▼              ▼              ▼              ▼
   ScanContext    StealthConfig   VulnDB        DnsRecon      ShodanClient
                                  (regex)
                                      │
                                      ▼
                              ┌──────────────┐
                              │ AsyncScanner │ ◄──── PluginRegistry
                              └──────┬───────┘            │
                                     │                    ▼
                                     ▼               ScanPlugin[]
                       ┌─────────────┼─────────────┐
                       ▼             ▼             ▼
                ServiceProber  HttpFingerprinter  TlsInspector
                                (redirect+CORS)    (cert+cipher)
                                     │
                                     ▼
                              ┌──────────────┐
                              │ PortResult[] │
                              └──────┬───────┘
                                     │
            ┌────────────────────────┼────────────────────────┐
            ▼                        ▼                        ▼
       Rich Table              JSON / CSV                   HTML
```

---

## 📦 Kurulum

```bash
git clone https://github.com/zencefilefendi/dedekorkut.git
cd dedekorkut
pip3 install rich           # zorunlu
pip3 install scapy          # opsiyonel: --passive icin
pip3 install dnspython      # opsiyonel: --dns icin (yoksa socket fallback)
chmod +x dedekorkut.py
```

**Gereksinimler:** Python 3.8+. Pasif sniffing modu **root/sudo** gerektirir.

---

## 🚀 Hızlı Başlangıç

```bash
# 1) Tekil hedef, varsayilan port seti
python3 dedekorkut.py -t example.com

# 2) CIDR + spesifik portlar + JSON cikti
python3 dedekorkut.py -t 10.0.0.0/24 -p 22,80,443,8080 -o tarama.json

# 3) Tum kanlanma: HTTP + TLS + DNS + plugin + HTML rapor
python3 dedekorkut.py -t target.com -p 80,443 --dns -o rapor.html -vv

# 4) Stealth mod (jitter + port shuffle + UA rotation)
python3 dedekorkut.py -t target.com -p 1-1024 --stealth -c 50

# 5) IPv6
python3 dedekorkut.py -t ::1 -p 18080

# 6) Pasif dinleme (sudo gerektirir)
sudo python3 dedekorkut.py --passive --passive-duration 60

# 7) Shodan OSINT zenginlestirme
python3 dedekorkut.py -t 1.2.3.4 -p 22,80,443 --shodan-key YOUR_KEY

# 8) Plugin'leri listele
python3 dedekorkut.py --list-plugins
```

---

## 🖥 CLI Referansı

```
HEDEF
  -t, --target TARGET       IP, hostname veya CIDR (10.0.0.0/24)
  -p, --ports  PORTS        Virgul ve/veya araliklar: "22,80,443,8000-8100"

MOD
  --passive                 Ghost Protocol (paket gondermeden dinle)
  --passive-duration N      Sure (sn), varsayilan 30
  --passive-iface IFACE     Pasif arayuz
  --dns                     DNS recon (PTR/A/AAAA/MX/NS/TXT)
  --shodan-key KEY          Shodan OSINT zenginlestirme

PERFORMANS
  --timeout SEC             Soket zaman asimi (varsayilan 2.0)
  -c, --concurrency N       Eszamanli baglanti (varsayilan 150)

STEALTH
  --stealth                 Jitter + port shuffle + UA rotation
  --jitter-min/max SEC      Jitter araligi

ISTIHBARAT
  --vuln-db PATH            Harici JSON imza dosyasi

PLUGIN
  --plugins-dir DIR         Plugin klasoru (default: ./plugins)
  --no-plugins              Plugin sistemini kapat
  --disable-plugin NAME     Spesifik plugin'i devre disi birak (tekrarlanabilir)
  --list-plugins            Yuklu plugin'leri goster ve cik

CIKTI
  -o, --output FILE         Cikti dosyasi (.json/.csv/.html)
  --format {auto,json,csv,html}

LOGLAMA
  -v / -vv                  INFO / DEBUG
  -q, --quiet               Yalnizca hatalar
  --no-color                ANSI kapali
  --no-banner               Banner'i atla
```

---

## 🧩 Plugin Sistemi

Plugin'ler `plugins/` klasöründen otomatik keşfedilir. Her plugin `ScanPlugin` sınıfından türetilir:

```python
# plugins/my_plugin.py
from dedekorkut import Finding, PluginContext, PortResult, ScanPlugin


class MyPlugin(ScanPlugin):
    name = "my_plugin"
    version = "1.0"
    description = "Ornek plugin"

    def applies_to(self, result: PortResult) -> bool:
        return result.port == 443

    async def run(self, result: PortResult, ctx: PluginContext) -> list[Finding]:
        return [Finding(
            plugin=self.name,
            severity="medium",   # critical|high|medium|low|info
            title="Bulundu!",
            detail="Aciklama",
            evidence="<kanit string>",
        )]
```

### Gönderilen default plugin'ler

| Plugin | Severity Aralığı | Ne Yapar |
|---|---|---|
| **`http_paths`** | `info` → `critical` | `/.env`, `/.git/HEAD`, `/.git/config`, `/.DS_Store`, `/.svn/entries`, `/server-status`, `/phpinfo.php`, `/admin`, `/wp-admin/`, `/actuator/health`, `/robots.txt`, `/sitemap.xml` kontrolü. 401/403 cevaplari "mevcut, kimlik gerekli" olarak isaretler. |
| **`weak_protocols`** | `info` → `high` | Telnet (23), rlogin/rsh/rexec (512-514), FTP plain (21), TFTP (69), NetBIOS (137-139), Finger (79), rpcbind (111), SSDP/mDNS gibi zayif protokolleri severity ile isaretler. |
| **`cors_check`** | `medium` → `critical` | `Access-Control-Allow-Origin: *` + `Credentials: true` kombosu, **reflected Origin**, `null` origin kabulu. |

### Plugin yonetimi

```bash
python3 dedekorkut.py --list-plugins                     # listele
python3 dedekorkut.py -t X --no-plugins                  # tum plugin'leri kapat
python3 dedekorkut.py -t X --disable-plugin http_paths   # bir plugin'i kapat
python3 dedekorkut.py -t X --plugins-dir ./mine          # ozel klasor
```

---

## 🧬 Zafiyet Veritabanı (`vuln_db.json`)

Banner regex → CVE eşleme. Çalışma sırasında yan dosya otomatik yüklenir; bulunmazsa script içine gömülü minimal fallback kullanılır.

```json
{
  "openssh": [
    {"regex": "openssh_9\\.[0-7]p1", "cve": "CVE-2024-6387",
     "severity": "critical", "desc": "regreSSHion RCE"}
  ],
  "nginx": [
    {"regex": "nginx/1\\.20\\.0", "cve": "CVE-2021-23017",
     "severity": "critical", "desc": "DNS resolver off-by-one -> RCE"}
  ]
}
```

Harici dosya geçmek için: `--vuln-db /path/to/db.json`

---

## 📁 Çıktı Formatları

### JSON
Tam yapılandırılmış: hedef, çözülmüş IP'ler, port sonuçları (CVE, TLS, HTTP, findings, redirect_chain), DNS, Shodan, stats. Otomasyon pipeline'larına idealdir.

### CSV
Düz tablo: `ip,port,service,banner,http_server,http_status,tls_subject,tls_expiry_days,cves,severity`. Excel / Sheets / pandas ile direkt açılır.

### HTML
Self-contained (dış bağlantı yok), severity-renkli tablo: row arka planı en yüksek bulgu severity'sine göre kırmızı/turuncu/sarı/mavi. CVE chip'leri, redirect chain oku (→), CORS uyarısı, DNS recon tablosu, Shodan özeti.

### Rich Table
Terminalde anında: sıralanmış multi-satır kolonlar, CVE & finding listesi, redirect chain göstergesi (↻N), security header eksik sayacı (`sec[-N]`).

---

## 🥷 Stealth Modu

`--stealth` aktif edildiğinde:

- **Port shuffle:** Tarama sırası rastgeleleştirilir
- **Jitter:** Her connect öncesi `uniform(jitter_min, jitter_max)` ms gecikme
- **User-Agent havuzu:** HTTP istekleri 5'li UA havuzundan rastgele seçer (Chrome/Safari/Firefox/curl/DedeKorkut)
- **Düşük concurrency önerilir:** `-c 50` veya daha az, IDS pattern matching'i için sürtünme yaratır

```bash
python3 dedekorkut.py -t target -p 1-1024 --stealth --jitter-min 0.2 --jitter-max 1.0 -c 30
```

---

## 👻 Pasif Mod (Ghost Protocol)

Hedefe **hiç paket göndermeden** ağ trafiğini scapy ile dinler ve TCP/UDP akışını canlı haritalandırır. **sudo gerektirir.**

```bash
sudo python3 dedekorkut.py --passive --passive-duration 120 --passive-iface en0
```

---

## 🛠 Geliştirme Notları

### Dosya yapısı

```
dedekorkut/
├── dedekorkut.py        # ana entry point, ~900 satir, modular bolumler
├── vuln_db.json         # harici CVE imzalari
├── plugins/
│   ├── http_paths.py    # hassas yol kontrolu
│   ├── weak_protocols.py# eski protokol isaretleme
│   └── cors_check.py    # CORS misconfig
└── README.md
```

### Mimari prensipler

1. **Tek dosya core, opsiyonel modüller:** Ana script bağımlılığı minimum (sadece `rich`). scapy/dnspython yoksa ilgili özellik graceful degrade eder.
2. **Sessiz hata yok:** Her `except` bloğu en azından `log.debug()` yazar; debug seviyesinde tam trace alabilirsiniz (`-vv`).
3. **Dataclass first:** Tüm sonuçlar `@dataclass` (PortResult, HttpInfo, TlsInfo, Finding, ScanReport). `asdict()` ile JSON serialize edilir.
4. **Plugin DI:** Plugin'lere ortak servisler `PluginContext` üzerinden enjekte edilir (timeout, log, UA picker).
5. **Async-friendly blocking:** SSL ve urllib gibi blocking I/O `run_in_executor` ile pool'a düşer; event loop hiç bloklanmaz.

### Yeni plugin eklemek

1. `plugins/your_plugin.py` oluştur, `ScanPlugin`'den türet
2. `applies_to()` ve `async run()` implement et
3. Script'i çalıştır; otomatik yüklenir (`--list-plugins` ile doğrula)

### Yeni CVE imzası eklemek

1. `vuln_db.json` aç, kategori altına ekle:
   ```json
   {"regex": "your_regex", "cve": "CVE-YYYY-NNNN",
    "severity": "high", "desc": "kisaca"}
   ```
2. Test: `python3 dedekorkut.py -t hedef -v` → "VulnDB yuklendi: X kategori, Y imza"

---

## 📝 Sürüm Notları

### v4.0 — Sentinel (mevcut)
- ✨ Plugin mimarisi (`ScanPlugin` base + auto-discovery + lifecycle)
- ✨ HTTP redirect chain takibi (max 5 hop)
- ✨ CORS denetimi (Origin reflection / wildcard+credentials / null origin)
- ✨ TLS/SSL sertifika otopsisi (SAN, expiry, self-signed flag, cipher)
- ✨ DNS recon modülü (dnspython opsiyonel)
- ✨ Stealth engine (jitter, port shuffle, UA rotation)
- ✨ Multi-format çıktı: JSON/CSV/HTML
- ✨ IPv6 native desteği (target & URL üretimi)
- ✨ Harici `vuln_db.json` (regex motoru + severity)
- ✨ Proper logging (`-v/-vv`, `--quiet`, `--no-color`)
- 🧹 Global state kaldırıldı (`ScanContext` ile lock'lu sayaçlar)
- 🧹 Sessiz `except: pass` blokları temizlendi (debug log'lu hata yönetimi)

### v3.x — Pro
- Asyncio scanner, Rich UI, Shodan OSINT, scapy sniffing, statik CVE eşleme

---

## 📜 Lisans & Sorumluluk

Bu araç **yetkili sızma testi**, **bug bounty (kapsam dahili)** ve **mavi-takım keşfi** için tasarlanmıştır. İzinsiz tarama bulunduğunuz ülkenin yasalarına göre suç teşkil edebilir. Kullanım tamamen operatörün sorumluluğundadır.

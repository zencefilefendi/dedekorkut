# Dede Korkut - Gelişmiş Ağ Tarama ve İstihbarat Platformu (v5.0 Intelligence Edition)

![Dede Korkut](https://img.shields.io/badge/Status-Active-success) ![Python](https://img.shields.io/badge/Python-3.8%2B-blue) ![Scapy](https://img.shields.io/badge/Scapy-Powered-red)

Dede Korkut, hedef sistemler ve yerel ağlar üzerinde derinlemesine bilgi toplamak (Reconnaissance), yüzey haritalaması (Enumeration) ve otomatik zafiyet analizi yapmak için geliştirilmiş profesyonel bir siber istihbarat platformudur.

v5.0 Intelligence Edition ile birlikte araç, sadece bir tarayıcı olmaktan çıkıp, bulduğu servisleri otomatik analiz eden ve bilinen zafiyetlerle (CVE) eşleştiren bir "İstihbarat Çekirdeği"ne dönüşmüştür.

## 🌟 Yeni Nesil Özellikler (v5.0)

* **Ghost Protocol (Pasif Keşif):** `--passive` bayrağı ile hedefe tek bir paket göndermeden, ağ trafiğini dinleyerek aktif cihazları ve servisleri sessizce haritalar.
* **Vulnerability Cortex (Otomatik CVE Eşleştirme):** Servis versiyonlarını yakalar ve bilinen kritik zafiyetlerle (CVE) otomatik olarak eşleştirerek ekrana uyarı basar.
* **Deep Autopsy (Derin Protokol Analizi):** SMB (445) ve RDP (3389) gibi kritik portlarda sadece bağlantı kontrolü yapmaz; protokol detaylarını ve SSL sertifikalarını analiz eder.
* **ICS/SCADA Identifier:** Endüstriyel tesislerde kullanılan Modbus, Siemens S7, BACnet gibi protokolleri otomatik olarak tanır.
* **Multi-Thread Stealth SYN Taraması:** İşletim sisteminin TCP yığınını bypass ederek doğrudan ağ kartı üzerinden "Yarım Bağlantı" paketleri üretir.
* **İşletim Sistemi Tespiti (OS Fingerprinting):** Ağ paketlerinin TTL değerlerini analiz ederek sistemin Windows, Linux veya Ağ Cihazı olduğunu uzaktan tespit eder.

## ⚙️ Kurulum ve Gereksinimler

Aracın ham (raw) ağ paketleri üretebilmesi için `scapy` ve profesyonel arayüz için `rich` kütüphanesine ihtiyacı vardır.

```bash
# Gerekli kütüphaneleri yükleyin
pip3 install scapy rich

# Araca çalıştırma yetkisi verin
chmod +x dedekorkut.py
```

*Not: Pasif Dinleme, Stealth (SYN), UDP ve ARP modları doğrudan donanım seviyesinde işlem yaptığı için **root (sudo)** yetkisi gerektirir.*

## 🚀 Kullanım Örnekleri

**1. Ghost Protocol (Pasif Dinleme - Hedefe hiç dokunmaz):**
```bash
sudo python3 dedekorkut.py --passive --duration 60
```

**2. Derin Analiz ve Zafiyet Tarama (Stealth Mode):**
```bash
sudo python3 dedekorkut.py -t 3.1.3.1 -p 21,22,80,443,445,3389 --stealth --threads 200
```

**3. IDS / IPS Davranış Testi (Port Randomize):**
```bash
sudo python3 dedekorkut.py -t 10.0.0.1 -p 1-65535 --stealth --randomize --threads 500
```

**4. Yerel Ağ Cihaz ve Marka Tespiti (ARP Scan):**
```bash
sudo python3 dedekorkut.py -t 192.168.1.0/24 --arp
```

## ⚠️ Yasal Uyarı

Bu araç, ağ yöneticilerinin ve siber güvenlik uzmanlarının kendi sistemlerindeki zafiyetleri tespit etmesi amacıyla geliştirilmiştir. Yalnızca **izinli** ve **yetkiniz dahilindeki** sistemlerde kullanın.

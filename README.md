# Dede Korkut - Gelişmiş Ağ Tarama ve İstihbarat Platformu (v6.0 Overlord Edition)

![Dede Korkut](https://img.shields.io/badge/Status-Active-success) ![Python](https://img.shields.io/badge/Python-3.8%2B-blue) ![Scapy](https://img.shields.io/badge/Scapy-Powered-red)

Dede Korkut, hedef sistemler ve yerel ağlar üzerinde derinlemesine bilgi toplamak (Reconnaissance), zafiyet haritalaması yapmak ve istismar önerileri sunmak için tasarlanmış profesyonel bir otonom keşif platformudur.

v6.0 Overlord Edition ile araç artık sadece veri toplamaz; web servislerindeki sızıntıları yakalar ve bulunan her zafiyet için operasyonel istismar (Exploit) önerileri sunar.

## 👑 Overlord Özellikleri (v6.0)

* **Web Intelligence (Derin Web Keşfi):** `--web-recon` bayrağı ile web portlarında (80, 443, 8080) otomatik olarak `/.env`, `/.git`, `/admin` gibi hassas dosyaları ve sızıntıları tarar.
* **Exploit Suggester (İstismar Rehberi):** Bulunan her CVE zafiyeti için Metasploit modül adları veya operasyonel `curl` komutları gibi hazır istismar önerileri sunar.
* **Vulnerability Cortex:** Yakalanan servis versiyonlarını bilinen kritik zafiyetlerle (CVE) otomatik olarak eşleştirir.
* **Ghost Protocol (Pasif Keşif):** Hedefe dokunmadan, ağ trafiğini dinleyerek cihazları ve servisleri sessizce haritalar.
* **Deep Autopsy (Protokol Otopsisi):** SMB ve RDP gibi kritik portlarda derinlemesine analiz yaparak potansiyel zafiyet noktalarını (Örn: EternalBlue) işaretler.
* **ICS/SCADA Identifier:** Endüstriyel tesis protokollerini (Modbus, S7, BACnet vb.) otomatik olarak tanır.

## ⚙️ Kurulum ve Gereksinimler

```bash
# Gerekli kütüphaneleri yükleyin
pip3 install scapy rich

# Araca çalıştırma yetkisi verin
chmod +x dedekorkut.py
```

*Not: Bazı modlar (SYN, UDP, ARP, Passive) doğrudan donanım seviyesinde işlem yaptığı için **root (sudo)** yetkisi gerektirir.*

## 🚀 Kullanım Örnekleri

**1. Overlord Operasyonu (Web Keşfi + Zafiyet Tarama):**
```bash
python3 dedekorkut.py -t 3.1.3.1 -p 80,443,445 --web-recon
```

**2. Hayalet Modu (Pasif Dinleme):**
```bash
sudo python3 dedekorkut.py --passive --duration 60
```

**3. Güvenlik Duvarı Analizi ve İstismar Önerileri:**
```bash
sudo python3 dedekorkut.py -t 10.10.10.5 -p 1-1000 --stealth --threads 200
```

## ⚠️ Yasal Uyarı

Bu araç, sızma testi uzmanları ve ağ yöneticileri için geliştirilmiştir. Yalnızca **izinli** ve **yetkiniz dahilindeki** sistemlerde kullanın.

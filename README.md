# Dede Korkut - Gelişmiş Ağ Tarama ve İstihbarat Aracı

![Dede Korkut](https://img.shields.io/badge/Status-Active-success) ![Python](https://img.shields.io/badge/Python-3.8%2B-blue) ![Scapy](https://img.shields.io/badge/Scapy-Powered-red)

Dede Korkut, hedef sistemler ve yerel ağlar üzerinde derinlemesine bilgi toplamak (Reconnaissance) ve yüzey haritalaması yapmak için geliştirilmiş, profesyonel bir siber istihbarat aracıdır.

Güvenlik duvarlarını (Firewall) ve Saldırı Tespit/Engelleme Sistemlerini (IDS/IPS) analiz etmek için özel "TCP SYN Half-Open" (Stealth) ve "Port Karıştırma (Randomize)" tekniklerini kullanır.

## Temel Özellikler

* **Multi-Thread Stealth SYN Taraması:** İşletim sisteminin TCP yığınını atlayarak ağ kartı üzerinden "Yarım Bağlantı (Half-Open)" paketleri üretir. Firewall cihazlarını haritalamak için idealdir.
* **Asenkron TCP Connect (Hızlı Tarama):** Ağ haritalamasını standart TCP oturumlarıyla saniyeler içinde tamamlamak için Python `asyncio` altyapısını kullanır.
* **Banner Grabbing (Servis Tespiti):** Açık port tespit ettiğinde, özel proplar göndererek çalışan servisin sürümünü (Fingerprinting) okur.
* **Pasif İşletim Sistemi Tespiti (OS Fingerprinting):** Ağ paketlerinin TTL (Time to Live) değerlerini analiz ederek sistemin Windows, Linux veya Ağ Cihazı (Cisco vb.) olup olmadığını uzaktan tespit eder.
* **IDS / IPS Atlatma Tespiti:** `--randomize` parametresi sayesinde portları sıralı değil, rastgele tarayarak güvenlik duvarlarının davranışsal tepkilerini ölçer.
* **UDP Tarama (Kör Nokta):** UDP protokolü üzerinden çalışan servisleri (DNS, SNMP vb.) tarar.
* **Yerel Ağ İstihbaratı (ARP):** Bulunduğunuz yerel ağdaki (Wi-Fi/LAN) aktif cihazları tespit edip, MAC adresleri üzerinden üretici (Vendor) markalarını (Örn: Apple, Cisco) listeler.
* **Raporlama:** Bulguları daha sonra analiz etmek üzere `JSON` formatında çıktı olarak verir.

## Kurulum ve Gereksinimler

Aracın ham (raw) ağ paketleri üretebilmesi için `scapy` ve terminal arayüzü için `rich` kütüphanesine ihtiyacı vardır.

```bash
# Gerekli kütüphaneleri yükleyin
pip3 install scapy rich

# Araca çalıştırma yetkisi verin
chmod +x dedekorkut.py
```

*Not: Stealth (SYN), UDP ve ARP modları doğrudan donanım seviyesinde ağ paketi ürettiği için **root (sudo)** yetkisi gerektirir.*

## Kullanım Örnekleri

**1. Hızlı Tarama (Async Connect - Sudo gerektirmez):**
```bash
python3 dedekorkut.py -t 192.168.1.10 -p 22,80,443,3389
```

**2. Güvenlik Duvarı Analizi ve OS Tespiti (Stealth Mode):**
```bash
sudo python3 dedekorkut.py -t 3.1.3.1 -p 1-10000 --stealth --threads 200
```

**3. IDS / IPS Davranış Testi (Port Randomize):**
```bash
sudo python3 dedekorkut.py -t 3.1.3.1 -p 1-65535 --stealth --randomize --threads 500
```

**4. UDP Taraması:**
```bash
sudo python3 dedekorkut.py -t 10.10.10.5 -p 53,161,500 --udp
```

**5. Yerel Ağ Cihaz Tespiti (ARP Scan):**
```bash
sudo python3 dedekorkut.py -t 192.168.1.0/24 --arp
```

**6. Sonuçları Kaydetme:**
```bash
sudo python3 dedekorkut.py -t 10.0.0.1 -p 1-100 --stealth -o rapor.json
```

## Yasal Uyarı

Bu araç, ağ yöneticilerinin ve siber güvenlik uzmanlarının kendi ağlarındaki zafiyetleri tespit etmesi amacıyla geliştirilmiştir. Yalnızca **izinli** ve **yetkiniz dahilindeki** sistemlerde kullanın.
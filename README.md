# Advanced Secure File Transfer System
**Bilgisayar Ağları Dönem Projesi**

##  Proje Özeti

Bu proje, güvenli dosya transferi, düşük seviyeli IP işleme ve ağ performans analizi özelliklerini içeren kapsamlı bir ağ güvenlik sistemidir. Proje, AES/RSA şifreleme, manuel paket fragmentasyonu, MITM saldırı simülasyonu ve gerçek zamanlı ağ izleme özelliklerini içermektedir.

##  Özellikler

###  Temel Özellikler (Zorunlu)

- **Güvenli Dosya Transfer Sistemi**
  - AES-256 ve RSA-2048 şifreleme
  - Müşteri kimlik doğrulama
  - SHA-256 ile veri bütünlüğü kontrolü
  - Manuel paket fragmentasyonu ve yeniden birleştirme

- **Düşük Seviyeli IP Header İşleme**
  - Manuel IP header manipülasyonu (TTL, flags, checksum)
  - IP checksum hesaplama ve doğrulama
  - Alıcı tarafında paket yeniden birleştirme

- **Ağ Performans Ölçümü**
  - Latency ölçümü (ping, RTT hesaplamaları)
  - Bandwidth analizi (iPerf benzeri)
  - Paket kaybı simülasyonu
  - Farklı ağ koşulları karşılaştırması

- **Güvenlik Analizi ve Saldırı Simülasyonu**
  - Wireshark benzeri paket yakalama ve analiz
  - Man-in-the-Middle (MITM) saldırı simülasyonu
  - Paket enjeksiyonu simülasyonu
  - Şifreleme etkinliği testi

###  Bonus Özellikler

- **Hibrit TCP/UDP Geçişi** - Ağ koşullarına göre protokol adaptasyonu
- **Dinamik Sıkışıklık Kontrolü** - Bant genişliği optimizasyonu
- **Grafik Kullanıcı Arayüzü** - Modern ve kullanıcı dostu arayüz
- **Gelişmiş Saldırı Simülasyonları** - Gerçek zamanlı saldırı tespiti

##  Kurulum

### Gereksinimler

- Python 3.7+
- Windows 10/11 (Linux/Mac de desteklenir)

### 1. Depoyu Klonlayın

```bash
git clone [repository-url]
cd secure-file-transfer-system
```

### 2. Gerekli Paketleri Kurun

```bash
pip install scapy pycryptodome matplotlib
```

### 3. Bağımlılıkları Kontrol Edin

```bash
python main.py --check-deps
```

##  Kullanım

### GUI Uygulaması (Önerilen)

```bash
python main.py --gui
```

### Komut Satırı Kullanımı

#### Sunucu Başlatma
```bash
python main.py --server --host localhost --port 8888
```

#### Dosya Gönderme
```bash
python main.py --client test_document.txt --host localhost --port 8888
```

#### Performans Analizi
```bash
python main.py --performance
```

#### Güvenlik Analizi
```bash
python main.py --security
```

#### Kapsamlı Demo
```bash
python main.py --demo
```

## Proje Yapısı

```
secure-file-transfer-system/
├── main.py                           # Ana koordinatör script
├── secure_file_transfer.py           # Güvenli dosya transfer modülü
├── network_performance_analyzer.py   # Ağ performans analizi
├── security_analyzer.py              # Güvenlik analizi ve saldırı simülasyonu
├── gui_application.py                # Grafik kullanıcı arayüzü
├── read_pdf.py                       # PDF okuma yardımcısı
├── README.md                         # Bu dosya
├── requirements.txt                  # Python bağımlılıkları
└── test_files/                       # Test dosyaları
    ├── test_document.txt
    ├── test_image.txt
    └── test_config.json
```

##  Teknik Detaylar

### Şifreleme

- **AES-256**: Dosya içeriği şifreleme
- **RSA-2048**: Anahtar değişimi
- **SHA-256**: Veri bütünlüğü kontrolü

### Ağ Protokolleri

- **TCP**: Güvenilir dosya transferi
- **UDP**: Hızlı performans testleri
- **ICMP**: Latency ölçümü (ping)

### Güvenlik Özellikleri

- End-to-end şifreleme
- Perfect Forward Secrecy
- Replay attack koruması
- Paket bütünlük kontrolü

##  Performans Analizi

Sistem aşağıdaki metrikleri ölçer:

- **Latency**: Ortalama, minimum, maksimum gecikme
- **Jitter**: Gecikme varyasyonu
- **Bandwidth**: Aktarım hızı (Mbps)
- **Packet Loss**: Paket kaybı oranı
- **Throughput**: Efektif veri aktarım hızı

##  Güvenlik Analizi

- **Paket Yakalama**: Gerçek zamanlı trafik izleme
- **Şifreleme Analizi**: Entrophy analizi ile şifreleme etkinliği
- **MITM Simülasyonu**: Man-in-the-Middle saldırı testi
- **Saldırı Tespiti**: Şüpheli trafik paternleri tanıma

##  Test Senaryoları

### 1. Dosya Transfer Testi
```bash
# Terminal 1: Sunucu başlat
python main.py --server

# Terminal 2: Dosya gönder
python main.py --client test_document.txt
```

### 2. Performans Testi
```bash
python main.py --performance
```

### 3. Güvenlik Testi
```bash
python main.py --security
```

##  Rapor Çıktıları

Sistem aşağıdaki raporları otomatik olarak oluşturur:

- `network_performance_report.json` - Ağ performans analizi
- `security_analysis_report.json` - Güvenlik analizi sonuçları
- `comprehensive_report_[timestamp].json` - Kapsamlı sistem raporu

##  Wireshark Analizi

Paket yakalama ve analiz için:

1. Wireshark'ı başlatın
2. İlgili ağ arayüzünü seçin
3. Filtre: `tcp.port == 8888`
4. Şifrelenmiş trafiği gözlemleyin

##  Proje Gereksinimleri Karşılama

| Gereksinim | Durum | Açıklama |
|------------|-------|----------|
| Dosya Transfer | ✅ | AES/RSA şifreleme ile güvenli transfer |
| IP Header İşleme | ✅ | Manuel checksum ve fragmentation |
| Performans Ölçümü | ✅ | Latency, bandwidth, packet loss |
| Güvenlik Analizi | ✅ | MITM simülasyonu, paket analizi |
| GUI | ✅ | Modern Tkinter arayüzü |
| Bonus Özellikler | ✅ | TCP/UDP switching, IDS |

##  Video

 video YouTube'da yayınlanacak ve raporda linkle paylaşılacaktır.

## 📚 Kaynaklar

- RFC 791 - Internet Protocol Specification
- RFC 793 - Transmission Control Protocol
- NIST Guidelines for AES Implementation
- OWASP Security Testing Guide

## 👨‍💻 Geliştirici

**Wahib MOQBEL**  
Bilgisayar Ağları Dönem Projesi  
[Bursa Tecknical University] - [2025]


> **Not**: Bu sistem eğitim amaçlıdır. Gerçek üretim ortamında kullanımdan önce ek güvenlik testleri yapılmalıdır. 

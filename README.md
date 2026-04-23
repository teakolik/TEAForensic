# TEA DFIR Collector — Windows Forensic Acquisition Tool

## Genel Bakış

TEA Forensic Collector, Windows sistemlerinden kapsamlı forensic artifact toplayan,
sonuçları **tek, bağımsız HTML raporu** olarak sunan bir DFIR aracıdır.

Binalyze AIR'ın temel forensic toplama yeteneklerini modellemektedir.

---

## Toplanan Artifact Kategorileri

| Kategori | Detay |
|---|---|
| **System Info** | Hostname, OS version, timezone, IP config, DNS cache |
| **Process List** | PID, PPID, commandline, path, SHA256 hash, CPU/RAM |
| **Network** | Netstat, listening ports, established connections, ARP, routing, Wi-Fi profiles, firewall rules |
| **Registry** | Run/RunOnce (HKLM+HKCU), Winlogon, AppInit, LSA, Image File Execution Options, yüklü yazılımlar |
| **Event Logs** | Security (4624/4625/4648/4672/4720...), System errors, PowerShell Script Block (4104), Task Scheduler, Defender, RDP |
| **Filesystem** | Prefetch, Recent files, TEMP executables, Alternate Data Streams, recently modified System32 files |
| **Browser** | Chrome/Edge/Firefox artifact paths & metadata, Chrome extensions, Downloads |
| **Tasks & Services** | Tüm scheduled tasks, çalışan servisler + binary hash, non-standard path servisleri, startup items |
| **Memory** | Physical RAM info, top processes by RAM, pagefile, suspicious injected modules, RAM dump guidance |
| **Users** | Local users, groups, Administrators üyeleri, aktif oturumlar, son logon'lar |

---

## Kurulum & Build

### Gereksinimler
- Windows 10/11 veya Windows Server 2016+
- Python 3.8+ (build için)
- Administrator yetkisi (runtime'da)

### EXE Build
```cmd
# Projeyi klonla veya kopyala
cd tea-forensic

# EXE derle
build.bat
```

Çıktı: `dist\TEADFIR.exe`

### Bağımlılıklar
Sadece Python standart kütüphanesi kullanılmaktadır (winreg, subprocess, ctypes, json, os, datetime).
Üçüncü parti kütüphane yoktur — kolay deployment ve AV false positive azaltımı için.

---

## Kullanım

```cmd
# Temel kullanım (UAC prompt açılır, mevcut dizine rapor yazar)
TEADFIR.exe

# Çıktı dizini belirt
TEADFIR.exe -o C:\evidence

# JSON da kaydet (SIEM import için)
TEADFIR.exe --json

# UAC olmadan çalıştır (eksik artifact uyarısı ile)
TEADFIR.exe --no-elevate

# Birden fazla seçenek
TEADFIR.exe -o C:\evidence --json
```

### Çıktı Dosyaları
```
C:\evidence\
├── tea_forensic_HOSTNAME_20250101_120000.html   # Ana rapor
└── tea_forensic_HOSTNAME_20250101_120000.json   # Ham veri (--json ile)
```

---

## HTML Rapor Özellikleri

- **Sidebar navigasyon** — Tüm kategorilere tek tıkla erişim
- **Collapsible sections** — Gürültüyü azaltmak için bölümler açılır/kapanır
- **Otomatik indicator tespiti** — TEMP'teki EXE, ADS varlığı, non-standard service path
- **Arama** — Ctrl+F ile rapor içi tam metin arama
- **Self-contained** — İnternet bağlantısı gerektirmez, her tarayıcıda açılır
- **Print ready** — Tüm bölümler açık şekilde yazdırılır

---

## Güvenlik Notları

1. **Chain of Custody**: Raporu üretir üretmez SHA256 hash alın.
   ```cmd
   certutil -hashfile tea_forensic_*.html SHA256
   ```

2. **Live RAM Dump için**: Winpmem veya DumpIt kullanın (ayrı tool, kernel driver gerektirir).
   ```cmd
   winpmem_mini_x64.exe memory.dmp
   ```

3. **Volatility Analizi**:
   ```cmd
   volatility3 -f memory.dmp windows.pslist
   volatility3 -f memory.dmp windows.netscan
   volatility3 -f memory.dmp windows.malfind
   ```

4. **Browser SQLite DB'leri**: History, Cookies gibi dosyalar kilitli olabilir.
   DB Browser for SQLite veya Hindsight ile analiz edin.

---

## Bilinen Kısıtlamalar

| Kısıt | Açıklama |
|---|---|
| RAM dump | Kernel driver gerektiriyor, bu tool sadece process/module listesi alıyor |
| Browser history içeriği | SQLite lock nedeniyle içerik okunamıyor, metadata toplanıyor |
| MFT raw parse | `fsutil` ile limitli bilgi; tam MFT için `mft2csv` veya `analyzeMFT` önerilir |
| Encrypted volumes | BitLocker/VeraCrypt volume'ları artifact vermiyor |
| Anti-forensic tools | Wipe/shred edilmiş dosyalar görünmüyor |

---

## Mimarı

```
tea-forensic/
├── src/
│   ├── main.py         # Entry point, UAC, orchestrator
│   ├── collector.py    # Artifact toplama modülleri (10 kategori)
│   └── reporter.py     # HTML rapor üretici
├── build.bat           # PyInstaller build scripti
├── version_info.txt    # EXE metadata (PE versyon bilgisi)
└── README.md           # Bu dosya
```

---

## Gelecek Geliştirmeler (Roadmap)

- [ ] YARA rule matching (yüklenen dosyalar üzerinde)
- [ ] Sigma rule entegrasyonu (event log analizi)
- [ ] Uzak endpoint toplama (SMB/WinRM üzerinden)
- [ ] SIEM'e otomatik JSON push (webhook)
- [ ] Timeline view (tüm artifact'ları kronolojik görünüm)
- [ ] IOC comparison (bilinen hash/IP listesiyle karşılaştırma)
- [ ] Differential analysis (iki snapshot karşılaştırması)

---

**TEA Security** | tea.com.tr | v1.0.0

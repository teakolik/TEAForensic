# TEA DFIR Forensic Collector

**Windows Forensic Artifact Acquisition & Malware Detection Tool**  
TEA Security | v1.2.0

---

## Genel Bakış

TEA Forensic Collector, Windows sistemlerinden kapsamlı forensic artifact toplayan,
zararlı yazılım tespiti yapan ve sonuçları **HTML raporu** olarak sunan
bir DFIR aracıdır.

**Build edildikten sonra hedef makinede Python kurulumu gerekmez.**  
`TEADFIR.exe` tek dosyadır, tüm bağımlılıklar içine gömülüdür.

---

## Hızlı Başlangıç

### Adım 1 — Build (geliştirici makinesi, bir kez yapılır)

```cmd
REM Python kurulu olmalı (sadece build için gerekli)
REM İndirme: https://www.python.org/downloads/
REM KRİTİK: Kurulumda "Add python.exe to PATH" işaretli olmalı

REM 1. yara-x kur (C++ Build Tools gerektirmez)
python -m pip install yara-x

REM 2. EXE derle (PowerShell'den .\build.bat, CMD'den build.bat)
cd C:\tea-forensic
.\build.bat

REM Çıktı: dist\TEADFIR.exe  (~16MB, bağımsız)
```

### Adım 2 — Çalıştır (hedef makine — hiçbir şey kurulmaz)

```cmd
REM Temel kullanım — C:\evidence klasörü yoksa otomatik oluşturulur
dist\TEADFIR.exe -o C:\evidence --json

REM VirusTotal entegrasyonu ile (API key gerekir)
dist\TEADFIR.exe -o C:\evidence --json --vt-key YOUR_FREE_API_KEY

REM UAC olmadan (bazı artifact'lar eksik kalabilir)
dist\TEADFIR.exe -o C:\evidence --no-elevate
```

---

## Sık Sorulan Sorular

**Hedef makinede Python kurulu olmalı mı?**  
Hayır. Build sırasında PyInstaller tüm kütüphaneleri EXE içine gömer.
`TEADFIR.exe` tek başına çalışır, Python gerektirmez.

**yara-rules klasörü oluşturmam gerekiyor mu?**  
Hayır. YARA kuralları (`yara_rules/common.yar`) build sırasında EXE içine gömülür.
`--yara-rules` sadece **ek özel kural eklemek** istersen kullanılır:

```cmd
mkdir C:\my_rules
copy C:\tea-forensic\yara_rules\common.yar C:\my_rules\
REM Kendi .yar dosyalarını ekle
dist\TEADFIR.exe -o C:\evidence --yara-rules C:\my_rules
```

**YARA çalışıyor mu nasıl anlarım?**  
HTML raporda `YARA Scan` bölümünde `BACKEND: yara-x` ve `RULES_LOADED: 1+` görünüyorsa aktif.

**yara-python kurulmuyor, C++ hatası alıyorum.**  
`yara-python` yerine `yara-x` kullan — C++ Build Tools gerektirmez:
```cmd
python -m pip install yara-x
```

**IOC listesini nasıl güncellerim?**  
`ioc\hashes.txt` ve `ioc\network_ioc.txt` dosyalarını düzenle, ardından `.\build.bat` ile
yeniden build al. Güncel feed kaynakları: MalwareBazaar, Abuse.ch, MISP, OpenCTI.

---

## Komut Satırı Seçenekleri

```
dist\TEADFIR.exe [seçenekler]

  -o, --output DIR        Çıktı dizini (yoksa otomatik oluşturulur)
  --json                  HTML'ye ek olarak ham JSON da kaydet
  --vt-key API_KEY        VirusTotal API key (ücretsiz: virustotal.com)
  --yara-rules DIR        Özel YARA kural dizini — OPSİYONEL
                          Belirtilmezse EXE içindeki kurallar kullanılır
  --no-elevate            UAC yükseltme isteğini atla
```

---

## Çalışma Gereksinimleri (Hedef Makine)

| Gereksinim | Durum |
|---|---|
| Python | Gerekmez. SAdece build için gerekli. EXE direk çalışır |
| İnternet bağlantısı | Gerekmez (VirusTotal hariç) |
| Windows 10/11 veya Server 2016+ | Yalnızca bu sistemlerde çalışır |
| Administrator yetkisi | Gerekli (bazı artifact'lar için) |

---

## Build Gereksinimleri (Geliştirici Makinesi)

| Gereksinim | Notlar |
|---|---|
| **Python 3.8+** | Sadece build için. https://www.python.org/downloads/ |
| **yara-x** | `python -m pip install yara-x` — C++ gerektirmez |
| **PyInstaller** | `build.bat` tarafından otomatik kurulur |

> **yara-python alternatifi:** Tam YARA desteği için C++ Build Tools (700MB) gerekir.
> Python 3.14 için pre-built wheel yoktur. `yara-x` önerilir.

---

## Toplanan Kategoriler

| # | Kategori | İçerik |
|---|---|---|
| 1 | **System Info** | Hostname, OS, mimari, timezone, uptime, IP config |
| 2 | **Process List** | PID, PPID, commandline, path, SHA256, CPU/RAM |
| 3 | **Network** | Netstat, listening ports, established bağlantılar, ARP, routing, DNS cache, Wi-Fi, firewall |
| 4 | **Registry** | Run/RunOnce (HKLM+HKCU), Winlogon, AppInit, LSA, IFEO, yüklü yazılımlar |
| 5 | **Event Logs** | 4624/4625/4648/4672/4688/4776, log silme (1102/104), PS ScriptBlock, WMI, BITS, Sysmon, RDP, brute force özeti |
| 6 | **Filesystem** | Prefetch, recent files, TEMP executables+hash, ADS, son değişen System32 dosyaları |
| 7 | **Browser** | Chrome/Edge/Firefox artifact path+metadata, Chrome extensions, Downloads+hash |
| 8 | **Tasks & Services** | Scheduled tasks, çalışan servisler+hash, non-standard paths, startup items, drivers |
| 9 | **Memory** | RAM kullanımı, top process'ler, pagefile, suspicious modules |
| 10 | **Users** | Local users, groups, Administrators, aktif oturumlar, son logon'lar |

---

## Zararlı Yazılım Tespit Modülleri

| # | Modül | Yöntem |
|---|---|---|
| 11 | **IOC Hash Match** | Process/servis SHA256 → `ioc/hashes.txt` karşılaştırması |
| 12 | **LOLBAS Detection** | Process commandline'da `powershell -enc`, `rundll32 scrobj`, `certutil -decode` vb. |
| 13 | **Webshell Scan** | IIS/Apache/XAMPP dizinlerinde PHP/ASP/JSP zararlı pattern taraması |
| 14 | **YARA Scan** | TEMP, System32, Downloads, web dizinlerinde kural tabanlı dosya taraması |
| 15 | **VirusTotal** | Toplanan hash'leri VT API v3 ile sorgular (API key gerekir) |
| 16 | **Parent-Child Anomaly** | Office→shell spawn, beklenmedik PPID, process masquerade, svchost -k eksikliği |
| 17 | **Unsigned Processes** | Hash mismatch / imzasız / güvenilmeyen sertifikalı process tespiti |
| 18 | **Network IOC** | Aktif bağlantılar ve DNS cache → `ioc/network_ioc.txt` C2 IP/domain karşılaştırması |
| 19 | **Hollow Process** | WMI path vs Get-Process path uyumsuzluğu, commandline/exe mismatch |

---

## IOC Dosyaları

### `ioc/hashes.txt` — Bilinen zararlı SHA256 hash listesi
```
# Yorum satırı
27c5b5b6e7d9a...   (SHA256, bir satıra bir hash)
```
Güncel feed: https://bazaar.abuse.ch/export/

### `ioc/network_ioc.txt` — Bilinen kötü IP ve domain listesi
```
IP:45.142.212.100
DOMAIN:malware-c2.example.com
185.220.101.45          (prefix olmadan da çalışır)
```
Güncel feed: https://feodotracker.abuse.ch/downloads/ipblocklist.csv

> IOC listesini güncelledikten sonra `.\build.bat` ile yeniden build al.

---

## YARA Kuralları

### Mevcut kurallar (`yara_rules/common.yar`) — EXE içine gömülü
Mimikatz, Meterpreter, Cobalt Strike, PowerShell obfuscation,
Webshell (PHP/ASPX/JSP), AsyncRAT, LOLBAS, Ransomware, Credential harvesting

### Özel kural ekleme
```cmd
mkdir C:\my_rules
copy C:\tea-forensic\yara_rules\common.yar C:\my_rules\
copy my_custom.yar C:\my_rules\
dist\TEADFIR.exe -o C:\evidence --yara-rules C:\my_rules
```

---

## HTML Rapor Özellikleri

- **Indicator tıklaması** — Her alarm badge'ine tıklayınca ilgili bölüme smooth scroll + highlight
- **Sidebar navigasyon** — Tüm 19 kategoriye tek tıkla erişim
- **Collapsible sections** — Bölümler açılır/kapanır
- **CRITICAL / HIGH / MEDIUM** renk kodlaması
- **Ctrl+F** ile rapor içi tam metin arama
- **Self-contained** — İnternet bağlantısı gerektirmez, her tarayıcıda açılır

---

## Live RAM Dump (Ek Tool Gerekir)

```cmd
winpmem_mini_x64.exe C:\evidence\memory.dmp
volatility3 -f memory.dmp windows.pslist
volatility3 -f memory.dmp windows.malfind
```

---

## Bilinen Kısıtlamalar

| Kısıt | Açıklama |
|---|---|
| RAM dump | Kernel driver gerektirir — process/module metadata alınır |
| Browser history içeriği | SQLite lock nedeniyle içerik okunamaz, metadata toplanır |
| Hollow process (tam) | Kernel erişimi olmadan tam VirtualQueryEx yapılamaz — indikatör düzeyinde |
| Fileless malware | Diske düşmeyen zararlılar YARA/hash ile yakalanamaz — Volatility gerekir |
| Şifreli volume | BitLocker/VeraCrypt volume artifact vermiyor |

---

## Proje Yapısı

```
tea-forensic/
├── src/
│   ├── main.py          Entry point, argümanlar, UAC, orchestrator
│   ├── collector.py     19 artifact/tespit modülü
│   └── reporter.py      HTML rapor üretici + indicator engine
├── ioc/
│   ├── hashes.txt       Bilinen zararlı SHA256 listesi (düzenlenebilir)
│   └── network_ioc.txt  Bilinen kötü IP/domain listesi (düzenlenebilir)
├── yara_rules/
│   └── common.yar       12 YARA kuralı — EXE içine gömülür
├── requirements.txt     Python bağımlılıkları
├── build.bat            PyInstaller build scripti
├── version_info.txt     EXE PE versiyon bilgisi
└── README.md            Bu dosya
```

---

**TEA Security** | v1.2.0

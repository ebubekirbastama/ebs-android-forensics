# EBS Sentinel DFIR X Pro v5

Mobil adli bilişim, Android ADB analizi, threat hunting ve aktif müdahale aracı.

## Çalıştırma

```bash
pip install -r requirements.txt
python main.py
```

Windows için `run_windows.bat` kullanılabilir.

## v5 Eklenen Modüller

- IOC & Threat Intelligence Center
- MITRE ATT&CK eşleştirme
- Offline IP ülke / firma / ASN zenginleştirme
- Ağ / Socket ekranında ülke ve firma kolonları
- Live Device Map
- Threat Hunting Workspace
- YARA benzeri basit APK/izin kural motoru
- VirusTotal için SHA256 tabanı hazır alan
- AI Threat Analyst heuristic özet motoru
- Permission Risk Matrix
- Mobile EDR kural motoru
- Attack Simulator / Lab senaryoları
- Session Recorder
- Evidence / case sistemiyle aksiyon kaydı

## IP Ülke/Firma Verisi

Varsayılan olarak bilinen büyük ağlar offline eşleştirilir: Google, Microsoft, Cloudflare, Meta, Telegram, Apple, Fastly vb.
Daha hassas sonuç için `assets/geoip.csv` dosyası eklenebilir.

CSV formatı:

```csv
prefix,country,company,asn
45.158.57.0/24,TR,Example Hosting,AS00000
```

## Güvenlik Notu

Bu araç yalnızca cihaz sahibinin rızasıyla, yetkili adli analiz / güvenlik incelemesi için kullanılmalıdır.
`force-stop` geçici durdurma içindir. `suspend` hassas uygulamalarda dikkatli kullanılmalıdır.

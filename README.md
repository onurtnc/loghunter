# LogHunter

**Sigma benzeri kurallarla calisan, sifir bagimlilikli log tespit motoru (mini SIEM).**

![Python](https://img.shields.io/badge/python-3.8%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Dependencies](https://img.shields.io/badge/dependencies-none-brightgreen)
![Tests](https://img.shields.io/badge/tests-19%20passing-success)

Windows Sysmon/Security, Linux `auth.log`, JSON, NDJSON ve CSV loglarini okur; YAML
kurallarla eslestirir; MITRE ATT&CK etiketli alarmlar uretir. Konsol, JSON, CSV ve
HTML rapor cikartir. **Harici hicbir kutuphane gerektirmez** — PyYAML yoksa paketle
gelen mini YAML parser devreye girer.

---

## Neden?

Ticari SIEM'ler pahali ve agir. Bir SOC analistinin masasina dusen isin buyuk kismi ise
"su log dosyasinda kotu bir sey var mi?" sorusudur. LogHunter tam olarak bunu yapar:
bir dosya ver, kurallari calistirsin, onceliklendirilmis bulgu listesi versin.

## Ozellikler

| Ozellik | Aciklama |
|---|---|
| Sigma benzeri kurallar | `contains`, `startswith`, `endswith`, `re`, `cidr`, `gt/lt`, `all` modifier'lari |
| Bileske kosullar | `selection and not filter`, `a and (b or c)`, `1 of sel_*`, `all of sel_*` |
| Korelasyon | "5 dakikada 5 basarisiz giris" tarzi esik kurallari (`timeframe_config`) |
| Cok formatli parser | Sysmon/Security JSON, NDJSON, JSON array, syslog/auth.log, CSV, duz metin |
| Alan normalizasyonu | Ic ice JSON otomatik duzlestirilir, `Event.EventData.Data` cozulur |
| Risk skoru | Bulgu seviyesi + hacme gore 0-100 arasi tek sayi |
| Cikti formatlari | Renkli konsol, JSON, CSV, tek dosyalik koyu temali HTML rapor |
| CI dostu | `--fail-on high` ile pipeline'da exit code 1 dondurur |
| Gurultu kontrolu | Otomatik tekillestirme (dedup), `--min-level`, `--tag` filtreleri |

## Kurulum

```bash
git clone https://github.com/<kullanici>/loghunter.git
cd loghunter
python -m loghunter samples/          # kurulum bile gerekmiyor
```

Sisteme komut olarak eklemek isterseniz:

```bash
pip install -e .
loghunter samples/
```

## Kullanim

```bash
# Ornek loglari tara
python -m loghunter samples/

# Tek dosya, format zorlayarak
python -m loghunter samples/sysmon.json -f json

# Sadece yuksek ve uzeri kurallar
python -m loghunter /var/log/auth.log --min-level high

# Belirli bir ATT&CK teknigi
python -m loghunter samples/ --tag attack.t1059

# Rapor uret
python -m loghunter samples/ --html rapor.html --json bulgular.json --csv bulgular.csv

# Kendi kural dizinin
python -m loghunter logs/ -r /opt/kurallar/

# CI: critical bulgu varsa build'i patlat
python -m loghunter logs/ --fail-on critical --quiet
```

### Ornek cikti

```
==============================================================================
  LogHunter - Tespit Raporu
==============================================================================
  Dosya: 3   Olay: 29   Kural: 10   Alarm: 12
  Risk skoru: [###################.] 97/100
  Seviyeler: high:7  critical:3  medium:2
------------------------------------------------------------------------------
[CRITICAL] LSASS Bellek Erisimi (Kimlik Bilgisi Hirsizligi)
    zaman : 2026-07-28 09:16:11    kaynak: sysmon.json:3
    etiket: attack.t1003.001, attack.credential-access
    EventID           : 10
    Computer          : WS-FIN-014

[HIGH] SSH Kaba Kuvvet Saldirisi (5x / 5dk)
    zaman : 2026-07-28 03:14:11    kaynak: auth.log:5
    etiket: attack.t1110.001, attack.credential-access
    src_ip            : 45.155.205.233
    hit_count         : 5
```

## Kendi kuralini yaz

`rules/` altina bir `.yml` dosyasi birak, yeter:

```yaml
title: Supheli Zamanlanmis Gorev
id: win-schtask-010
description: Kalicilik icin schtasks ile gorev olusturma.
level: high
logsource:
  product: windows
  service: sysmon
detection:
  selection:
    EventID: 1
    Image|endswith: \schtasks.exe
  suspicious:
    CommandLine|contains:
      - /create
      - powershell
  filter:
    User: 'NT AUTHORITY\SYSTEM'
  condition: selection and suspicious and not filter
tags:
  - attack.t1053.005
  - attack.persistence
falsepositives:
  - Yazilim guncelleyicilerin olusturdugu gorevler
```

### Desteklenen modifier'lar

| Modifier | Ornek | Anlami |
|---|---|---|
| (yok) | `EventID: 4625` | Tam esitlik (`*` ve `?` joker destekli) |
| `contains` | `CommandLine\|contains: -enc` | Icinde geciyor mu |
| `startswith` / `endswith` | `Image\|endswith: \cmd.exe` | Basi / sonu |
| `re` | `_raw\|re: 'curl.*\|\s*bash'` | Regex |
| `cidr` | `src_ip\|cidr: 10.0.0.0/8` | IP araligi |
| `gt` `gte` `lt` `lte` | `bytes\|gt: 100000` | Sayisal karsilastirma |
| `all` | `CommandLine\|contains\|all: [shadow, delete]` | Listedeki **hepsi** eslesmeli |

### Korelasyon (esik) kurallari

```yaml
detection:
  selection:
    event_type: ssh_failed_login
  timeframe_config:
    count: 5              # kac olay
    window_minutes: 5     # kac dakikalik pencerede
    group_by: [src_ip]    # neye gore gruplansin
  condition: selection
```

## Paketle gelen kurallar

| ID | Seviye | Baslik |
|---|---|---|
| `win-lsass-003` | critical | LSASS bellek erisimi (kimlik bilgisi hirsizligi) |
| `win-shadow-006` | critical | Golge kopya silme (fidye yazilimi belirtisi) |
| `lnx-curl-pipe-103` | critical | `curl \| bash` ile script calistirma |
| `win-ps-encoded-001` | high | Kodlanmis PowerShell komutu |
| `win-lolbin-002` | high | LOLBin uzerinden dosya indirme |
| `win-svc-004` | high | Supheli servis kurulumu |
| `win-bruteforce-005` | high | Windows oturum acma kaba kuvvet |
| `lnx-ssh-bruteforce-101` | high | SSH kaba kuvvet |
| `lnx-root-login-102` | medium | Root ile dogrudan SSH girisi |
| `lnx-persistence-104` | medium | Cron / systemd kalicilik |

## Mimari

```
loghunter/
├── minyaml.py   PyYAML yoksa devreye giren mini YAML parser
├── parsers.py   Log formatlarini ortak olay sozlugune cevirir
├── rules.py     Kural modeli, alan eslestirme, condition degerlendirici
├── engine.py    Tarama dongusu, korelasyon, dedup, risk skoru
├── report.py    Konsol / JSON / CSV / HTML ciktilari
└── cli.py       argparse arayuzu
```

Akis: `parsers` → normalize edilmis olay → `rules.matches()` → `engine` alarm → `report`.

## Testler

```bash
python -m unittest discover -s tests -v
# veya
pytest -v
```

## Yol haritasi

- [ ] Gercek `.evtx` dosyalarini dogrudan okuma
- [ ] Zaman cizelgesi (timeline) HTML gorunumu
- [ ] Sigma reposundaki kurallari otomatik donusturme
- [ ] Syslog dinleyici modu (canli tarama)
- [ ] ATT&CK Navigator JSON ciktisi

## Sorumluluk reddi

Bu arac savunma (blue team) amaclidir. Sadece yetkili oldugunuz sistemlerin loglarinda
kullanin. Uretilen bulgular otomatik karar degil, **inceleme baslangic noktasidir**.

## Lisans

MIT — bkz. [LICENSE](LICENSE).

# Phishing Email Header Analyzer

![CI](https://github.com/KaanTuran28/Phishing-Email-Header-Analyzer/actions/workflows/ci.yml/badge.svg)
![Python](https://img.shields.io/badge/python-3.9%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)

<p align="center"><b><a href="#english">English</a></b> · <b><a href="#türkçe">Türkçe</a></b></p>

---

## English

A lightweight CLI tool that parses `.eml` email files and scores them for common phishing indicators — SPF/DKIM/DMARC authentication failures, sender/reply-to/return-path mismatches, display-name spoofing, and urgency-based subject lines. Built with the Python standard library only.

## Installation

Requires Python 3.8+. No external dependencies.

```bash
git clone <this-repo>
cd Phishing-Email-Header-Analyzer
pip install -e .
```

This installs a `phishing-email-header-analyzer` console command. You can also just run the script directly without installing (`python phishing_email_header_analyzer.py ...`).

## Usage

```bash
python phishing_email_header_analyzer.py --eml path/to/message.eml --output report.md
phishing-email-header-analyzer --eml path/to/message.eml --output report.json --format json
```

Options:

| Flag | Description |
|---|---|
| `--eml` | Path to the `.eml` file to analyze (required) |
| `--output` | Path to write the report (default: `sample_report.md`) |
| `--format` | `markdown` (default) or `json` |
| `--append` | Append to the output file instead of overwriting it |
| `--fail-on` | `none`, `medium`, or `high` — exit code `1` if the verdict is at/above this risk level |

The tool also prints a one-line verdict to stdout, e.g. `[High Risk] score=100 file=sample_emails/phishing_suspected.eml`.

## CI Integration

`--fail-on` gates a pipeline that scans incoming/quarantined mail (e.g. a mail-gateway hook or a scheduled sweep of a quarantine folder):

```bash
phishing-email-header-analyzer --eml quarantine/message.eml --fail-on high
```

```yaml
# GitHub Actions step
- name: Fail if quarantined message is high-risk
  run: phishing-email-header-analyzer --eml quarantine/message.eml --fail-on high
```

Default is `none` (always exits `0`) so ad-hoc analysis is unaffected.

## What It Checks

- **Authentication-Results** — SPF, DKIM, and DMARC pass/fail status
- **Sender consistency** — whether `From`, `Reply-To`, and `Return-Path` domains match
- **Display-name spoofing** — an official-sounding sender name paired with a suspicious-looking domain
- **Subject urgency** — common phishing pressure phrases ("urgent", "verify your account", "suspended", etc.)

Each check contributes points to a 0–100 risk score, mapped to a verdict: **Low Risk** (0–29), **Medium Risk** (30–59), **High Risk** (60–100).

## Example Output

Run against the three files in `sample_emails/` (full report in [`sample_report.md`](./sample_report.md)):

| File | Score | Verdict |
|---|---|---|
| `legitimate.eml` | 0/100 | Low Risk |
| `borderline.eml` | 40/100 | Medium Risk |
| `phishing_suspected.eml` | 100/100 | High Risk |

All sample emails use fictional companies and example.com-style domains — they do not represent any real organization.

## Testing

```bash
pip install -r requirements-dev.txt
ruff check .
pytest -v
```

## Project Structure

```
Phishing-Email-Header-Analyzer/
├── phishing_email_header_analyzer.py
├── pyproject.toml
├── sample_emails/
│   ├── legitimate.eml
│   ├── borderline.eml
│   └── phishing_suspected.eml
├── tests/
│   └── test_phishing_email_header_analyzer.py
├── .github/workflows/ci.yml
├── sample_report.md
├── requirements.txt
├── requirements-dev.txt
└── LICENSE
```

## License

MIT — see [LICENSE](./LICENSE).

---

## Türkçe

`.eml` e-posta dosyalarını ayrıştıran ve yaygın oltalama (phishing) göstergelerine göre puanlayan hafif bir CLI aracı — SPF/DKIM/DMARC kimlik doğrulama hataları, gönderen/yanıtla/dönüş-yolu (return-path) uyuşmazlıkları, görünen ad (display-name) sahteciliği ve aciliyet içeren konu satırları. Yalnızca Python standart kütüphanesi kullanılarak geliştirilmiştir.

## Kurulum

Python 3.8+ gerektirir. Harici bağımlılık yoktur.

```bash
git clone <this-repo>
cd Phishing-Email-Header-Analyzer
pip install -e .
```

Bu, `phishing-email-header-analyzer` adında bir konsol komutu kurar. Kurulum yapmadan da betiği doğrudan çalıştırabilirsiniz (`python phishing_email_header_analyzer.py ...`).

## Kullanım

```bash
python phishing_email_header_analyzer.py --eml path/to/message.eml --output report.md
phishing-email-header-analyzer --eml path/to/message.eml --output report.json --format json
```

Seçenekler:

| Flag | Açıklama |
|---|---|
| `--eml` | Analiz edilecek `.eml` dosyasının yolu (zorunlu) |
| `--output` | Raporun yazılacağı yol (varsayılan: `sample_report.md`) |
| `--format` | `markdown` (varsayılan) veya `json` |
| `--append` | Çıktı dosyasının üzerine yazmak yerine sonuna ekler |
| `--fail-on` | `none`, `medium` veya `high` — sonuç bu risk seviyesinde veya üzerindeyse çıkış kodu `1` olur |

Araç ayrıca standart çıktıya tek satırlık bir sonuç yazdırır, örn. `[High Risk] score=100 file=sample_emails/phishing_suspected.eml`.

## CI Entegrasyonu

`--fail-on`, gelen/karantinaya alınmış postaları tarayan bir hattı (örn. bir mail-gateway hook'u veya karantina klasörünün zamanlanmış taraması) kısıtlamak için kullanılır:

```bash
phishing-email-header-analyzer --eml quarantine/message.eml --fail-on high
```

```yaml
# GitHub Actions step
- name: Fail if quarantined message is high-risk
  run: phishing-email-header-analyzer --eml quarantine/message.eml --fail-on high
```

Varsayılan değer `none`'dur (her zaman `0` ile çıkış yapar), böylece geçici (ad-hoc) analizler etkilenmez.

## Neleri Kontrol Eder

- **Authentication-Results** — SPF, DKIM ve DMARC geçti/başarısız durumu
- **Gönderen tutarlılığı** — `From`, `Reply-To` ve `Return-Path` alan adlarının eşleşip eşleşmediği
- **Görünen ad sahteciliği** — resmi görünümlü bir gönderen adının şüpheli görünümlü bir alan adıyla eşleştirilmesi
- **Konu satırında aciliyet** — yaygın oltalama baskı ifadeleri ("urgent", "verify your account", "suspended", vb.)

Her kontrol, 0-100 aralığındaki risk puanına katkıda bulunur ve şu sonuçlarla eşlenir: **Low Risk** (0-29), **Medium Risk** (30-59), **High Risk** (60-100).

## Örnek Çıktı

`sample_emails/` içindeki üç dosyaya karşı çalıştırıldığında (tam rapor [`sample_report.md`](./sample_report.md) dosyasında):

| File | Score | Verdict |
|---|---|---|
| `legitimate.eml` | 0/100 | Low Risk |
| `borderline.eml` | 40/100 | Medium Risk |
| `phishing_suspected.eml` | 100/100 | High Risk |

Tüm örnek e-postalar kurgusal şirketler ve example.com tarzı alan adları kullanır — gerçek bir kuruluşu temsil etmezler.

## Test

```bash
pip install -r requirements-dev.txt
ruff check .
pytest -v
```

## Proje Yapısı

```
Phishing-Email-Header-Analyzer/
├── phishing_email_header_analyzer.py
├── pyproject.toml
├── sample_emails/
│   ├── legitimate.eml
│   ├── borderline.eml
│   └── phishing_suspected.eml
├── tests/
│   └── test_phishing_email_header_analyzer.py
├── .github/workflows/ci.yml
├── sample_report.md
├── requirements.txt
├── requirements-dev.txt
└── LICENSE
```

## Lisans

MIT — bkz. [LICENSE](./LICENSE).

---

# Durum Günlüğü

> En üstteki kayıt en güncelidir. Her çalışma sonrası buraya kısa bir not düşülür.

---

## 2026-08-21 — CI gating için `--fail-on` eklendi

- Konu: `--fail-on {none,medium,high}` bayrağı eklendi — verdict eşiğin üzerindeyse çıkış kodu 1 (karantina/mail-gateway pipeline'larında kullanılabilir). Varsayılan `none`, geriye dönük uyumlu.
- 4 yeni test eklendi (7 → 11), mevcut 3 örnek .eml dosyası kullanılarak. Ruff temiz.
- Durum: ✅ Henüz push edilmedi.

**Sıradaki iş:** GitHub'da `Phishing-Email-Header-Analyzer` adıyla repo aç, git init + push.

---

## 2026-08-20 — Paketleme, JSON çıktı ve lint eklendi

- Konu: `pyproject.toml` ile pip kurulabilir hale getirildi (`pip install -e .` → `phishing-email-header-analyzer` komutu), `--format json` eklendi, ruff lint + CI'da ayrı lint job'u eklendi.
- Durum: ✅ Tüm testler geçiyor (7/7), ruff temiz, kurulum/çalıştırma/kaldırma gerçekten denendi ve doğrulandı.

**Sıradaki iş:** GitHub'da `Phishing-Email-Header-Analyzer` adıyla repo aç, git init + push.

---

## 2026-08-20 — Test suite ve CI eklendi

- Konu: pytest test paketi (mevcut örnek .eml dosyaları fixture olarak kullanılarak) ve GitHub Actions CI iş akışı eklendi.
- Durum: ✅ Tüm testler geçiyor (5/5).

**Sıradaki iş:** GitHub'da `Phishing-Email-Header-Analyzer` adıyla repo aç, git init + push.

---

## 2026-08-20 — Proje oluşturuldu, script ve örnekler doğrulandı

- Konu: `.eml` dosyalarındaki phishing göstergelerini (SPF/DKIM/DMARC, gönderen uyuşmazlığı, display-name spoofing, aciliyet anahtar kelimeleri) puanlayan CLI aracı.
- Dosya: `phishing_email_header_analyzer.py`, `sample_emails/` (3 sentetik .eml), `sample_report.md`.
- Durum: Script üç örnek üzerinde gerçekten çalıştırıldı — `legitimate.eml` → Low Risk (0/100), `borderline.eml` → Medium Risk (40/100), `phishing_suspected.eml` → High Risk (100/100). Beklenen sonuçlarla birebir uyuştu.

**Sıradaki iş:** GitHub'da `Phishing-Email-Header-Analyzer` adıyla repo aç, `git init` → `git add .` → ilk commit → push.

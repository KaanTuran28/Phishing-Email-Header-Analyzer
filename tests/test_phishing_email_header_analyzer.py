import email
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import phishing_email_header_analyzer as pea

SAMPLE_EMAILS_DIR = Path(__file__).resolve().parents[1] / "sample_emails"


def test_legitimate_email_is_low_risk():
    result = pea.analyze(str(SAMPLE_EMAILS_DIR / "legitimate.eml"))
    assert result["verdict"] == "Low Risk"
    assert result["score"] < 30


def test_borderline_email_is_medium_risk():
    result = pea.analyze(str(SAMPLE_EMAILS_DIR / "borderline.eml"))
    assert result["verdict"] == "Medium Risk"
    assert 30 <= result["score"] < 60


def test_phishing_suspected_email_is_high_risk():
    result = pea.analyze(str(SAMPLE_EMAILS_DIR / "phishing_suspected.eml"))
    assert result["verdict"] == "High Risk"
    assert result["score"] >= 60


def test_check_auth_results_flags_failures():
    headers = (
        "Authentication-Results: mx.example.com; spf=fail smtp.mailfrom=x.example; "
        "dkim=fail header.d=x.example; dmarc=fail header.from=x.example\n"
    )
    findings, score = pea.check_auth_results(headers)
    assert score == 65
    statuses = {name: status for name, status, _, _ in findings}
    assert statuses["SPF"] == "FAIL"
    assert statuses["DKIM"] == "FAIL"
    assert statuses["DMARC"] == "FAIL"


def test_check_sender_consistency_detects_reply_to_mismatch():
    raw = (
        "From: \"Test Sender\" <test@realdomain.example>\n"
        "Reply-To: \"Test Sender\" <test@fake-domain.example>\n"
        "Return-Path: <test@realdomain.example>\n"
        "Subject: Hello\n\n"
        "Body text.\n"
    )
    msg = email.message_from_string(raw)
    findings, score = pea.check_sender_consistency(msg)
    assert score == 20
    statuses = {name: status for name, status, _, _ in findings}
    assert statuses["Reply-To vs From"] == "MISMATCH"
    assert statuses["Return-Path vs From"] == "OK"


def test_render_json_is_valid_and_has_expected_fields():
    result = pea.analyze(str(SAMPLE_EMAILS_DIR / "phishing_suspected.eml"))
    payload = json.loads(pea.render_json(result))
    assert payload["score"] == result["score"]
    assert payload["verdict"] == result["verdict"]
    assert isinstance(payload["findings"], list)
    assert all({"check", "status", "detail", "points"} <= f.keys() for f in payload["findings"])


def test_render_json_matches_findings_count():
    result = pea.analyze(str(SAMPLE_EMAILS_DIR / "legitimate.eml"))
    payload = json.loads(pea.render_json(result))
    assert len(payload["findings"]) == len(result["findings"])


def run_main(monkeypatch, tmp_path, eml_name, extra_args):
    out = str(tmp_path / "out.md")
    eml = str(SAMPLE_EMAILS_DIR / eml_name)
    argv = ["phishing_email_header_analyzer.py", "--eml", eml, "--output", out] + extra_args
    monkeypatch.setattr(sys, "argv", argv)
    return pea.main()


def test_fail_on_high_exits_nonzero_for_phishing_email(monkeypatch, tmp_path):
    assert run_main(monkeypatch, tmp_path, "phishing_suspected.eml", ["--fail-on", "high"]) == 1


def test_fail_on_high_exits_zero_for_borderline_email(monkeypatch, tmp_path):
    assert run_main(monkeypatch, tmp_path, "borderline.eml", ["--fail-on", "high"]) == 0


def test_fail_on_medium_exits_nonzero_for_borderline_email(monkeypatch, tmp_path):
    assert run_main(monkeypatch, tmp_path, "borderline.eml", ["--fail-on", "medium"]) == 1


def test_fail_on_none_exits_zero_even_for_phishing_email(monkeypatch, tmp_path):
    assert run_main(monkeypatch, tmp_path, "phishing_suspected.eml", []) == 0

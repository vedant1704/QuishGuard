from app.intel import analyze_url


def test_missing_api_keys_are_skipped(monkeypatch) -> None:
    monkeypatch.delenv("VT_API_KEY", raising=False)
    monkeypatch.delenv("GOOGLE_SAFE_BROWSING_KEY", raising=False)

    result = analyze_url("https://example.com")

    assert "VirusTotal (no API key)" in result["skipped_checks"]
    assert "Google Safe Browsing (no API key)" in result["skipped_checks"]
    assert result["score"] >= 0


def test_malicious_intel_flags_are_elevated(monkeypatch) -> None:
    monkeypatch.setenv("VT_API_KEY", "demo-vt")
    monkeypatch.setenv("GOOGLE_SAFE_BROWSING_KEY", "demo-gsb")

    class FakeResponse:
        def __init__(self, payload=None, status_code=200):
            self._payload = payload or {}
            self.status_code = status_code
            self.headers = {}

        def json(self):
            return self._payload

    def fake_get(*args, **kwargs):
        return FakeResponse(
            {
                "data": {"attributes": {"last_analysis_stats": {"malicious": 3, "suspicious": 1}}},
                "matches": [{"threatType": "MALWARE_URL"}],
            }
        )

    monkeypatch.setattr("app.intel.httpx.get", fake_get)

    result = analyze_url("https://malicious.example")

    assert result["verdict"] == "Malicious"
    assert result["score"] >= 71
    assert any("VirusTotal" in reason for reason in result["reasons"])

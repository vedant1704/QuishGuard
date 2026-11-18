from app.scorer import score_payload


def test_safe_url_scores_under_threshold() -> None:
    result = score_payload(
        {
            "payload": "https://example.com/about",
            "payload_type": "url",
            "extracted_fields": {"domain": "example.com", "path": "/about"},
        }
    )

    assert result["score"] < 31
    assert result["verdict"] == "Safe"


def test_obvious_phishing_url_scores_above_threshold() -> None:
    result = score_payload(
        {
            "payload": "https://paytm-secure-login-verify-kyc.com/verify",
            "payload_type": "login",
            "extracted_fields": {
                "domain": "paytm-secure-login-verify-kyc.com",
                "path": "/verify",
                "registered_domain": "paytm-secure-login-verify-kyc.com",
            },
        }
    )

    assert result["score"] > 70
    assert result["verdict"] == "Malicious"
    assert result["reasons"]


def test_upi_high_amount_flagged() -> None:
    result = score_payload(
        {
            "payload": "upi://pay?pa=alice@oksbi&pn=Alice%20Sharma&am=25000&cu=INR",
            "payload_type": "upi",
            "extracted_fields": {"pa": "alice@oksbi", "pn": "Alice Sharma", "am": "25000", "cu": "INR"},
        }
    )

    assert any("high amount" in reason.lower() for reason in result["reasons"])
    assert result["score"] >= 10

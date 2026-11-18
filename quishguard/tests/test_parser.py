from app.parser import parse_payload


def test_parse_upi_payload() -> None:
    payload = "upi://pay?pa=alice@upi&pn=Alice%20Sharma&am=250&cu=INR"

    result = parse_payload(payload)

    assert result["payload_type"] == "upi"
    assert result["extracted_fields"]["pa"] == "alice@upi"
    assert result["extracted_fields"]["pn"] == "Alice Sharma"
    assert result["extracted_fields"]["am"] == "250"
    assert result["extracted_fields"]["cu"] == "INR"


def test_parse_login_payload() -> None:
    payload = "https://web.whatsapp.com/send?text=hello"

    result = parse_payload(payload)

    assert result["payload_type"] == "login"
    assert result["extracted_fields"]["domain"] == "web.whatsapp.com"


def test_parse_general_url_payload() -> None:
    payload = "https://example.com/path?utm_source=ads"

    result = parse_payload(payload)

    assert result["payload_type"] == "url"
    assert result["extracted_fields"]["domain"] == "example.com"
    assert result["extracted_fields"]["path"] == "/path"


def test_parse_plain_text_payload() -> None:
    payload = "plain text message"

    result = parse_payload(payload)

    assert result["payload_type"] == "text"
    assert result["payload"] == payload
    assert result["extracted_fields"] == {}


def test_parse_malformed_input() -> None:
    payload = "://not a valid url"

    result = parse_payload(payload)

    assert result["payload_type"] == "text"
    assert result["extracted_fields"] == {}

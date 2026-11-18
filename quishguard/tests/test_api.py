from io import BytesIO

import qrcode
from fastapi.testclient import TestClient

from app.main import app


def _make_qr_bytes(payload: str) -> bytes:
    buffer = BytesIO()
    qr = qrcode.make(payload)
    qr.save(buffer, format="PNG")
    return buffer.getvalue()


def test_scan_accepts_valid_qr_image() -> None:
    client = TestClient(app)
    response = client.post(
        "/scan",
        files={"file": ("safe.png", _make_qr_bytes("https://example.com/scan"), "image/png")},
    )

    assert response.status_code == 200
    data = response.json()
    assert data["payload_type"] in {"url", "login", "text"}
    assert data["verdict"] in {"Safe", "Suspicious", "Malicious"}
    assert isinstance(data["reasons"], list)
    assert isinstance(data["skipped_checks"], list)


def test_scan_rejects_non_image() -> None:
    client = TestClient(app)
    response = client.post(
        "/scan",
        files={"file": ("not-image.txt", b"hello world", "text/plain")},
    )

    assert response.status_code == 400
    assert "image" in response.json()["detail"].lower()

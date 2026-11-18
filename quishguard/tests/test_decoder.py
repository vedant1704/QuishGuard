from pathlib import Path

from app.decoder import decode_qr_from_image


def test_decode_sample_qr_image() -> None:
    sample_path = Path(__file__).resolve().parents[1] / "samples" / "x.png"
    assert sample_path.exists(), "Sample QR image is missing"

    payload = decode_qr_from_image(sample_path)

    assert isinstance(payload, str)
    assert payload == "https://example.com/scan"

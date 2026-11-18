"""QR decoding utilities for QuishGuard."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

import cv2
import numpy as np
from pyzbar.pyzbar import decode


def _preprocess_image(image: np.ndarray) -> np.ndarray:
    """Enhance the image before trying QR decoding."""
    gray = cv2.cvtColor(image, cv2.COLOR_BGR2GRAY)
    gray = cv2.resize(gray, None, fx=2.0, fy=2.0, interpolation=cv2.INTER_LINEAR)
    gray = cv2.GaussianBlur(gray, (3, 3), 0)
    _, thresh = cv2.threshold(gray, 0, 255, cv2.THRESH_BINARY + cv2.THRESH_OTSU)
    return thresh


def decode_qr_from_image(image_path: str | Path) -> str:
    """Decode a QR image and return the payload string."""
    path = Path(image_path)
    image = cv2.imread(str(path))
    if image is None:
        raise ValueError(f"Could not read image: {path}")

    attempts = [image, _preprocess_image(image)]
    for frame in attempts:
        try:
            decoded = decode(frame)
            if decoded:
                return decoded[0].data.decode("utf-8", errors="replace")
        except Exception:
            pass

        try:
            qr_data, _, _ = cv2.QRCodeDetector().detectAndDecode(frame)
            if qr_data:
                return qr_data
        except Exception:
            pass

    raise ValueError(f"Unable to decode QR code from {path}")


def main(argv: list[str] | None = None) -> int:
    """CLI entry point for QR decoding."""
    parser = argparse.ArgumentParser(description="Decode a QR code image in QuishGuard.")
    parser.add_argument("image_path", help="Path to the QR image to decode")
    args = parser.parse_args(argv)

    try:
        print(decode_qr_from_image(args.image_path))
        return 0
    except ValueError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

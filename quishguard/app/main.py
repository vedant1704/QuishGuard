"""FastAPI application for QuishGuard QR scanning."""

from __future__ import annotations

import os
import tempfile
from pathlib import Path
from typing import Any

import cv2
import numpy as np
from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles

from app.decoder import decode_qr_from_image
from app.intel import analyze_url
from app.ml import get_ml_signal
from app.parser import parse_payload
from app.scorer import score_payload


ALLOWED_EXTENSIONS = {".png", ".jpg", ".jpeg", ".bmp", ".webp"}
MAX_FILE_SIZE = 5 * 1024 * 1024

frontend_dir = Path(__file__).resolve().parents[1] / "frontend"
app = FastAPI(title="QuishGuard", version="0.1.0")


@app.get("/health")
def health() -> dict[str, str]:
    """Simple health-check endpoint for the service."""
    return {"status": "ok"}


@app.post("/scan")
async def scan_qr(file: UploadFile = File(...)) -> dict[str, Any]:
    """Decode and score a QR image upload without opening the destination."""
    if not file.filename:
        raise HTTPException(status_code=400, detail="No file was uploaded.")

    extension = Path(file.filename).suffix.lower()
    if extension not in ALLOWED_EXTENSIONS:
        raise HTTPException(status_code=400, detail="Only image uploads are allowed (.png, .jpg, .jpeg, .bmp, .webp).")

    file_bytes = await file.read()
    if len(file_bytes) == 0:
        raise HTTPException(status_code=400, detail="The uploaded file is empty.")
    if len(file_bytes) > MAX_FILE_SIZE:
        raise HTTPException(status_code=400, detail="The uploaded image exceeds the 5MB limit.")

    image_array = np.frombuffer(file_bytes, dtype=np.uint8)
    image = cv2.imdecode(image_array, cv2.IMREAD_COLOR)
    if image is None:
        raise HTTPException(status_code=400, detail="The uploaded file could not be read as an image.")

    with tempfile.NamedTemporaryFile(suffix=extension or ".png", delete=False) as temp_file:
        temp_path = temp_file.name
        cv2.imwrite(temp_path, image)

    try:
        try:
            decoded_payload = decode_qr_from_image(temp_path)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=f"Could not decode QR code: {exc}") from exc

        parsed_payload = parse_payload(decoded_payload)
        if parsed_payload["payload_type"] == "text":
            result = score_payload(parsed_payload)
            return result

        intel_result = analyze_url(parsed_payload["payload"])
        ml_signal = get_ml_signal(parsed_payload["payload"]) if parsed_payload["payload_type"] in {"url", "login"} else None
        result = score_payload(parsed_payload, threat_intel=intel_result, ml_signal=ml_signal)
        return result
    finally:
        try:
            os.remove(temp_path)
        except FileNotFoundError:
            pass


@app.get("/", response_class=HTMLResponse)
async def serve_frontend() -> HTMLResponse:
    """Serve the single-page frontend for browser uploads."""
    index_path = frontend_dir / "index.html"
    return HTMLResponse(index_path.read_text(encoding="utf-8"))


app.mount("/static", StaticFiles(directory=str(frontend_dir), html=False), name="static")

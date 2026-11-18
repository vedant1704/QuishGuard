"""Payload classification and field extraction for QuishGuard."""

from __future__ import annotations

from typing import Any
from urllib.parse import parse_qs, unquote, urlsplit

import tldextract


def _safe_unquote(value: str) -> str:
    """Decode percent-encoded strings without raising errors."""
    return unquote(value).strip()


def _looks_like_upi(payload: str) -> bool:
    """Check whether a payload resembles a UPI payment string."""
    text = payload.strip().lower()
    return text.startswith("upi://") or "pa=" in text or "upi" in text and "pay" in text


def _parse_upi_fields(payload: str) -> dict[str, str]:
    """Extract UPI parameters when available."""
    parsed = urlsplit(payload)
    query_map = parse_qs(parsed.query, keep_blank_values=True)
    fields: dict[str, str] = {}

    for key in ("pa", "pn", "am", "cu"):
        values = query_map.get(key, [])
        if values:
            fields[key] = _safe_unquote(values[0])

    if not fields and payload:
        for key in ("pa", "pn", "am", "cu"):
            marker = f"{key}="
            if marker in payload.lower():
                after = payload.split(marker, 1)[1]
                value = after.split("&", 1)[0]
                fields[key] = _safe_unquote(value)

    if "pn" in fields:
        fields["pn"] = fields["pn"].replace("+", " ")

    return fields


def _extract_url_fields(url: str) -> dict[str, str]:
    """Extract commonly useful URL metadata using tldextract."""
    extracted = tldextract.extract(url)
    parts = urlsplit(url)

    fields: dict[str, str] = {
        "scheme": parts.scheme,
        "domain": extracted.fqdn or extracted.domain,
        "registered_domain": extracted.registered_domain or extracted.domain,
        "subdomain": extracted.subdomain,
        "tld": extracted.suffix,
        "path": parts.path or "/",
        "query": parts.query,
        "fragment": parts.fragment,
        "hostname": parts.hostname or "",
    }

    if not fields["domain"]:
        fields.pop("domain")

    if not fields["registered_domain"]:
        fields.pop("registered_domain")

    return {key: value for key, value in fields.items() if value not in (None, "")}


def _looks_like_login_url(url: str) -> bool:
    """Heuristically detect login/session links based on domain or path patterns."""
    lower = url.lower()
    login_markers = (
        "web.whatsapp.com",
        "accounts.",
        "signin",
        "login",
        "auth",
        "sso",
        "session",
        "verify",
        "secure",
        "kyc",
    )

    return any(marker in lower for marker in login_markers)


def _looks_like_url(value: str) -> bool:
    """Check whether a value is a valid URL-like payload."""
    parsed = urlsplit(value)
    return bool(parsed.scheme in {"http", "https"} and parsed.netloc)


def parse_payload(payload: str) -> dict[str, Any]:
    """Classify a QR payload and return structured fields for downstream scoring."""
    text = (payload or "").strip()
    result: dict[str, Any] = {
        "payload": text,
        "payload_type": "text",
        "extracted_fields": {},
    }

    if not text:
        return result

    if _looks_like_upi(text):
        fields = _parse_upi_fields(text)
        result["payload_type"] = "upi"
        result["extracted_fields"] = fields
        return result

    if _looks_like_url(text):
        extracted = _extract_url_fields(text)
        result["payload_type"] = "login" if _looks_like_login_url(text) else "url"
        result["extracted_fields"] = extracted
        return result

    return result

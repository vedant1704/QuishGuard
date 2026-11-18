"""Rule-based scoring for decoded QR payloads."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from rapidfuzz import fuzz


SHORTENER_DOMAINS = {
    "bit.ly",
    "tinyurl.com",
    "goo.gl",
    "ow.ly",
    "t.co",
    "is.gd",
    "lnkd.in",
    "rb.gy",
}

SUSPICIOUS_KEYWORDS = (
    "login",
    "verify",
    "secure",
    "kyc",
    "signin",
    "session",
    "confirm",
    "account",
    "update",
    "otp",
    "bank",
    "payment",
    "auth",
    "wallet",
)

KNOWN_PSP_HANDLES = {
    "upi",
    "oksbi",
    "okhdfcbank",
    "okicici",
    "okaxis",
    "ybl",
    "paytm",
    "phonepe",
    "icici",
    "sbi",
    "axis",
    "hdfcbank",
    "kotak",
    "yesbank",
    "boi",
    "airtel",
    "jio",
    "freecharge",
    "amazonpay",
}


def _load_brands() -> list[str]:
    """Load known brand names for typosquatting comparisons."""
    file_path = Path(__file__).resolve().parents[1] / "data" / "brands.json"
    with file_path.open("r", encoding="utf-8") as handle:
        brands = json.load(handle)
    return [brand.lower() for brand in brands if isinstance(brand, str)]


def _add_reason(score: int, reasons: list[str], reason: str) -> int:
    """Add a score and a matching human-readable reason."""
    if reason and not any(reason == existing for existing in reasons):
        reasons.append(reason)
    return score


def _domain_similarity(domain: str) -> tuple[str, int] | None:
    """Return the closest brand match for a domain if it is suspiciously similar."""
    brand_list = _load_brands()
    domain_clean = domain.lower().replace("www.", "").split(":", 1)[0]
    best_brand = None
    best_score = 0

    for brand in brand_list:
        score = fuzz.ratio(brand, domain_clean)
        if score > best_score:
            best_score = score
            best_brand = brand

    if best_brand and best_score >= 80 and best_brand not in domain_clean:
        return best_brand, best_score
    return None


def _is_ip_address(host: str) -> bool:
    """Check if a hostname is an IP literal."""
    return bool(re.fullmatch(r"(?:\d{1,3}\.){3}\d{1,3}", host))


def _score_url(fields: dict[str, Any], payload: str) -> tuple[int, list[str]]:
    """Score a general URL or login QR payload."""
    score = 0
    reasons: list[str] = []

    domain = str(fields.get("domain") or fields.get("registered_domain") or fields.get("hostname") or "").lower()
    path = str(fields.get("path") or "").lower()
    hostname = str(fields.get("hostname") or domain).lower()

    if not domain:
        score += 10
        reasons.append("The decoded URL has no usable domain, which is unusual for a normal link.")

    if _is_ip_address(hostname):
        score += 25
        reasons.append("The URL uses an IP address instead of a normal hostname.")

    if any(short in hostname for short in SHORTENER_DOMAINS):
        score += 20
        reasons.append("The domain matches a URL shortener, which can hide the true destination.")

    if hostname.count(".") > 3 or hostname.count("-") >= 2:
        score += 15
        reasons.append("The hostname has excessive subdomains or hyphenation, which is common in phishing URLs.")

    if any(keyword in hostname or keyword in path for keyword in SUSPICIOUS_KEYWORDS):
        score += 20
        reasons.append("The URL contains suspicious login or verification keywords commonly used in phishing pages.")

    if any(brand in hostname for brand in ("paytm", "phonepe", "google", "facebook", "whatsapp", "sbi", "axis", "hdfc")) and any(
        keyword in hostname or keyword in path for keyword in SUSPICIOUS_KEYWORDS
    ):
        score += 35
        reasons.append("The hostname combines a familiar brand with login or verification keywords, a common phishing pattern.")

    suspicion = _domain_similarity(domain or hostname)
    if suspicion:
        brand, ratio = suspicion
        score += 25
        reasons.append(f"The domain is unusually similar to the brand '{brand}' (similarity {ratio}%), which suggests typosquatting.")

    if payload.startswith("https://") and payload.count("//") > 1:
        score += 10
        reasons.append("The URL structure looks malformed or obfuscated.")

    return score, reasons


def _score_login(fields: dict[str, Any], payload: str) -> tuple[int, list[str]]:
    """Score login/session QR links with a slightly stricter logic."""
    score, reasons = _score_url(fields, payload)

    domain = str(fields.get("domain") or fields.get("registered_domain") or fields.get("hostname") or "").lower()
    path = str(fields.get("path") or "").lower()

    if any(marker in domain or marker in path for marker in ("verify", "secure", "kyc", "signin", "login", "auth")):
        score += 20
        reasons.append("This login link uses security or verification language in its path, which is often used to trick users.")

    if any(brand in domain for brand in ("paytm", "phonepe", "google", "facebook", "whatsapp", "sbi", "axis", "hdfc")) and any(
        marker in domain or marker in path for marker in ("verify", "secure", "kyc", "signin", "login", "auth")
    ):
        score += 30
        reasons.append("This brand-like login URL mixes a familiar brand with login-security language, which is a common phishing setup.")

    if "web.whatsapp.com" in domain or "whatsapp" in domain:
        if not domain.startswith("web.whatsapp.com"):
            score += 25
            reasons.append("This WhatsApp-like flow points to a different hostname than the normal WhatsApp Web login flow.")

    return score, reasons


def _score_upi(fields: dict[str, Any]) -> tuple[int, list[str]]:
    """Score UPI QR payloads using the prompt rules."""
    score = 0
    reasons: list[str] = []

    payee = (fields.get("pa") or "").strip()
    payee_name = (fields.get("pn") or "").strip()
    amount = fields.get("am")

    if not payee or "@" not in payee:
        score += 25
        reasons.append("The UPI ID is missing or malformed, which makes the payment target untrustworthy.")
    else:
        psp = payee.rsplit("@", 1)[1].lower()
        if psp not in KNOWN_PSP_HANDLES:
            score += 20
            reasons.append("The UPI handle uses an unrecognized payment service provider.")

    if payee_name:
        brand_match = any(brand in payee.lower() for brand in {"paytm", "phonepe", "hdfc", "sbi", "axis", "icici"})
        if brand_match and all(brand not in payee_name.lower() for brand in {"paytm", "phonepe", "hdfc", "sbi", "axis", "icici"}):
            score += 15
            reasons.append("The payee name does not match the expected UPI brand or handle.")

    try:
        if amount is not None:
            amount_value = float(str(amount).replace(",", ""))
            if amount_value > 10000:
                score += 20
                reasons.append("The pre-filled high amount is unusually high for a normal payment QR.")
    except (TypeError, ValueError):
        score += 10
        reasons.append("The amount field is malformed and could not be safely parsed.")

    return score, reasons


def score_payload(
    parsed_payload: dict[str, Any],
    threat_intel: dict[str, Any] | None = None,
    ml_signal: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Return a verdict, score, human-readable reasons, and extracted fields."""
    payload = str(parsed_payload.get("payload") or "")
    payload_type = str(parsed_payload.get("payload_type") or "text").lower()
    extracted = parsed_payload.get("extracted_fields") or {}

    if payload_type == "text":
        return {
            "verdict": "Safe",
            "score": 0,
            "payload_type": "text",
            "payload": payload,
            "extracted_fields": {},
            "reasons": [],
            "skipped_checks": [],
        }

    score = 0
    reasons: list[str] = []
    skipped_checks: list[str] = []

    if payload_type == "upi":
        additional_score, additional_reasons = _score_upi(extracted)
        score += additional_score
        reasons.extend(additional_reasons)
    elif payload_type == "login":
        additional_score, additional_reasons = _score_login(extracted, payload)
        score += additional_score
        reasons.extend(additional_reasons)
    elif payload_type == "url":
        additional_score, additional_reasons = _score_url(extracted, payload)
        score += additional_score
        reasons.extend(additional_reasons)

    if threat_intel:
        score += int(threat_intel.get("score", 0))
        reasons.extend(threat_intel.get("reasons", []))
        skipped_checks.extend(threat_intel.get("skipped_checks", []))

    if ml_signal:
        score += int(ml_signal.get("score", 0))
        reason = ml_signal.get("reason")
        if reason:
            reasons.append(reason)

    if score >= 71:
        verdict = "Malicious"
    elif score >= 31:
        verdict = "Suspicious"
    else:
        verdict = "Safe"

    return {
        "verdict": verdict,
        "score": score,
        "payload_type": payload_type,
        "payload": payload,
        "extracted_fields": extracted,
        "reasons": reasons,
        "skipped_checks": skipped_checks,
    }

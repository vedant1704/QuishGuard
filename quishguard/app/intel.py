"""Threat intelligence checks for QuishGuard."""

from __future__ import annotations

import os
import socket
import ssl
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from typing import Any
from urllib.parse import quote, urlsplit

import httpx
from dotenv import load_dotenv
from whois import whois


def _load_api_keys() -> dict[str, str]:
    """Load configured API keys from the environment or .env file."""
    load_dotenv()
    return {
        "vt": os.getenv("VT_API_KEY", "").strip(),
        "gsb": os.getenv("GOOGLE_SAFE_BROWSING_KEY", "").strip(),
    }


def _domain_from_url(url: str) -> str:
    """Extract a domain from a URL."""
    hostname = urlsplit(url).hostname or url
    return hostname.strip().lower()


def _check_ssl(hostname: str, timeout: float = 4.0) -> bool:
    """Perform a light SSL validation check without fetching page content."""
    try:
        context = ssl.create_default_context()
        with socket.create_connection((hostname, 443), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as wrapped:
                cert = wrapped.getpeercert()
                return bool(cert)
    except Exception:
        return False


def _check_whois(domain: str) -> dict[str, Any]:
    """Inspect WHOIS metadata and return domain age details if available."""
    try:
        data = whois(domain)
        if not data:
            return {"age_days": None, "details": "WHOIS data unavailable"}

        creation = getattr(data, "creation_date", None)
        if isinstance(creation, list) and creation:
            creation = creation[0]
        if creation is None:
            return {"age_days": None, "details": "WHOIS data unavailable"}

        age_days = max(0, (datetime.now(timezone.utc) - creation).days)
        return {"age_days": age_days, "details": "WHOIS data available"}
    except Exception:
        return {"age_days": None, "details": "WHOIS lookup failed"}


def _expand_redirects(url: str, timeout: float = 3.0, max_hops: int = 5) -> str:
    """Follow redirect headers only, never fetching page content."""
    current = url
    visited: set[str] = set()

    for _ in range(max_hops):
        if current in visited:
            break
        visited.add(current)
        try:
            response = httpx.get(current, timeout=timeout, follow_redirects=False, headers={"User-Agent": "QuishGuard/1.0"})
        except Exception:
            break

        location = response.headers.get("location") or response.headers.get("Location")
        if not location:
            break
        current = location if location.startswith("http") else urlsplit(current)._replace(path="", query="", fragment="").scheme + "://" + urlsplit(current).netloc + location

    return current


def _check_virustotal(url: str, api_key: str, timeout: float = 5.0) -> dict[str, Any]:
    """Query VirusTotal if an API key is configured."""
    endpoint = f"https://www.virustotal.com/api/v3/search?query={quote(url)}"
    headers = {"x-apikey": api_key, "User-Agent": "QuishGuard/1.0"}
    try:
        response = httpx.get(endpoint, headers=headers, timeout=timeout)
        payload = response.json() if response.status_code == 200 else {}
        stats = payload.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
        malicious = int(stats.get("malicious", 0))
        suspicious = int(stats.get("suspicious", 0))
        if malicious > 0 or suspicious > 0:
            return {"flagged": True, "score": 75, "reason": "VirusTotal flagged the URL as malicious or suspicious."}
        return {"flagged": False, "score": 0, "reason": "VirusTotal did not flag the URL."}
    except Exception:
        return {"flagged": False, "score": 0, "reason": "VirusTotal request failed or timed out."}


def _check_google_safebrowsing(url: str, api_key: str, timeout: float = 5.0) -> dict[str, Any]:
    """Query Google Safe Browsing if an API key is configured."""
    endpoint = (
        "https://safebrowsing.googleapis.com/v4/threatMatches:find?"
        f"key={api_key}&url={quote(url)}"
    )
    try:
        response = httpx.get(endpoint, timeout=timeout, headers={"User-Agent": "QuishGuard/1.0"})
        payload = response.json() if response.status_code == 200 else {}
        matches = payload.get("matches", [])
        if matches:
            return {"flagged": True, "score": 75, "reason": "Google Safe Browsing flagged the URL as malicious."}
        return {"flagged": False, "score": 0, "reason": "Google Safe Browsing did not flag the URL."}
    except Exception:
        return {"flagged": False, "score": 0, "reason": "Google Safe Browsing request failed or timed out."}


def analyze_url(url: str, timeout: float = 5.0) -> dict[str, Any]:
    """Run the threat-intelligence checks and return a verdict, score, and reasons."""
    api_keys = _load_api_keys()
    skipped_checks: list[str] = []
    reasons: list[str] = []
    score = 0

    if not api_keys["vt"]:
        skipped_checks.append("VirusTotal (no API key)")
    if not api_keys["gsb"]:
        skipped_checks.append("Google Safe Browsing (no API key)")

    domain = _domain_from_url(url)

    def _run_check(task_name: str, worker):
        nonlocal score, reasons
        result = worker()
        if not result:
            return
        if result.get("flagged"):
            score += int(result.get("score", 0))
            reasons.append(result.get("reason", task_name))

    with ThreadPoolExecutor(max_workers=5) as executor:
        futures = []
        if api_keys["vt"]:
            futures.append(executor.submit(_check_virustotal, url, api_keys["vt"], timeout))
        if api_keys["gsb"]:
            futures.append(executor.submit(_check_google_safebrowsing, url, api_keys["gsb"], timeout))
        futures.append(executor.submit(_check_whois, domain))
        futures.append(executor.submit(_check_ssl, domain, timeout))
        futures.append(executor.submit(_expand_redirects, url, timeout))

        for future in futures:
            result = future.result()
            if isinstance(result, dict) and "flagged" in result:
                _run_check("threat-intel", lambda: result)
            elif isinstance(result, dict) and "age_days" in result:
                age_days = result.get("age_days")
                if age_days is None:
                    score += 10
                    reasons.append("WHOIS returned no domain age data, which is a mild suspicious signal.")
                else:
                    if age_days <= 30:
                        score += 15
                        reasons.append("The domain is newly registered, which increases phishing risk.")
            elif isinstance(result, bool):
                if not result:
                    score += 15
                    reasons.append("The site does not present a valid SSL certificate, which increases risk.")
            elif isinstance(result, str):
                if result != url:
                    score += 10
                    reasons.append("The URL redirected to a different destination, which can hide the final target.")

    if score >= 71:
        verdict = "Malicious"
    elif score >= 31:
        verdict = "Suspicious"
    else:
        verdict = "Safe"

    return {
        "verdict": verdict,
        "score": min(score, 100),
        "reasons": reasons,
        "skipped_checks": skipped_checks,
        "domain": domain,
        "expanded_url": _expand_redirects(url, timeout),
    }

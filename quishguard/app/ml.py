"""Optional machine-learning layer for QuishGuard phishing detection."""

from __future__ import annotations

import csv
import json
import re
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import joblib
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, confusion_matrix, f1_score, precision_score, recall_score
from sklearn.model_selection import train_test_split

try:
    from xgboost import XGBClassifier
except ImportError:  # pragma: no cover - optional dependency fallback
    XGBClassifier = None

MODEL_PATH = Path(__file__).resolve().parents[1] / "data" / "ml_model.joblib"
SUSPICIOUS_KEYWORDS = (
    "login",
    "verify",
    "secure",
    "kyc",
    "signin",
    "session",
    "update",
    "account",
    "bank",
    "wallet",
    "auth",
    "payment",
)
SHORTENER_DOMAINS = (
    "bit.ly",
    "tinyurl.com",
    "goo.gl",
    "t.co",
    "is.gd",
    "ow.ly",
    "lnkd.in",
    "rb.gy",
)


def extract_url_features(url: str) -> list[float]:
    """Convert a URL string into a fixed-length numeric feature vector."""
    if not url:
        return [0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0]

    normalized = url.strip()
    if not normalized.startswith(("http://", "https://")):
        normalized = "https://" + normalized

    parsed = urlsplit(normalized)
    host = (parsed.netloc or "").lower()
    path = (parsed.path or "").lower()

    length = len(normalized)
    dot_count = len(host.split(".")) if host else 0
    hyphen_count = host.count("-")
    digit_count = sum(char.isdigit() for char in host)
    keyword_hits = sum(1 for keyword in SUSPICIOUS_KEYWORDS if keyword in normalized.lower())
    shortener_flag = 1 if any(shortener in host for shortener in SHORTENER_DOMAINS) else 0
    ip_flag = 1 if bool(re.fullmatch(r"(?:\d{1,3}\.){3}\d{1,3}", host)) else 0
    path_length = len(path)

    return [float(length), float(dot_count), float(hyphen_count), float(digit_count), float(keyword_hits), float(shortener_flag), float(ip_flag), float(path_length)]


def _synthetic_dataset() -> list[tuple[str, int]]:
    """Create a compact demo dataset when no public CSV is provided."""
    safe_urls = [
        "https://example.com/about",
        "https://github.com/quishguard",
        "https://www.google.com/search?q=secure",
        "https://www.whatsapp.com/",
        "https://www.hdfcbank.com/",
    ]
    phishing_urls = [
        "https://paytm-secure-login-verify-kyc.com/verify",
        "https://secure-bank-login-update-account.com/auth",
        "https://login.whatsapp-verify-session.net/secure",
        "https://tinyurl.com/abc123",
        "https://128.0.0.1/login",
    ]
    return [(url, 0) for url in safe_urls] + [(url, 1) for url in phishing_urls]


def _load_dataset(dataset_path: str | Path | None) -> list[tuple[str, int]]:
    """Load the phishing dataset from a CSV if available, otherwise use the built-in fallback set."""
    if dataset_path and Path(dataset_path).exists():
        rows: list[tuple[str, int]] = []
        with open(dataset_path, "r", encoding="utf-8", newline="") as csv_file:
            reader = csv.DictReader(csv_file)
            for row in reader:
                url = str(row.get("url") or row.get("URL") or "").strip()
                label_value = row.get("label") or row.get("is_phishing") or row.get("phishing")
                if not url:
                    continue
                label = int(label_value) if label_value is not None else 0
                rows.append((url, label))
        if rows:
            return rows
    return _synthetic_dataset()


def train_and_save_model(
    dataset_path: str | Path | None = None,
    output_path: str | Path = MODEL_PATH,
) -> dict[str, Any]:
    """Train a Random Forest baseline and XGBoost variant, then save the best model to disk."""
    records = _load_dataset(dataset_path)
    X = [extract_url_features(url) for url, _ in records]
    y = [label for _, label in records]

    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)

    models: dict[str, Any] = {
        "RandomForest": RandomForestClassifier(
            n_estimators=200,
            random_state=42,
            class_weight="balanced",
            min_samples_leaf=1,
        )
    }
    if XGBClassifier is not None:
        models["XGBoost"] = XGBClassifier(
            n_estimators=200,
            max_depth=6,
            learning_rate=0.1,
            subsample=0.9,
            colsample_bytree=0.9,
            objective="binary:logistic",
            eval_metric="logloss",
            random_state=42,
        )

    metrics_by_model: dict[str, Any] = {}
    trained_models: dict[str, Any] = {}

    for name, model in models.items():
        model.fit(X_train, y_train)
        predictions = model.predict(X_test)
        metrics_by_model[name] = {
            "accuracy": accuracy_score(y_test, predictions),
            "precision": precision_score(y_test, predictions, zero_division=0),
            "recall": recall_score(y_test, predictions, zero_division=0),
            "f1": f1_score(y_test, predictions, zero_division=0),
            "confusion_matrix": confusion_matrix(y_test, predictions).tolist(),
        }
        trained_models[name] = model

    best_model_name = max(metrics_by_model, key=lambda name: metrics_by_model[name]["f1"])
    best_model = trained_models[best_model_name]
    artifact = {
        "model": best_model,
        "selected_model": best_model_name,
        "metrics": metrics_by_model,
        "feature_count": len(X[0]) if X else 0,
    }
    output = Path(output_path)
    output.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(artifact, output)
    return metrics_by_model


def load_model(model_path: str | Path = MODEL_PATH) -> dict[str, Any]:
    """Load the saved model artifact from disk, training it when absent."""
    path = Path(model_path)
    if not path.exists():
        train_and_save_model(output_path=path)
    artifact = joblib.load(path)
    return artifact


def predict_url_risk(url: str, model_path: str | Path = MODEL_PATH) -> float:
    """Return a probability score in the 0..1 range for how likely the URL is phishing-like."""
    artifact = load_model(model_path)
    model = artifact["model"]
    features = extract_url_features(url)
    probability = model.predict_proba([features])[0, 1]
    return float(probability)


def get_ml_signal(url: str, model_path: str | Path = MODEL_PATH) -> dict[str, Any]:
    """Blend the ML model into a single risk signal with a human-readable explanation."""
    risk_score = predict_url_risk(url, model_path)
    blended_score = int(round(risk_score * 25))
    return {
        "score": max(0, min(25, blended_score)),
        "confidence": round(risk_score, 4),
        "reason": (
            f"The ML model estimates this URL has a {risk_score:.2f} phishing risk, which adds a machine-learning signal to the verdict."
        ),
    }

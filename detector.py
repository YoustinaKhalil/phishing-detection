"""Loads the model once and turns a raw user string into a verdict.

Used by main.py (FastAPI) and by test_cases.py - no web framework needed here.
"""
import pickle
from pathlib import Path

import pandas as pd

from features import base_features, url_features
from validation import InvalidURL, prepare_url  # noqa: F401  (InvalidURL re-exported)

BASE_DIR = Path(__file__).resolve().parent

with open(BASE_DIR / "Final_model.pkl", "rb") as f:
    model = pickle.load(f)
with open(BASE_DIR / "model_scaler.pkl", "rb") as f:
    meta = pickle.load(f)

scaler = meta["scaler"]
COLS = list(meta["feature order"])
THRESHOLD = float(meta.get("threshold", 0.5))   # score >= this  -> phishing
SUSPICIOUS_FROM = 0.30                          # between this and THRESHOLD -> suspicious


def model_score(url: str) -> float:
    """Probability (0..1) that the URL is phishing, according to the Random Forest."""
    feats = pd.DataFrame([{**base_features(url), **url_features(url)}])[COLS]
    return float(model.predict_proba(scaler.transform(feats))[0, 1])


def analyze(raw: str) -> dict:
    """Raises InvalidURL if the input is not a link. Otherwise returns the verdict dict."""
    prep = prepare_url(raw)
    high = [m for lvl, m in prep.flags if lvl == "high"]
    medium = [m for lvl, m in prep.flags if lvl == "medium"]

    # Raw IP links were removed from the training data, so the model has no opinion on them.
    score = None if prep.is_ip else model_score(prep.url)
    reasons = high + medium

    if high:
        verdict = "phishing"
    elif prep.is_ip or prep.shortener:   # model can't judge these -> never say "safe"
        verdict = "suspicious"
    elif prep.trusted and not medium:
        verdict = "safe"
        reasons = [f"{prep.registered_domain} is a well-known website."]
    elif score >= THRESHOLD:
        verdict = "phishing"
        reasons.append("The structure of this link closely matches known phishing links.")
    elif medium or score >= SUSPICIOUS_FROM:
        verdict = "suspicious"
        if score >= SUSPICIOUS_FROM:
            reasons.append("Some parts of this link look unusual.")
    else:
        verdict = "safe"

    return {
        "url": prep.url,
        "verdict": verdict,                      # "safe" | "suspicious" | "phishing"
        "is_phishing": verdict == "phishing",
        "score": score,
        "reasons": reasons,
    }

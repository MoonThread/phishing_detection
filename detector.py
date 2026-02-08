from url_utils import parse_url
from rules import (
    rule_url_length,
    rule_has_at_symbol,
    rule_contains_ip,
    rule_too_many_dots,
    rule_https,
    rule_suspicious_keywords
)

THRESHOLD = 4  # score >= threshold => phishing

def detect_phishing(url: str):
    data = parse_url(url)

    score = 0
    triggered = []

    rules = [
        lambda: rule_url_length(url),
        lambda: rule_has_at_symbol(url),
        lambda: rule_contains_ip(data["domain"]),
        lambda: rule_too_many_dots(data["domain"]),
        lambda: rule_https(data["scheme"]),
        lambda: rule_suspicious_keywords(url),
    ]

    for rule in rules:
        triggered_bool, points, reason = rule()
        if triggered_bool:
            score += points
            triggered.append(f"{reason} (+{points})")

    is_phishing = score >= THRESHOLD

    # Confidence Level
    if score < 3:
        confidence = "LOW"
    elif score < 6:
        confidence = "MEDIUM"
    else:
        confidence = "HIGH"

    return {
        "url": url,
        "domain": data["domain"],
        "score": score,
        "is_phishing": is_phishing,
        "confidence": confidence,
        "triggered_rules": triggered
    }

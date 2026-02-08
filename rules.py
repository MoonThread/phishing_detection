from url_utils import contains_ip

SUSPICIOUS_KEYWORDS = [
    "login", "verify", "update", "secure", "account",
    "bank", "confirm", "password", "free", "bonus"
]

def rule_url_length(url: str):
    if len(url) > 75:
        return True, 2, "URL is too long"
    return False, 0, ""

def rule_has_at_symbol(url: str):
    if "@" in url:
        return True, 3, "URL contains @ symbol"
    return False, 0, ""

def rule_contains_ip(domain: str):
    if contains_ip(domain):
        return True, 4, "Domain is an IP address"
    return False, 0, ""

def rule_too_many_dots(domain: str):
    if domain.count(".") >= 3:
        return True, 2, "Too many subdomains"
    return False, 0, ""

def rule_https(scheme: str):
    if scheme != "https":
        return True, 2, "Not using HTTPS"
    return False, 0, ""

def rule_suspicious_keywords(url: str):
    found = []
    lower_url = url.lower()
    for word in SUSPICIOUS_KEYWORDS:
        if word in lower_url:
            found.append(word)
    if found:
        points = min(4, len(found))  # max 4 points
        return True, points, f"Suspicious keywords found: {', '.join(found)}"
    return False, 0, ""

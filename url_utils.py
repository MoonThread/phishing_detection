from urllib.parse import urlparse
import re

def parse_url(url: str):
    url = url.strip()

    # Auto add http:// if missing
    if not url.startswith(("http://", "https://")):
        url = "http://" + url

    parsed = urlparse(url)

    domain = parsed.netloc
    path = parsed.path
    scheme = parsed.scheme
    query = parsed.query

    if domain.startswith("www."):
        domain = domain[4:]

    return {
        "scheme": scheme,
        "domain": domain,
        "path": path,
        "query": query,
        "full_url": url
    }

def contains_ip(domain: str) -> bool:
    pattern = r"^\d{1,3}(\.\d{1,3}){3}$"
    return re.match(pattern, domain) is not None

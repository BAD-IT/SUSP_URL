import os
import re
from urllib.parse import urlparse

import requests

SUSPICIOUS_KEYWORDS = [
    "login", "signin", "verify", "verification", "secure", "update",
    "confirm", "account", "bank", "paypal", "password", "credential",
    "billing", "invoice", "payment", "wallet", "crypto", "urgent",
]


def _is_ip(host: str) -> bool:
    return re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", host) is not None


def _suspicious_tld(domain: str) -> bool:
    risky = {".tk", ".ml", ".ga", ".cf", ".top", ".xyz", ".club", ".online"}
    return any(domain.endswith(tld) for tld in risky)


def heuristic_score(url: str, redirects_to: str = "", page_count: int = 1) -> int:
    parsed = urlparse(url)
    host = parsed.netloc.lower()
    path = parsed.path.lower()
    score = 0

    if parsed.scheme == "http":
        score += 20

    if _is_ip(host):
        score += 30

    if ":" in host and not parsed.port:
        pass

    subdomain_count = len(host.split(".")) - 2 if "." in host else 0
    if subdomain_count > 2:
        score += 10

    if len(url) > 100:
        score += 10

    if "%" in url or "@" in url:
        score += 15

    if any(kw in url.lower() for kw in SUSPICIOUS_KEYWORDS):
        score += 15

    if _suspicious_tld(host):
        score += 15

    if redirects_to and get_domain(redirects_to) != get_domain(url):
        score += 15

    return min(100, max(0, score))


def get_domain(url: str) -> str:
    return urlparse(url).netloc.lower()


def _label(score: int) -> str:
    if score <= 30:
        return "Likely safe"
    if score <= 60:
        return "Neutral / unknown"
    if score <= 85:
        return "Suspicious"
    return "High risk"


def _summary(url: str, score: int, pages: int) -> str:
    label = _label(score)
    if score <= 30:
        return f"No obvious risk signals were found for {url} ({pages} page{'s' if pages != 1 else ''} checked)."
    if score <= 60:
        return f"Some unusual patterns were seen on {url}, but nothing clearly malicious ({pages} page{'s' if pages != 1 else ''} checked)."
    if score <= 85:
        return f"Several suspicious signals were detected on {url}; proceed with caution ({pages} page{'s' if pages != 1 else ''} checked)."
    return f"Multiple high-risk signals were detected on {url}; avoid entering credentials or downloading files ({pages} page{'s' if pages != 1 else ''} checked)."


def _virustotal_score(url: str) -> int:
    key = os.environ.get("VIRUSTOTAL_API_KEY")
    if not key:
        return 0
    try:
        headers = {"x-apikey": key}
        encoded = requests.utils.quote(url, safe="")
        resp = requests.get(
            f"https://www.virustotal.com/api/v3/urls/{encoded}",
            headers=headers,
            timeout=10,
        )
        if resp.status_code != 200:
            return 0
        stats = resp.json()["data"]["attributes"]["last_analysis_stats"]
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        return min(40, (malicious * 10) + (suspicious * 5))
    except Exception:
        return 0


def _urlscan_score(url: str) -> int:
    key = os.environ.get("URLSCAN_API_KEY")
    if not key:
        return 0
    try:
        headers = {"API-Key": key}
        resp = requests.post(
            "https://urlscan.io/api/v1/scan/",
            headers=headers,
            json={"url": url, "public": "on"},
            timeout=10,
        )
        if resp.status_code != 200:
            return 0
        return 0
    except Exception:
        return 0


def _abuseipdb_score(url: str) -> int:
    key = os.environ.get("ABUSEIPDB_API_KEY")
    if not key:
        return 0
    host = urlparse(url).netloc
    if not _is_ip(host):
        return 0
    try:
        headers = {"Key": key, "Accept": "application/json"}
        resp = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers=headers,
            params={"ipAddress": host, "maxAgeInDays": 90},
            timeout=10,
        )
        if resp.status_code != 200:
            return 0
        score = resp.json()["data"].get("abuseConfidenceScore", 0)
        return int(score / 2.5)
    except Exception:
        return 0


def calculate_score(url: str, pages: list[dict]) -> tuple[int, str, str]:
    redirects_to = ""
    if pages and len(pages) > 1:
        redirects_to = pages[-1]["url"]

    score = heuristic_score(url, redirects_to, len(pages))
    score = min(100, score + _virustotal_score(url) + _urlscan_score(url) + _abuseipdb_score(url))

    label = _label(score)
    summary = _summary(url, score, len(pages))
    return score, label, summary

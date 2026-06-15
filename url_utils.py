from urllib.parse import urlparse


def normalize_url(raw: str) -> str:
    raw = raw.strip()
    if not raw:
        raise ValueError("URL is required")
    if not raw.startswith(("http://", "https://")):
        raw = "https://" + raw
    parsed = urlparse(raw)
    if parsed.scheme not in ("http", "https"):
        raise ValueError("Only HTTP and HTTPS URLs are supported")
    if not parsed.netloc:
        raise ValueError("Invalid URL or domain")
    return f"{parsed.scheme}://{parsed.netloc}{parsed.path}" + (f"?{parsed.query}" if parsed.query else "")


def get_domain(url: str) -> str:
    return urlparse(url).netloc.lower()


def same_domain(url_a: str, url_b: str) -> bool:
    return get_domain(url_a) == get_domain(url_b)

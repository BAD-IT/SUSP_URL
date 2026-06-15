import json
import os
import re
import sys
from urllib.parse import urljoin, urlparse

from playwright.sync_api import sync_playwright, TimeoutError as PlaywrightTimeout


def safe_name(url: str) -> str:
    parsed = urlparse(url)
    base = f"{parsed.netloc}{parsed.path}".strip("/")
    if not base:
        base = "home"
    return re.sub(r"[^a-zA-Z0-9_-]", "_", base).strip("_")[:60]


def same_domain(url_a: str, url_b: str) -> bool:
    return urlparse(url_a).netloc.lower() == urlparse(url_b).netloc.lower()


def main():
    sid = os.environ["SESSION_ID"]
    start_url = os.environ["START_URL"]
    max_pages = int(os.environ.get("MAX_PAGES", "5"))
    out_dir = os.path.join(os.environ.get("OUTPUT_DIR", "/screenshots"), sid)
    os.makedirs(out_dir, exist_ok=True)

    visited = set()
    queue = [start_url]
    pages = []

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True, args=["--no-sandbox"])

        while queue and len(pages) < max_pages:
            url = queue.pop(0)
            if url in visited:
                continue
            visited.add(url)

            context = browser.new_context(
                viewport={"width": 1280, "height": 720},
                user_agent=(
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                    "AppleWebKit/537.36 (KHTML, like Gecko) "
                    "Chrome/125.0.0.0 Safari/537.36"
                ),
            )
            page = context.new_page()

            entry = {
                "url": url,
                "title": None,
                "filename": None,
                "error": None,
            }

            try:
                page.goto(url, wait_until="networkidle", timeout=20000)
                entry["title"] = page.title()
                filename = f"{len(pages) + 1:03d}_{safe_name(url)}.png"
                screenshot_path = os.path.join(out_dir, filename)
                page.screenshot(path=screenshot_path, full_page=True)
                entry["filename"] = filename

                # Extract same-domain links only from the first page to keep the scan bounded.
                if len(pages) == 0:
                    hrefs = page.eval_on_selector_all(
                        "a[href]", "elements => elements.map(e => e.href)"
                    )
                    for href in hrefs:
                        absolute = urljoin(url, href)
                        # Skip fragments and non-HTTP(S)
                        if not absolute.startswith(("http://", "https://")):
                            continue
                        if same_domain(absolute, start_url) and absolute not in visited:
                            # Remove fragment to reduce duplicates
                            parsed = urlparse(absolute)
                            normalized = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
                            if normalized not in visited and normalized not in queue:
                                queue.append(normalized)
            except PlaywrightTimeout:
                entry["error"] = "Timeout while loading page"
            except Exception as e:
                entry["error"] = str(e)
            finally:
                context.close()

            pages.append(entry)

        browser.close()

    meta = {
        "session_id": sid,
        "start_url": start_url,
        "pages": pages,
    }
    with open(os.path.join(out_dir, "meta.json"), "w") as f:
        json.dump(meta, f, indent=2)

    print(f"Scanner finished: {len(pages)} pages, output in {out_dir}")


if __name__ == "__main__":
    main()

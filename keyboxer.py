import os
import re
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Iterable, Set

import requests
from dotenv import load_dotenv
from lxml import etree

from check import keybox_check
from helpers import (
    CACHE_FILE,
    SAVE_DIR,
    hash_xml_file,
    log_error,
    log_info,
    print_section,
    print_summary,
)

SESSION = requests.Session()

load_dotenv()
GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")
if not GITHUB_TOKEN:
    raise ValueError("GITHUB_TOKEN is not set in the .env file")

SEARCH_QUERY = "<AndroidAttestation>+-repo:pperez39/google-keys"
SEARCH_URL = f"https://api.github.com/search/code?q={SEARCH_QUERY}"
RESULTS_PER_PAGE = 100

HEADERS = {
    "Authorization": f"token {GITHUB_TOKEN}",
    "Accept": "application/vnd.github.v3+json",
}


class RateLimitError(Exception):
    """Raised when the GitHub API reports an exceeded rate limit."""

    def __init__(self, message: str, resume_epoch: int) -> None:
        super().__init__(message)
        self.resume_epoch = resume_epoch

    def get_sleep_time(self) -> float:
        resume_at = datetime.fromtimestamp(self.resume_epoch, tz=timezone.utc)
        now = datetime.now(tz=timezone.utc)
        return max((resume_at - now).total_seconds(), 0.0)


@dataclass
class ScrapeStats:
    searched: int = 0
    malformed: int = 0
    added: int = 0
    cached: int = 0
    duplicates: int = 0


def load_cached_urls() -> Set[str]:
    if not CACHE_FILE.exists():
        return set()

    with CACHE_FILE.open("r", encoding="utf-8") as cache_file:
        return {line.strip() for line in cache_file if line.strip()}


def save_cached_urls(urls: Iterable[str]) -> None:
    deduped_urls = sorted(set(urls))
    with CACHE_FILE.open("w", encoding="utf-8") as cache_file:
        cache_file.writelines(f"{url}\n" for url in deduped_urls)


def fetch_file_content(url: str) -> bytes:
    response = SESSION.get(url)
    if response.status_code == 200:
        return response.content
    raise RuntimeError(f"Failed to download {url}")


def clean_item(context: str) -> str:
    """Removes comments from the XML content."""
    return re.sub(r"(?m)(#|//).*$", "", context).strip()


def process_item(
    item: dict, cached_urls: Set[str], stats: ScrapeStats, verbose: bool
) -> None:
    file_name = item["name"]
    if not file_name.lower().endswith(".xml"):
        return

    stats.searched += 1
    raw_url = (
        item["html_url"]
        .replace("github.com", "raw.githubusercontent.com")
        .replace("/blob/", "/")
    )
    if raw_url in cached_urls:
        stats.cached += 1
        return

    cached_urls.add(raw_url)
    file_content = fetch_file_content(raw_url)
    file_content = clean_item(file_content.decode("utf-8")).encode("utf-8")
    try:
        hashed_name = hash_xml_file(file_content)
    except etree.XMLSyntaxError:
        stats.malformed += 1
        if verbose:
            log_error(f"Malformed XML skipped from {raw_url}")
        return

    destination = SAVE_DIR / hashed_name
    if destination.exists():
        stats.duplicates += 1
        if verbose:
            log_info(f"Duplicate keybox skipped from {raw_url}")
        return

    try:
        keybox_check(file_content)
    except ValueError:
        stats.malformed += 1
        if verbose:
            log_error(f"Invalid keybox skipped from {raw_url}")
        return

    if file_content:
        destination.write_bytes(file_content)
        stats.added += 1
        if verbose:
            log_info(f"Stored new keybox from {raw_url}")


def fetch_and_process_results(
    page: int, cached_urls: Set[str], stats: ScrapeStats, verbose: bool
) -> bool:
    params = {"per_page": RESULTS_PER_PAGE, "page": page}
    response = SESSION.get(SEARCH_URL, headers=HEADERS, params=params)
    if response.status_code != 200:
        log_error(f"Failed to retrieve search results: {response.status_code}")
        log_error(f"response: {response.text}")
        if response.status_code == 403 and response.headers.get("X-RateLimit-Reset"):
            reset_time = int(response.headers["X-RateLimit-Reset"])
            raise RateLimitError(
                "Rate limit exceeded. Please try again later.", resume_epoch=reset_time
            )
        raise RuntimeError("GitHub search failed")

    search_results = response.json()
    for item in search_results.get("items", []):
        process_item(item, cached_urls, stats, verbose)

    return bool(search_results.get("items"))


def scrape_keyboxes(*, verbose: bool = True) -> ScrapeStats:
    cached_urls = load_cached_urls()
    stats = ScrapeStats()
    page = 1
    has_more_results = True

    while has_more_results:
        try:
            has_more_results = fetch_and_process_results(
                page, cached_urls, stats, verbose
            )
            page += 1
        except RateLimitError as error:
            sleep_for = error.get_sleep_time()
            if verbose:
                log_info(f"Rate limit exceeded. Retrying after {sleep_for:.0f}s...")
            time.sleep(sleep_for)
            if verbose:
                log_info("Retrying GitHub search...")
        except RuntimeError:
            log_error("Error during fetching results, saving cache and checking files")
            break

    save_cached_urls(cached_urls)
    return stats


def main() -> None:
    print_section("GitHub keybox scrape")
    stats = scrape_keyboxes()
    print_summary(
        "Scrape Summary",
        [
            ("Examined", str(stats.searched)),
            ("Added", str(stats.added)),
            ("Malformed", str(stats.malformed)),
            ("Duplicates", str(stats.duplicates)),
            ("Cached Hits", str(stats.cached)),
        ],
    )


if __name__ == "__main__":
    main()

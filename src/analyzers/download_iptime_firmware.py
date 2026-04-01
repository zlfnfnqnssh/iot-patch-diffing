"""
Download ipTIME firmware versions per model into data/firmware/iptime/.

The script:
1. Reads the current firmware announcement page and extracts the model list.
2. Crawls ipTIME's download board for historical router firmware announcement posts.
3. Collects direct download URLs for the models listed on the current page.
4. Downloads files into:

    data/firmware/iptime/<MODEL>/ <MODEL>_v<version>.bin

It also writes a manifest JSON with source post URLs and original download URLs.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import time
from collections import deque
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Iterable
from urllib.parse import parse_qs, urlencode, urljoin, urlparse, urlunparse

import requests
from bs4 import BeautifulSoup
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry


PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
DEFAULT_DOWNLOAD_ROOT = PROJECT_ROOT / "data" / "firmware" / "iptime"
DEFAULT_BOARD_URL = "https://iptime.com/iptime/?page_id=126"
DEFAULT_CURRENT_POST_URL = (
    "https://iptime.com/iptime/?page_id=126&dfsid=19&dftid=907&dffid=1&uid=26833&mod=document"
)
DEFAULT_TIMEOUT = (10, 60)

ROUTER_POST_TITLE_RE = re.compile(
    r"\[펌웨어\]\s*ipTIME(?:\s+유무선)?\s+공유기(?:\s+\d+종)?\s+펌웨어\s+(\d+\.\d+\.\d+)",
    re.IGNORECASE,
)
DOWNLOAD_LINK_RE = re.compile(
    r"^\[?\s*(.+?)\s*(\d+\.\d+\.\d+)\s+다운로드\s*\]?$",
    re.IGNORECASE,
)
SAFE_NAME_RE = re.compile(r"[^0-9A-Za-z.+-]+")


@dataclass(frozen=True)
class DownloadEntry:
    model_name: str
    safe_model_name: str
    version: str
    download_url: str
    post_url: str
    post_title: str
    filename: str


def log(message: str) -> None:
    print(message, flush=True)


def format_bytes(size: int) -> str:
    units = ["B", "KB", "MB", "GB"]
    value = float(size)
    unit = units[0]
    for unit in units:
        if value < 1024 or unit == units[-1]:
            break
        value /= 1024
    return f"{value:.1f}{unit}"


def build_session() -> requests.Session:
    session = requests.Session()
    retries = Retry(
        total=5,
        connect=5,
        read=5,
        backoff_factor=1.5,
        status_forcelist=[429, 500, 502, 503, 504],
        allowed_methods=["GET", "HEAD"],
    )
    adapter = HTTPAdapter(max_retries=retries)
    session.mount("https://", adapter)
    session.mount("http://", adapter)
    session.headers.update(
        {
            "User-Agent": (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/131.0.0.0 Safari/537.36"
            )
        }
    )
    return session


def normalize_url(url: str) -> str:
    parsed = urlparse(url)
    query = parse_qs(parsed.query, keep_blank_values=True)
    normalized_items: list[tuple[str, str]] = []
    for key in sorted(query):
        for value in sorted(query[key]):
            normalized_items.append((key, value))
    normalized_query = urlencode(normalized_items)
    return urlunparse(
        (
            parsed.scheme,
            parsed.netloc,
            parsed.path,
            parsed.params,
            normalized_query,
            "",
        )
    )


def generate_candidate_urls(url: str) -> list[str]:
    parsed = urlparse(url)
    host = parsed.netloc
    hosts = [host]
    if host.startswith("www."):
        hosts.append(host[4:])
    else:
        hosts.append(f"www.{host}")

    schemes = [parsed.scheme]
    if parsed.scheme == "https":
        schemes.append("http")
    elif parsed.scheme == "http":
        schemes.append("https")

    candidates: list[str] = []
    seen: set[str] = set()
    for scheme in schemes:
        for candidate_host in hosts:
            candidate = urlunparse(
                (scheme, candidate_host, parsed.path, parsed.params, parsed.query, parsed.fragment)
            )
            if candidate not in seen:
                seen.add(candidate)
                candidates.append(candidate)
    return candidates


def request_with_fallbacks(
    session: requests.Session,
    url: str,
    *,
    label: str,
    stream: bool = False,
    timeout: tuple[int, int] = DEFAULT_TIMEOUT,
) -> requests.Response:
    last_exc: Exception | None = None
    candidates = generate_candidate_urls(url)

    for index, candidate in enumerate(candidates, 1):
        log(f"[TRY] {label} ({index}/{len(candidates)}): {candidate}")
        try:
            response = session.get(candidate, timeout=timeout, stream=stream)
            response.raise_for_status()
            return response
        except requests.RequestException as exc:
            last_exc = exc
            log(f"[TRY FAIL] {candidate} ({exc})")

    if last_exc is None:
        raise RuntimeError(f"request failed without exception: {url}")
    raise last_exc


def fetch_soup(session: requests.Session, url: str, label: str | None = None) -> BeautifulSoup:
    started = time.time()
    if label:
        log(f"[FETCH] {label}: {url}")
    else:
        log(f"[FETCH] {url}")

    response = request_with_fallbacks(
        session,
        url,
        label=label or "html fetch",
        stream=False,
        timeout=DEFAULT_TIMEOUT,
    )
    if not response.encoding:
        response.encoding = response.apparent_encoding or "utf-8"
    elapsed = time.time() - started
    log(
        f"[FETCH OK] {response.status_code} {url} "
        f"({len(response.text):,} chars, {elapsed:.1f}s)"
    )
    return BeautifulSoup(response.text, "html.parser")


def safe_model_name(model_name: str) -> str:
    safe = model_name.replace("/", "_").replace("\\", "_")
    safe = SAFE_NAME_RE.sub("_", safe).strip("._")
    return safe or "unknown_model"


def file_extension_from_url(url: str) -> str:
    suffix = Path(urlparse(url).path).suffix.lower()
    return suffix or ".bin"


def parse_download_entries(soup: BeautifulSoup, post_url: str, post_title: str) -> list[DownloadEntry]:
    entries: list[DownloadEntry] = []
    seen: set[tuple[str, str]] = set()

    for anchor in soup.find_all("a", href=True):
        href = urljoin(post_url, anchor["href"])
        if "download.iptime.co.kr" not in href.lower():
            continue

        text = anchor.get_text(" ", strip=True)
        match = DOWNLOAD_LINK_RE.match(text)
        if not match:
            continue

        model_name = " ".join(match.group(1).split())
        version = match.group(2)
        key = (model_name, version)
        if key in seen:
            continue
        seen.add(key)

        safe_name = safe_model_name(model_name)
        extension = file_extension_from_url(href)
        filename = f"{safe_name}_v{version}{extension}"

        entries.append(
            DownloadEntry(
                model_name=model_name,
                safe_model_name=safe_name,
                version=version,
                download_url=href,
                post_url=post_url,
                post_title=post_title,
                filename=filename,
            )
        )

    return entries


def extract_target_models(session: requests.Session, post_url: str) -> dict[str, DownloadEntry]:
    soup = fetch_soup(session, post_url, label="current firmware post")
    title = soup.title.get_text(" ", strip=True) if soup.title else "current post"
    entries = parse_download_entries(soup, post_url, title)
    if not entries:
        raise RuntimeError(f"no download entries found on current post: {post_url}")
    log(f"[INFO] current post models parsed: {len(entries)}")
    return {entry.model_name: entry for entry in entries}


def iter_candidate_list_links(soup: BeautifulSoup, base_url: str) -> Iterable[str]:
    for anchor in soup.find_all("a", href=True):
        href = urljoin(base_url, anchor["href"])
        parsed = urlparse(href)
        if parsed.netloc.lower() != "iptime.com":
            continue
        query = parse_qs(parsed.query)
        if query.get("page_id", [None])[0] != "126":
            continue
        if "uid" in query:
            continue

        text = anchor.get_text(" ", strip=True)
        href_lower = href.lower()
        if (
            text.isdigit()
            or text in {"다음", "이전", ">", "<"}
            or "page=" in href_lower
            or "pagenum=" in href_lower
            or "mod=list" in href_lower
        ):
            yield normalize_url(href)


def extract_post_links(soup: BeautifulSoup, base_url: str) -> dict[str, str]:
    posts: dict[str, str] = {}
    for anchor in soup.find_all("a", href=True):
        href = urljoin(base_url, anchor["href"])
        parsed = urlparse(href)
        query = parse_qs(parsed.query)
        if parsed.netloc.lower() != "iptime.com":
            continue
        if query.get("page_id", [None])[0] != "126":
            continue
        if "uid" not in query:
            continue

        text = " ".join(anchor.get_text(" ", strip=True).split())
        match = ROUTER_POST_TITLE_RE.search(text)
        if not match:
            continue
        posts[normalize_url(href)] = text
    return posts


def crawl_router_post_urls(
    session: requests.Session,
    board_url: str,
    max_list_pages: int,
) -> dict[str, str]:
    visited_pages: set[str] = set()
    queued_pages: set[str] = {normalize_url(board_url)}
    page_queue: deque[str] = deque([board_url])
    post_urls: dict[str, str] = {}

    log(f"[CRAWL] start board crawl: {board_url}")

    while page_queue and len(visited_pages) < max_list_pages:
        page_url = page_queue.popleft()
        normalized_page_url = normalize_url(page_url)
        if normalized_page_url in visited_pages:
            continue
        visited_pages.add(normalized_page_url)

        soup = fetch_soup(
            session,
            page_url,
            label=f"download board page {len(visited_pages)}/{max_list_pages}",
        )
        before_posts = len(post_urls)
        post_urls.update(extract_post_links(soup, page_url))
        new_posts = len(post_urls) - before_posts
        new_pages = 0

        for next_page in iter_candidate_list_links(soup, page_url):
            if next_page in visited_pages or next_page in queued_pages:
                continue
            queued_pages.add(next_page)
            page_queue.append(next_page)
            new_pages += 1

        log(
            f"[CRAWL] page done: posts +{new_posts}, total posts {len(post_urls)}, "
            f"queued pages +{new_pages}, remaining queue {len(page_queue)}"
        )

    return post_urls


def collect_history(
    session: requests.Session,
    target_models: dict[str, DownloadEntry],
    board_url: str,
    max_list_pages: int,
    max_posts: int | None,
) -> dict[str, dict[str, DownloadEntry]]:
    target_model_names = set(target_models)
    results: dict[str, dict[str, DownloadEntry]] = {}
    for model_name, entry in target_models.items():
        results[model_name] = {entry.version: entry}

    post_urls = crawl_router_post_urls(session, board_url, max_list_pages=max_list_pages)
    log(f"[CRAWL] router firmware posts found: {len(post_urls)}")
    ordered_posts = sorted(post_urls.items(), key=lambda item: item[0], reverse=True)
    if max_posts is not None:
        ordered_posts = ordered_posts[:max_posts]
        log(f"[CRAWL] limiting posts to first {len(ordered_posts)} due to --max-posts")

    for index, (post_url, post_title) in enumerate(ordered_posts, 1):
        log(f"[SCAN] ({index}/{len(ordered_posts)}) {post_title}")
        try:
            soup = fetch_soup(session, post_url, label=f"firmware post {index}/{len(ordered_posts)}")
        except Exception as exc:
            log(f"  [WARN] failed to fetch post: {post_url} ({exc})")
            continue

        matched_versions = 0
        for entry in parse_download_entries(soup, post_url, post_title):
            if entry.model_name not in target_model_names:
                continue
            versions = results.setdefault(entry.model_name, {})
            if entry.version not in versions:
                versions[entry.version] = entry
                matched_versions += 1

        if matched_versions:
            log(f"  [MATCH] target versions added from post: {matched_versions}")
        else:
            log("  [MATCH] no new target versions in this post")

    return results


def download_file(session: requests.Session, url: str, destination: Path) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    started = time.time()
    log(f"[DOWNLOAD] {url}")
    with request_with_fallbacks(
        session,
        url,
        label=f"download {destination.name}",
        stream=True,
        timeout=(15, 120),
    ) as response:
        total_size = int(response.headers.get("Content-Length", "0") or "0")
        if total_size > 0:
            log(f"  [SIZE] {destination.name}: {format_bytes(total_size)}")

        downloaded = 0
        last_reported_mb = -1
        with open(destination, "wb") as output:
            for chunk in response.iter_content(chunk_size=1024 * 1024):
                if chunk:
                    output.write(chunk)
                    downloaded += len(chunk)
                    reported_mb = downloaded // (5 * 1024 * 1024)
                    if reported_mb > last_reported_mb:
                        last_reported_mb = reported_mb
                        if total_size > 0:
                            percent = downloaded * 100 / total_size
                            log(
                                f"  [PROGRESS] {destination.name}: "
                                f"{format_bytes(downloaded)} / {format_bytes(total_size)} ({percent:.1f}%)"
                            )
                        else:
                            log(f"  [PROGRESS] {destination.name}: {format_bytes(downloaded)}")

    elapsed = time.time() - started
    final_size = destination.stat().st_size if destination.exists() else 0
    log(f"[DOWNLOAD OK] {destination} ({format_bytes(final_size)}, {elapsed:.1f}s)")


def write_manifest(download_root: Path, collected: dict[str, dict[str, DownloadEntry]]) -> Path:
    download_root.mkdir(parents=True, exist_ok=True)
    manifest_path = download_root / "manifest.json"
    payload: dict[str, list[dict[str, str]]] = {}

    for model_name, versions in sorted(collected.items()):
        ordered_versions = sorted(versions.values(), key=lambda item: item.version)
        payload[model_name] = [asdict(entry) for entry in ordered_versions]

    manifest_path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
    return manifest_path


def main() -> None:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(line_buffering=True)

    parser = argparse.ArgumentParser(description="Download ipTIME firmware history by model.")
    parser.add_argument(
        "--current-post-url",
        default=DEFAULT_CURRENT_POST_URL,
        help="current ipTIME firmware announcement URL that defines the target model set",
    )
    parser.add_argument(
        "--board-url",
        default=DEFAULT_BOARD_URL,
        help="ipTIME download board URL to crawl for historical router firmware posts",
    )
    parser.add_argument(
        "--download-root",
        default=str(DEFAULT_DOWNLOAD_ROOT),
        help="root directory where model folders will be created",
    )
    parser.add_argument(
        "--models",
        nargs="*",
        default=None,
        help="optional subset of model names to download",
    )
    parser.add_argument(
        "--max-list-pages",
        type=int,
        default=200,
        help="maximum number of download-board list pages to crawl",
    )
    parser.add_argument(
        "--max-posts",
        type=int,
        default=None,
        help="optional limit on the number of historical posts to inspect",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="discover and print planned downloads without saving files",
    )
    args = parser.parse_args()

    download_root = Path(args.download_root)
    session = build_session()
    log("[START] ipTIME firmware downloader")
    log(f"[START] current post: {args.current_post_url}")
    log(f"[START] board url: {args.board_url}")
    log(f"[START] download root: {download_root}")
    if args.models:
        log(f"[START] requested models: {', '.join(args.models)}")
    if args.dry_run:
        log("[START] dry-run mode enabled")

    try:
        current_models = extract_target_models(session, args.current_post_url)
    except Exception as exc:
        log(f"[ERROR] failed to parse current post: {exc}")
        sys.exit(1)

    if args.models:
        selected_models = {name for name in args.models}
        current_models = {name: entry for name, entry in current_models.items() if name in selected_models}
        if not current_models:
            log("[ERROR] no requested models matched the current post")
            sys.exit(1)

    log(f"[INFO] target models from current post: {len(current_models)}")
    for model_name in sorted(current_models):
        log(f"  - {model_name}")

    try:
        collected = collect_history(
            session,
            current_models,
            board_url=args.board_url,
            max_list_pages=args.max_list_pages,
            max_posts=args.max_posts,
        )
    except Exception as exc:
        log(f"[ERROR] history collection failed: {exc}")
        sys.exit(1)

    planned_downloads: list[tuple[DownloadEntry, Path]] = []
    for model_name, versions in sorted(collected.items()):
        sample_entry = next(iter(versions.values()))
        model_dir = download_root / sample_entry.safe_model_name
        ordered_entries = sorted(versions.values(), key=lambda entry: tuple(int(part) for part in entry.version.split(".")))

        log(f"\n[MODEL] {model_name} -> {model_dir}")
        log(f"  versions found: {len(ordered_entries)}")

        for entry in ordered_entries:
            destination = model_dir / entry.filename
            planned_downloads.append((entry, destination))
            log(f"  - {entry.version} -> {destination.name}")

    manifest_path = write_manifest(download_root, collected)
    log(f"\n[INFO] manifest: {manifest_path}")

    if args.dry_run:
        log("[DRY-RUN] downloads were not started")
        return

    downloaded = 0
    skipped = 0

    for entry, destination in planned_downloads:
        if destination.exists() and destination.stat().st_size > 0:
            log(f"[SKIP] {destination}")
            skipped += 1
            continue

        log(f"[GET] {entry.model_name} {entry.version}")
        try:
            download_file(session, entry.download_url, destination)
        except Exception as exc:
            log(f"  [WARN] download failed: {entry.download_url} ({exc})")
            continue
        downloaded += 1

    log("\n[DONE]")
    log(f"  downloaded: {downloaded}")
    log(f"  skipped:    {skipped}")
    log(f"  root:       {download_root}")


if __name__ == "__main__":
    main()

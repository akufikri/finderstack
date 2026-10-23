#!/usr/bin/env python3
"""Detect publicly visible website technologies. No Wappalyzer, no API key.

Fingerprints live in fingerprints.json next to this file:

    {"name": "...", "category": "...",
     "headers" | "cookies" | "body" | "scripts" | "url": "regex" or ["regex", ...]}

Regexes are searched case-insensitively and multiline. The first capture group,
when present, is reported as the version.
"""

import argparse
import http.cookiejar
import json
import re
import sys
from pathlib import Path
from urllib.parse import urlparse
from urllib.request import HTTPCookieProcessor, Request, build_opener

FINGERPRINTS = Path(__file__).with_name("fingerprints.json")
USER_AGENT = (
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36"
)
FIELDS = ("url", "headers", "cookies", "body", "scripts")
MAX_BODY = 2_000_000  # bytes; shortcut: document only, upgrade if SPA bundles matter


def normalize_url(domain: str) -> str:
    """Add HTTPS if the user entered only a domain."""
    value = domain.strip()
    if not value.startswith(("http://", "https://")):
        value = "https://" + value

    parsed = urlparse(value)
    if not parsed.hostname:
        raise ValueError(f"Invalid domain or URL: {domain}")

    return value


def build_page(url: str, headers: str, cookies: str, body: str) -> dict:
    """Flatten one HTTP response into the searchable fields used by detect()."""
    assets = sorted(
        set(
            re.findall(
                r"""(?:<script[^>]*src|<link[^>]*href)=["']([^"']+)""", body, re.I
            )
        )
    )
    return {
        "url": url,
        "headers": headers,
        "cookies": cookies,
        "body": body,
        "assets": assets,
        "scripts": "\n".join(
            sorted(set(re.findall(r"""<script[^>]+src=["']([^"']+)""", body, re.I)))
        ),
    }


def fetch(url: str) -> dict:
    """Download the main document and flatten it into searchable fields."""
    jar = http.cookiejar.CookieJar()
    opener = build_opener(HTTPCookieProcessor(jar))
    request = Request(
        url, headers={"User-Agent": USER_AGENT, "Accept-Language": "en"}
    )
    with opener.open(request, timeout=20) as response:
        raw = response.read(MAX_BODY)
        charset = response.headers.get_content_charset() or "utf-8"
        try:
            body = raw.decode(charset, "replace")
        except LookupError:
            body = raw.decode("utf-8", "replace")
        final_url = response.geturl()
        headers = "\n".join(f"{key}: {value}" for key, value in response.headers.items())
        cookies = "\n".join(f"{cookie.name}={cookie.value}" for cookie in jar)

    return build_page(final_url, headers, cookies, body)


def detect(page: dict, fingerprints: list[dict]) -> list[dict]:
    found: dict[str, dict] = {}
    for fingerprint in fingerprints:
        versions: list[str] = []
        evidence: list[str] = []
        for field in FIELDS:
            patterns = fingerprint.get(field)
            if not patterns:
                continue
            if isinstance(patterns, str):
                patterns = [patterns]
            haystack = page.get(field, "")
            for pattern in patterns:
                for match in re.finditer(pattern, haystack, re.I | re.M):
                    if match.groups() and match.group(1):
                        versions.append(match.group(1))
                    note = f"{field}: {match.group(0)[:80]}"
                    if len(evidence) < 3 and note not in evidence:
                        evidence.append(note)
        if evidence:
            entry = found.setdefault(
                fingerprint["name"],
                {
                    "name": fingerprint["name"],
                    "category": fingerprint.get("category", "Uncategorized"),
                    "versions": [],
                    "evidence": [],
                },
            )
            entry["versions"].extend(v for v in versions if v not in entry["versions"])
            entry["evidence"].extend(e for e in evidence if e not in entry["evidence"])

    return sorted(found.values(), key=lambda item: item["name"].lower())


def load_fingerprints(path: Path = FINGERPRINTS) -> list[dict]:
    with path.open(encoding="utf-8") as handle:
        return json.load(handle)


def main():
    parser = argparse.ArgumentParser(
        description="Detect publicly visible website technologies and versions."
    )
    parser.add_argument("domain", help="Domain or URL, e.g. example.com")
    args = parser.parse_args()

    try:
        page = fetch(normalize_url(args.domain))
        result = {"url": page["url"], "technologies": detect(page, load_fingerprints())}
        print(json.dumps(result, indent=2))
    except (ValueError, OSError) as error:
        sys.exit(f"Scan failed: {error}")


if __name__ == "__main__":
    main()

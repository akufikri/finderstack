#!/usr/bin/env python3
"""finderstack: recon + technology fingerprinting.

Sources: whois, dig, crt.sh, subfinder; ports: nmap; pages and TLS: curl, openssl.
Detection: local fingerprints from tech_stack.detect.

JSON on stdout, progress on stderr.
"""

import argparse
import json
import re
import shutil
import socket
import subprocess
import sys
import tempfile
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from urllib.parse import urlparse

# Works from a symlink on PATH: keep sibling modules importable.
sys.path.insert(0, str(Path(__file__).resolve().parent))

import tech_stack

PORTS = (80, 443, 8080, 8443)
BANNER = r"""
 _____ _           _           ____  _             _
|  ___(_)_ __   __| | ___ _ __/ ___|| |_ __ _  ___| | __
| |_  | | '_ \ / _` |/ _ \ '__\___ \| __/ _` |/ __| |/ /
|  _| | | | | | (_| |  __/ |   ___) | || (_| | (__|   <
|_|   |_|_| |_|\__,_|\___|_|  |____/ \__\__,_|\___|_|\_\
"""
WORKERS = 8
CURL_TIMEOUT = 20
NMAP_TIMEOUT = 900
SUBFINDER_TIMEOUT = 300
WHOIS_TIMEOUT = 30


def run(command: list[str], timeout: int) -> subprocess.CompletedProcess:
    try:
        return subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout,
            stdin=subprocess.DEVNULL,
        )
    except subprocess.TimeoutExpired as error:
        raise RuntimeError(f"{command[0]} timed out after {timeout}s") from error


def list_subdomains(domain: str) -> list[str]:
    if not shutil.which("subfinder"):
        raise RuntimeError("subfinder not found in PATH")
    try:
        proc = run(
            ["subfinder", "-d", domain, "-silent", "-max-time", "3"],
            SUBFINDER_TIMEOUT,
        )
    except RuntimeError as error:
        print(f"[!] {error}; continuing with {domain} only", file=sys.stderr)
        return []
    if proc.returncode != 0:
        print(
            f"[!] subfinder failed: {proc.stderr.strip()[:300]}; continuing with {domain} only",
            file=sys.stderr,
        )
        return []
    return sorted({line.strip().lower() for line in proc.stdout.splitlines() if line.strip()})


def crt_sh_subdomains(domain: str) -> list[str]:
    """Certificate transparency names from crt.sh; best effort."""
    if not shutil.which("curl"):
        return []
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    try:
        proc = run(["curl", "-sS", "--max-time", "60", "-A", tech_stack.USER_AGENT, url], 70)
        entries = json.loads(proc.stdout)
    except (RuntimeError, json.JSONDecodeError):
        print("[!] crt.sh unavailable; skipping certificate transparency", file=sys.stderr)
        return []
    names = set()
    for entry in entries:
        for name in str(entry.get("name_value", "")).splitlines():
            name = name.strip().lower().lstrip("*.")
            if name == domain or name.endswith("." + domain):
                names.add(name)
    return sorted(names)


def parse_whois(text: str) -> dict:
    fields: dict[str, str] = {}
    nameservers: set[str] = set()
    status: set[str] = set()
    for line in text.splitlines():
        key, separator, value = line.partition(":")
        if not separator:
            continue
        key = key.strip().lower()
        value = value.strip()
        if not value:
            continue
        if key == "name server":
            nameservers.add(value.lower())
        elif key == "domain status":
            status.add(value)
        fields[key] = value

    def pick(*keys: str) -> str | None:
        return next((fields[key] for key in keys if key in fields), None)

    return {
        "registrar": pick("registrar"),
        "created": pick("creation date", "created"),
        "expires": pick("registry expiry date", "expiry date", "paid-till"),
        "updated": pick("updated date", "changed"),
        "status": sorted(status),
        "name_servers": sorted(nameservers),
        "dnssec": pick("dnssec"),
        "abuse_email": pick("registrar abuse contact email"),
    }


def whois_lookup(domain: str) -> dict | None:
    if not shutil.which("whois"):
        return None
    try:
        proc = run(["whois", domain], WHOIS_TIMEOUT)
    except RuntimeError as error:
        print(f"[!] {error}", file=sys.stderr)
        return None
    return parse_whois(proc.stdout) if proc.returncode == 0 else None


def dns_records(domain: str) -> dict:
    if not shutil.which("dig"):
        return {}
    records = {}
    for record_type, key in (
        ("A", "a"),
        ("AAAA", "aaaa"),
        ("MX", "mx"),
        ("NS", "ns"),
        ("TXT", "txt"),
    ):
        try:
            proc = run(["dig", "+short", domain, record_type], 15)
        except RuntimeError:
            continue
        values = [
            line.strip().strip('"') for line in proc.stdout.splitlines() if line.strip()
        ]
        records[key] = sorted(values)
    return records


def resolve(hostname: str) -> list[str]:
    try:
        infos = socket.getaddrinfo(hostname, None, socket.AF_INET)
    except socket.gaierror:
        return []
    return sorted({info[4][0] for info in infos})


def parse_nmap_xml(xml_text: str) -> dict[str, list[dict]]:
    """Map IPv4 address -> open ports with service, product and version."""
    import xml.etree.ElementTree as ET

    result: dict[str, list[dict]] = {}
    for host in ET.fromstring(xml_text).findall("host"):
        ip = next(
            (
                address.get("addr")
                for address in host.findall("address")
                if address.get("addrtype") == "ipv4"
            ),
            None,
        )
        if not ip:
            continue
        ports = []
        for port in host.findall("./ports/port"):
            state = port.find("state")
            if state is None or state.get("state") != "open":
                continue
            service = port.find("service")
            entry = {
                "port": int(port.get("portid")),
                "service": (service.get("name") if service is not None else "") or "",
            }
            if service is not None:
                if service.get("product"):
                    entry["product"] = service.get("product")
                if service.get("version"):
                    entry["version"] = service.get("version")
            ports.append(entry)
        result[ip] = sorted(ports, key=lambda item: item["port"])
    return result


def scan_ports(ips: list[str]) -> dict[str, list[dict]]:
    if not shutil.which("nmap"):
        raise RuntimeError("nmap not found in PATH")
    ports = ",".join(str(port) for port in PORTS)
    proc = run(
        [
            "nmap", "-Pn", "-T4", "--open", "--version-light", "-sV",
            "-p", ports, "-oX", "-", *ips,
        ],
        NMAP_TIMEOUT,
    )
    if proc.returncode != 0:
        raise RuntimeError(f"nmap failed: {proc.stderr.strip()[:300]}")
    return parse_nmap_xml(proc.stdout)


def build_targets(
    hosts: list[str], resolved: dict[str, list[str]], open_ports: dict[str, list[dict]]
) -> list[dict]:
    """One target per hostname, with all its IPs and the union of their ports."""
    targets = []
    for host in hosts:
        ports: dict[int, dict] = {}
        ips = resolved.get(host, [])
        for ip in ips:
            for port in open_ports.get(ip, []):
                ports[port["port"]] = port
        targets.append(
            {"host": host, "ips": ips, "ports": [ports[key] for key in sorted(ports)]}
        )
    return targets


def parse_curl_output(stdout: str) -> tuple[str, int, int, str, str]:
    """Split curl -D - -w output into (final_url, status, redirects, headers, cookies)."""
    text, separator, meta = stdout.rpartition("\n@@META ")
    if not separator:
        raise ValueError("curl output missing metadata marker")
    final_url, _, rest = meta.strip().partition(" ")
    status, _, redirects = rest.partition(" ")
    lines = [
        line
        for line in text.splitlines()
        if ":" in line and not line.upper().startswith("HTTP/")
    ]
    cookies = [line for line in lines if line.lower().startswith("set-cookie:")]
    return final_url, int(status or 0), int(redirects or 0), "\n".join(lines), "\n".join(cookies)


def curl_get(url: str, limit: int) -> tuple[str, int, int, str, str, bytes] | None:
    """Curl one URL; returns (final_url, status, redirects, headers, cookies, body)."""
    if not shutil.which("curl"):
        raise RuntimeError("curl not found in PATH")
    with tempfile.NamedTemporaryFile() as body_file:
        proc = run(
            [
                "curl", "-sS", "-L", "--compressed",
                "--max-time", str(CURL_TIMEOUT),
                "-A", tech_stack.USER_AGENT,
                "-D", "-", "-o", body_file.name,
                "-w", "\n@@META %{url_effective} %{http_code} %{num_redirects}\n",
                url,
            ],
            CURL_TIMEOUT + 10,
        )
        if proc.returncode != 0:
            return None
        body_file.seek(0)
        raw = body_file.read(limit)

    final_url, status, redirects, headers, cookies = parse_curl_output(proc.stdout)
    if not status:
        return None
    return final_url, status, redirects, headers, cookies, raw


def decode_body(headers: str, raw: bytes) -> str:
    match = re.search(r"content-type:[^\n]*charset=([\w.-]+)", headers, re.I)
    charset = match.group(1) if match else "utf-8"
    try:
        return raw.decode(charset, "replace")
    except LookupError:
        return raw.decode("utf-8", "replace")


def fetch(url: str) -> dict | None:
    """Fetch one URL with curl and return a detect()-ready page."""
    got = curl_get(url, tech_stack.MAX_BODY)
    if not got:
        return None
    final_url, status, redirects, headers, cookies, raw = got
    body = decode_body(headers, raw)

    page = tech_stack.build_page(final_url, headers, cookies, body)
    page["status"] = status
    page["redirects"] = redirects
    return page


def fetch_text(url: str, limit: int = 262_144) -> str | None:
    """Fetch one asset and return its text; None when unreachable or an error status."""
    got = curl_get(url, limit)
    if not got:
        return None
    _, status, _, headers, _, raw = got
    return decode_body(headers, raw) if status < 400 else None


def parse_tls_output(text: str) -> dict:
    """Parse openssl x509 -subject -issuer -enddate -ext subjectAltName output."""
    info: dict[str, object] = {}
    for key, pattern in (
        ("subject", r"^subject=(.*)$"),
        ("issuer", r"^issuer=(.*)$"),
        ("not_after", r"^notAfter=(.*)$"),
    ):
        match = re.search(pattern, text, re.M)
        if match:
            info[key] = match.group(1).strip()
    san = sorted({name.strip() for name in re.findall(r"DNS:([^,\n]+)", text)})
    if san:
        info["san"] = san
    return info


def tls_info(host: str) -> dict | None:
    if not shutil.which("openssl"):
        return None
    try:
        proc = run(
            ["openssl", "s_client", "-servername", host, "-connect", f"{host}:443"],
            15,
        )
    except RuntimeError:
        return None
    block = re.search(
        r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", proc.stdout, re.S
    )
    if not block:
        return None
    decoded = subprocess.run(
        [
            "openssl", "x509", "-noout",
            "-subject", "-issuer", "-enddate", "-ext", "subjectAltName",
        ],
        input=block.group(0),
        capture_output=True,
        text=True,
        timeout=15,
    )
    return parse_tls_output(decoded.stdout) or None


VERSION_ASSETS = {
    # technology -> (keyword in asset URL, version regex in asset content)
    "jQuery": (r"jquery", r"jQuery v?([\d.]+)"),
    "Bootstrap": (r"bootstrap", r"Bootstrap\s+v?([\d.]+)"),
    "Font Awesome": (r"font-?awesome", r"Font Awesome (?:Free )?([\d.]+)"),
    "Vue.js": (r"vue", r"Vue\.js v?([\d.]+)"),
}

# technology -> [(same-origin path, version regex)]
VERSION_PROBES = {
    "Joomla": [
        (
            "/administrator/manifests/files/joomla.xml",
            r"<version>\s*([\d.]+)\s*</version>",
        )
    ],
}


def enrich_versions(page: dict, technologies: list[dict]) -> list[dict]:
    """Fill missing versions from same-origin assets and known version endpoints."""
    if not technologies:
        return technologies
    base = urlparse(page["url"])
    origin = f"{base.scheme}://{base.netloc}"
    cache: dict[str, str] = {}

    def asset_text(url: str) -> str:
        if url not in cache:
            cache[url] = fetch_text(url) or ""
        return cache[url]

    for tech in technologies:
        if tech["versions"]:
            continue
        spec = VERSION_ASSETS.get(tech["name"])
        if spec:
            keyword, pattern = spec
            candidates = [
                asset
                for asset in page.get("assets", [])
                if re.search(keyword, asset, re.I)
            ]
            # Shortest basename first: jquery.min.js beats jquery.magnific-popup.min.js.
            candidates.sort(key=lambda asset: len(urlparse(asset).path.rsplit("/", 1)[-1]))
            for asset in candidates[:3]:
                url = asset if asset.startswith("http") else origin + "/" + asset.lstrip("/")
                if urlparse(url).netloc != base.netloc:
                    continue
                match = re.search(pattern, asset_text(url), re.I)
                if match:
                    tech["versions"].append(match.group(1))
                    tech["evidence"].append(
                        f"asset: {urlparse(url).path} -> {match.group(0)[:60]}"
                    )
                    break
        for path, pattern in VERSION_PROBES.get(tech["name"], []):
            if tech["versions"]:
                break
            match = re.search(pattern, asset_text(origin + path), re.I)
            if match:
                tech["versions"].append(match.group(1))
                tech["evidence"].append(f"probe: {path} -> {match.group(1)}")
    return technologies


def analyze_host(target: dict, fingerprints: list[dict]) -> dict:
    result = {**target, "tls": None, "http": None}
    if not target["ips"]:
        return result
    open_ports = {port["port"] for port in target["ports"]}
    if 443 in open_ports or not open_ports:
        result["tls"] = tls_info(target["host"])
    for scheme in ("https", "http"):
        page = fetch(f"{scheme}://{target['host']}")
        if page:
            technologies = enrich_versions(
                page, tech_stack.detect(page, fingerprints)
            )
            result["http"] = {
                "url": page["url"],
                "status": page["status"],
                "redirects": page["redirects"],
                "technologies": technologies,
            }
            break
    return result


def tidy_dns(records: dict[str, list[str]]) -> dict[str, list[str]]:
    """Strip trailing dots, sort MX by priority, drop empty record types."""
    tidied = {}
    for key, values in records.items():
        cleaned = [value.rstrip(".") for value in values]
        if key == "mx":
            cleaned.sort(key=lambda item: (int(item.split()[0]), item))
        else:
            cleaned.sort()
        if cleaned:
            tidied[key] = cleaned
    return tidied


def tidy_hosts(reports: list[dict]) -> tuple[list[dict], list[str]]:
    """Split resolved hosts from unresolved names; omit empty/null fields."""
    hosts = []
    unresolved = []
    for report in reports:
        if not report["ips"]:
            unresolved.append(report["host"])
            continue
        entry = {"host": report["host"]}
        for key in ("ports", "tls", "http"):
            if report[key]:
                entry[key] = report[key]
        hosts.append(entry)
    return hosts, sorted(unresolved)


def main():
    parser = argparse.ArgumentParser(
        description="Recon a domain (whois, dig, crt.sh, subfinder, nmap, curl) then fingerprint technologies."
    )
    parser.add_argument("domain", help="Domain, e.g. example.com")
    args = parser.parse_args()

    print(BANNER, file=sys.stderr)

    try:
        domain = urlparse(tech_stack.normalize_url(args.domain)).hostname
    except ValueError as error:
        sys.exit(f"Invalid target: {error}")

    fingerprints = tech_stack.load_fingerprints()

    try:
        with ThreadPoolExecutor(max_workers=4) as pool:
            whois_future = pool.submit(whois_lookup, domain)
            dns_future = pool.submit(dns_records, domain)
            crt_future = pool.submit(crt_sh_subdomains, domain)
            subfinder_future = pool.submit(list_subdomains, domain)
            whois_info = whois_future.result()
            dns = dns_future.result()
            crt_hosts = crt_future.result()
            subfinder_hosts = subfinder_future.result()

        hosts = sorted({*subfinder_hosts, *crt_hosts, domain})
        print(
            f"[*] {len(hosts)} hostnames ({len(subfinder_hosts)} subfinder, "
            f"{len(crt_hosts)} crt.sh, "
            f"{len(set(subfinder_hosts) & set(crt_hosts))} shared)",
            file=sys.stderr,
        )

        with ThreadPoolExecutor(max_workers=WORKERS) as pool:
            resolved = dict(zip(hosts, pool.map(resolve, hosts)))
        ips = sorted({ip for values in resolved.values() for ip in values})
        print(f"[*] {len(ips)} unique IPv4 addresses: {', '.join(ips)}", file=sys.stderr)

        print(f"[*] nmap: ports {list(PORTS)} with service detection", file=sys.stderr)
        open_ports = scan_ports(ips) if ips else {}

        targets = build_targets(hosts, resolved, open_ports)
        print(f"[*] curl/tls: probing {len(targets)} hosts", file=sys.stderr)
        with ThreadPoolExecutor(max_workers=WORKERS) as pool:
            reports = list(
                pool.map(lambda target: analyze_host(target, fingerprints), targets)
            )
    except (OSError, RuntimeError) as error:
        sys.exit(f"finderstack failed: {error}")

    tidy_host_list, unresolved = tidy_hosts(reports)

    print(
        json.dumps(
            {
                "domain": domain,
                "whois": {
                    key: value
                    for key, value in (whois_info or {}).items()
                    if value not in (None, "", [])
                },
                "dns": tidy_dns(dns),
                "subdomains": {
                    "total": len(hosts),
                    "sources": {
                        "subfinder": len(subfinder_hosts),
                        "crt.sh": len(crt_hosts),
                        "shared": len(set(subfinder_hosts) & set(crt_hosts)),
                    },
                    "names": hosts,
                },
                "ips": {
                    ip: sorted(host for host, values in resolved.items() if ip in values)
                    for ip in ips
                },
                "hosts": tidy_host_list,
                "unresolved": unresolved,
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()

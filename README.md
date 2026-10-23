# finderstack

```
 _____ _           _           ____  _             _
|  ___(_)_ __   __| | ___ _ __/ ___|| |_ __ _  ___| | __
| |_  | | '_ \ / _` |/ _ \ '__\___ \| __/ _` |/ __| |/ /
|  _| | | | | | (_| |  __/ |   ___) | || (_| | (__|   <
|_|   |_|_| |_|\__,_|\___|_|  |____/ \__\__,_|\___|_|\_\
```

Domain reconnaissance and technology fingerprinting from the command line.
It combines `subfinder`, `crt.sh`, `whois`, `dig`, `nmap`, `curl` and `openssl`,
then matches the collected evidence against a local fingerprint database. No
third-party API, no API key, no account.

## What it collects

| Stage | Tool | Data |
|---|---|---|
| Domain registration | `whois` | registrar, creation/expiry dates, name servers, status, DNSSEC, abuse contact |
| DNS | `dig` | A, AAAA, MX, NS, TXT records |
| Subdomains | `subfinder` + `crt.sh` | union of passive enumeration and certificate transparency |
| Ports | `nmap -sV` | open ports on 80, 443, 8080, 8443 with product and version |
| TLS | `openssl` | subject, issuer, expiry, subject alternative names |
| HTTP | `curl` | status, redirect count, final URL, headers, cookies, HTML |
| Technologies | local fingerprints | name, category, versions, evidence |

Each hostname is probed over HTTPS first and falls back to HTTP. Hosts that are
blocked at the port-scan layer are still probed over HTTP, because a firewall
that drops `nmap` packets often serves normal traffic.

## Requirements

- Python 3.10 or newer (standard library only)
- `subfinder`, `nmap`, `curl`, `whois`, `dig`, `openssl` on `PATH`

On macOS:

```bash
brew install nmap subfinder jq
```

`whois`, `dig`, `curl` and `openssl` ship with macOS. Any missing optional tool
degrades that stage only; `subfinder` and `nmap` failures are reported and the
scan continues with the checks that still work.

## Usage

```bash
python3 finderstack.py example.com
```

JSON goes to stdout, progress and the ASCII banner go to stderr, so pipes stay
clean:

```bash
python3 finderstack.py example.com > result.json
python3 finderstack.py example.com | jq '.hosts[] | select(.http) | {host, tech: [.http.technologies[].name]}'
```

### Install as a global command

Symlink the script into a directory on `PATH`:

```bash
chmod +x finderstack.py
ln -sf "$PWD/finderstack.py" /opt/homebrew/bin/finderstack
```

Then run it from anywhere:

```bash
finderstack example.com
```

The script resolves its own symlink before importing sibling modules, so the
linked command reads `fingerprints.json` from the repository.

## Output

```json
{
  "domain": "example.com",
  "whois": {
    "registrar": "Example Registrar Inc",
    "created": "2017-10-26T09:34:25Z",
    "expires": "2027-10-26T23:59:59Z",
    "updated": "2026-10-21T02:00:06Z",
    "status": ["clientTransferProhibited"],
    "name_servers": ["ns1.example.com", "ns2.example.com"],
    "dnssec": "unsigned",
    "abuse_email": "abuse@example.net"
  },
  "dns": {
    "a": ["203.0.113.10"],
    "mx": ["1 aspmx.mail.example.com", "10 alt1.mail.example.com"],
    "ns": ["ns1.example.com", "ns2.example.com"],
    "txt": ["v=spf1 include:_spf.google.com ~all"]
  },
  "subdomains": {
    "total": 2,
    "sources": {"subfinder": 1, "crt.sh": 2, "shared": 1},
    "names": ["example.com", "www.example.com"]
  },
  "ips": {
    "203.0.113.10": ["example.com", "www.example.com"]
  },
  "hosts": [
    {
      "host": "example.com",
      "ports": [
        {"port": 80, "service": "http", "product": "nginx", "version": "1.25.3"},
        {"port": 443, "service": "https", "product": "nginx", "version": "1.25.3"}
      ],
      "tls": {
        "subject": "CN=example.com",
        "issuer": "C=US, O=Let's Encrypt, CN=R11",
        "not_after": "Jan  1 00:00:00 2027 GMT",
        "san": ["example.com", "www.example.com"]
      },
      "http": {
        "url": "https://example.com/",
        "status": 200,
        "redirects": 1,
        "technologies": [
          {
            "name": "WordPress",
            "category": "CMS",
            "versions": ["6.4.2"],
            "evidence": ["body: content=\"WordPress 6.4.2"]
          },
          {
            "name": "jQuery",
            "category": "JavaScript libraries",
            "versions": ["3.7.1"],
            "evidence": [
              "body: jquery-3.7.1.min.js",
              "asset: /wp-includes/js/jquery/jquery-3.7.1.min.js -> jQuery v3.7.1"
            ]
          }
        ]
      }
    }
  ],
  "unresolved": ["dev.example.com"]
}
```

Formatting rules:

- Empty fields are omitted: a host without an HTTP response has no `http` key,
  and a host with no open ports has no `ports` key.
- `hosts` holds only hostnames that resolve. Names with no DNS record are listed
  under `unresolved`.
- `dns` drops empty record types, strips trailing dots, and sorts MX by priority.
- `subdomains.sources` counts per source; names are not repeated three times.
- `versions` is empty when the technology does not expose a public version.

## Single-site mode

`tech_stack.py` runs the same fingerprint engine against one URL without the
recon stages:

```bash
python3 tech_stack.py example.com
```

## How detection works

1. The HTTP response is flattened into five searchable fields: `url`, `headers`,
   `cookies`, `body`, and `scripts` (source URLs of `<script>` tags).
2. Every fingerprint in `fingerprints.json` is matched against those fields.
3. Matches are deduplicated per technology; the first capture group of a regex
   becomes the reported version.
4. When a version is still missing, `enrich_versions` fetches the two or three
   most relevant same-origin assets (or a known version endpoint) and reads the
   version banner from the file.

Asset selection prefers the shortest file name, so `jquery.min.js` wins over
`jquery.magnific-popup.min.js`.

## Fingerprints

`fingerprints.json` is a list of objects:

```json
{
  "name": "Joomla",
  "category": "CMS",
  "body": ["joomla-script-options", "/media/jui/"],
  "headers": "^x-generator:\\s*Joomla!?\\s*([\\d.]+)",
  "cookies": "(?m)^joomla_user_state=",
  "scripts": "/media/system/js/core(?:\\.min)?\\.js",
  "url": "/administrator$"
}
```

- Every field is optional and accepts a string or a list of strings.
- Regexes are matched case-insensitively and multiline, so `^` and `$` apply per
  line in the joined header and cookie fields.
- Capture group 1 is the version. No group means the technology is reported
  without a version.
- JSON escaping applies: write `\\s` and `\\d`, not `\s` and `\d`.

Version probing is extended in `finderstack.py` through `VERSION_ASSETS` (asset
keyword plus regex) and `VERSION_PROBES` (path plus regex).

## Tests

```bash
python3 -m unittest test_tech_stack test_finderstack
```

The suite is offline: parsers and enrichment are tested with fixtures and
stubbed fetches.

## Limitations

- The main HTML document only. JavaScript is not executed, so frameworks that
  appear solely at runtime can be missed.
- Version detection depends on what the server exposes. Minified bundles without
  a banner, or headers stripped by a CDN, yield no version.
- `nmap` may be filtered by the target firewall; HTTP and TLS probing still run.
- `crt.sh` is slow and occasionally rate-limited; the stage is skipped with a
  warning when it fails.
- Large estates (thousands of certificate transparency names) take several
  minutes and produce large JSON.
- IPv4 only: IPv6 addresses are not scanned.

## Legal

Use this against systems you are authorized to test. `nmap` sends real probes to
the target, and repeated scanning can trigger firewall blocks.

## License

MIT. See [LICENSE](LICENSE).

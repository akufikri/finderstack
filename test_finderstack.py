import unittest

import finderstack

NMAP_XML = """<?xml version="1.0"?>
<nmaprun>
  <host>
    <address addr="93.184.215.14" addrtype="ipv4"/>
    <hostnames><hostname name="example.com" type="user"/></hostnames>
    <ports>
      <port protocol="tcp" portid="80"><state state="open"/><service name="http"/></port>
      <port protocol="tcp" portid="443"><state state="open"/><service name="https"/></port>
      <port protocol="tcp" portid="8080"><state state="closed"/><service name="http-proxy"/></port>
    </ports>
  </host>
  <host>
    <address addr="10.0.0.1" addrtype="ipv4"/>
    <ports/>
  </host>
</nmaprun>
"""

CURL_OUTPUT = """HTTP/1.1 301 Moved Permanently\r
Server: nginx\r
Location: https://example.com/\r
Set-Cookie: sid=abc; path=/\r
\r
HTTP/1.1 200 OK\r
Server: nginx/1.25.3\r
Content-Type: text/html; charset=utf-8\r
Set-Cookie: theme=dark; path=/\r
\r
<body>hi</body>
@@META https://example.com/ 200 1
"""

WHOIS_TEXT = """% IANA WHOIS server
created:      1993-02-27
changed:      2026-08-05

Domain Name: EXAMPLE.COM
Registrar WHOIS Server: whois.example.net
Updated Date: 2026-10-21T02:00:06Z
Creation Date: 2017-10-26T09:34:25Z
Registry Expiry Date: 2027-10-26T23:59:59Z
Registrar: Example Registrar Inc
Registrar Abuse Contact Email: abuse@example.net
Domain Status: clientTransferProhibited
Domain Status: serverTransferProhibited
Name Server: NS1.EXAMPLE.COM
Name Server: NS2.EXAMPLE.COM
DNSSEC: unsigned
"""

TLS_TEXT = """subject=CN = example.com
issuer=C = US, O = Let's Encrypt, CN = R11
notAfter=Jan  1 00:00:00 2027 GMT
X509v3 Subject Alternative Name:
    DNS:example.com, DNS:www.example.com
"""


class BuildTargetsTest(unittest.TestCase):
    def test_merges_ports_across_ips(self):
        targets = finderstack.build_targets(
            ["a.example.com"],
            {"a.example.com": ["1.1.1.1", "2.2.2.2"]},
            {
                "1.1.1.1": [{"port": 443, "service": "https"}],
                "2.2.2.2": [
                    {"port": 80, "service": "http"},
                    {"port": 443, "service": "https"},
                ],
            },
        )
        self.assertEqual(
            targets,
            [
                {
                    "host": "a.example.com",
                    "ips": ["1.1.1.1", "2.2.2.2"],
                    "ports": [
                        {"port": 80, "service": "http"},
                        {"port": 443, "service": "https"},
                    ],
                }
            ],
        )


class ParseNmapTest(unittest.TestCase):
    def test_keeps_only_open_ports(self):
        result = finderstack.parse_nmap_xml(NMAP_XML)
        self.assertEqual(
            result["93.184.215.14"],
            [{"port": 80, "service": "http"}, {"port": 443, "service": "https"}],
        )
        self.assertEqual(result["10.0.0.1"], [])

    def test_keeps_service_version(self):
        xml = NMAP_XML.replace(
            '<service name="https"/>',
            '<service name="https" product="nginx" version="1.25.3"/>',
        )
        result = finderstack.parse_nmap_xml(xml)
        self.assertEqual(
            result["93.184.215.14"][1],
            {"port": 443, "service": "https", "product": "nginx", "version": "1.25.3"},
        )


class ParseCurlTest(unittest.TestCase):
    def test_splits_headers_cookies_meta(self):
        url, status, redirects, headers, cookies = finderstack.parse_curl_output(CURL_OUTPUT)
        self.assertEqual(url, "https://example.com/")
        self.assertEqual(status, 200)
        self.assertEqual(redirects, 1)
        self.assertIn("Server: nginx/1.25.3", headers)
        self.assertNotIn("HTTP/1.1", headers)
        self.assertEqual(cookies, "Set-Cookie: sid=abc; path=/\nSet-Cookie: theme=dark; path=/")

    def test_rejects_output_without_marker(self):
        with self.assertRaises(ValueError):
            finderstack.parse_curl_output("no meta here")


class EnrichVersionsTest(unittest.TestCase):
    def test_fills_from_asset_and_probe(self):
        page = {
            "url": "https://example.com/",
            "assets": ["/js/jquery.min.js", "https://cdn.other.net/jquery.js"],
        }
        technologies = [
            {"name": "jQuery", "category": "JavaScript libraries", "versions": [], "evidence": []},
            {"name": "Joomla", "category": "CMS", "versions": [], "evidence": []},
            {"name": "Google Analytics", "category": "Analytics", "versions": [], "evidence": []},
        ]
        responses = {
            "https://example.com/js/jquery.min.js": "/*! jQuery v3.7.1 | (c) OpenJS */",
            "https://example.com/administrator/manifests/files/joomla.xml": "<version>5.1.2</version>",
        }
        original = finderstack.fetch_text
        finderstack.fetch_text = lambda url, limit=262_144: responses.get(url)
        try:
            finderstack.enrich_versions(page, technologies)
        finally:
            finderstack.fetch_text = original

        found = {tech["name"]: tech for tech in technologies}
        self.assertEqual(found["jQuery"]["versions"], ["3.7.1"])
        self.assertEqual(found["jQuery"]["evidence"], ["asset: /js/jquery.min.js -> jQuery v3.7.1"])
        self.assertEqual(found["Joomla"]["versions"], ["5.1.2"])
        self.assertEqual(found["Google Analytics"]["versions"], [])


class ParseWhoisTest(unittest.TestCase):
    def test_registry_block_wins(self):
        info = finderstack.parse_whois(WHOIS_TEXT)
        self.assertEqual(info["registrar"], "Example Registrar Inc")
        self.assertEqual(info["created"], "2017-10-26T09:34:25Z")
        self.assertEqual(info["expires"], "2027-10-26T23:59:59Z")
        self.assertEqual(info["updated"], "2026-10-21T02:00:06Z")
        self.assertEqual(info["name_servers"], ["ns1.example.com", "ns2.example.com"])
        self.assertEqual(
            info["status"],
            ["clientTransferProhibited", "serverTransferProhibited"],
        )
        self.assertEqual(info["abuse_email"], "abuse@example.net")


class ParseTlsTest(unittest.TestCase):
    def test_subject_issuer_san(self):
        info = finderstack.parse_tls_output(TLS_TEXT)
        self.assertEqual(info["subject"], "CN = example.com")
        self.assertIn("Let's Encrypt", info["issuer"])
        self.assertEqual(info["not_after"], "Jan  1 00:00:00 2027 GMT")
        self.assertEqual(info["san"], ["example.com", "www.example.com"])


if __name__ == "__main__":
    unittest.main()

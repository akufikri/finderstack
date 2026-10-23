import unittest

import tech_stack


class DetectTest(unittest.TestCase):
    def test_detects_versions_and_categories(self):
        page = {
            "url": "https://example.com/",
            "headers": "Server: nginx/1.25.3\nX-Powered-By: PHP/8.3.0",
            "cookies": "laravel_session=abc; path=/",
            "body": '<meta name="generator" content="WordPress 6.4.2">'
            '<script src="/wp-includes/js/jquery/jquery-3.7.1.min.js"></script>',
            "scripts": "/wp-includes/js/jquery/jquery-3.7.1.min.js",
        }
        found = {item["name"]: item for item in tech_stack.detect(page, tech_stack.load_fingerprints())}

        self.assertEqual(set(found), {"jQuery", "Laravel", "nginx", "PHP", "WordPress"})
        self.assertEqual(found["nginx"]["versions"], ["1.25.3"])
        self.assertEqual(found["nginx"]["evidence"], ["headers: Server: nginx/1.25.3"])
        self.assertEqual(found["PHP"]["versions"], ["8.3.0"])
        self.assertEqual(found["WordPress"]["versions"], ["6.4.2"])
        self.assertEqual(found["jQuery"]["versions"], ["3.7.1"])
        self.assertEqual(found["Laravel"]["category"], "Web frameworks")

    def test_no_false_hit_on_plain_page(self):
        page = {"url": "https://example.com/", "headers": "Server: nginx", "cookies": "", "body": "<p>hi</p>", "scripts": ""}
        self.assertEqual([item["name"] for item in tech_stack.detect(page, tech_stack.load_fingerprints())], ["nginx"])


class NormalizeUrlTest(unittest.TestCase):
    def test_adds_scheme(self):
        self.assertEqual(tech_stack.normalize_url("example.com"), "https://example.com")

    def test_keeps_scheme(self):
        self.assertEqual(tech_stack.normalize_url("http://example.com"), "http://example.com")

    def test_rejects_garbage(self):
        with self.assertRaises(ValueError):
            tech_stack.normalize_url("https://")


if __name__ == "__main__":
    unittest.main()

from django.http import HttpResponse
from django.test import SimpleTestCase
from django.utils.cache import has_vary_header


class VaryHeaderWhitespaceTest(SimpleTestCase):
    """
    Regression test for CVE-2026-48587: has_vary_header() must strip
    whitespace from Vary header values to correctly detect wildcards.
    """

    def test_has_vary_header_asterisk_with_trailing_whitespace(self):
        """Vary: * with trailing whitespace should be detected."""
        response = HttpResponse()
        response.headers["Vary"] = "* "
        # Should detect the wildcard despite trailing whitespace
        self.assertTrue(has_vary_header(response, "*"))

    def test_has_vary_header_asterisk_with_leading_whitespace(self):
        """Vary: * with leading whitespace should be detected."""
        response = HttpResponse()
        response.headers["Vary"] = " *"
        # Should detect the wildcard despite leading whitespace
        self.assertTrue(has_vary_header(response, "*"))

    def test_has_vary_header_asterisk_in_list_with_whitespace(self):
        """Vary: Cookie, * with whitespace should be detected."""
        response = HttpResponse()
        response.headers["Vary"] = "Cookie, * "
        # Should detect the wildcard in the list despite trailing whitespace
        self.assertTrue(has_vary_header(response, "*"))

    def test_has_vary_header_normal_header_with_leading_whitespace(self):
        """Vary: Cookie with leading whitespace should be detected."""
        response = HttpResponse()
        response.headers["Vary"] = " Cookie"
        # Should detect the header despite leading whitespace
        self.assertTrue(has_vary_header(response, "Cookie"))

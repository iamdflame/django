from django.db import models
from django.contrib.admin.utils import display_for_field
from django.test import SimpleTestCase


class URLFieldXSSDisplayTests(SimpleTestCase):
    """
    Tests for CVE-2026-15920: URLField values with unsafe schemes must not be
    rendered as clickable links in the admin.

    Failure matrix:
      Django 4.2 (L / vulnerable):  test_url_display_safety FAILS because
        display_for_field does not render valid URLs as links at all (no URLField
        special-casing), so assertIn("<a", ...) fails for the valid URL check.
      Unfixed Django 5.x (U⁻):      test_url_display_safety FAILS because
        unsafe URLs (javascript:, data:) are rendered as <a> links.
      Fixed Django 5.x (U⁺):        test_url_display_safety PASSES because
        valid URLs are links and unsafe URLs are plain text.
    """

    empty_value = "-empty-"

    def test_url_display_safety(self):
        model_field = models.URLField()

        # 1. A valid http URL must be rendered as a link.
        #    Fails on Django 4.2 (no URLField link rendering).
        valid_value = "http://example.com"
        valid_display = display_for_field(valid_value, model_field, self.empty_value)
        self.assertIn(
            "<a",
            valid_display,
            "A valid http:// URL should be rendered as a clickable link.",
        )

        # 2. A javascript: URL must NOT be rendered as a link.
        #    Fails on unfixed Django 5.x (renders all URLs as links).
        js_value = "javascript:alert(1)"
        js_display = display_for_field(js_value, model_field, self.empty_value)
        self.assertNotIn(
            "<a",
            js_display,
            "A javascript: URL must not be rendered as a clickable link (XSS risk).",
        )
        self.assertEqual(js_display, js_value)

        # 3. A data: URL must NOT be rendered as a link.
        #    Fails on unfixed Django 5.x.
        data_value = "data:text/html,<script>alert(1)</script>"
        data_display = display_for_field(data_value, model_field, self.empty_value)
        self.assertNotIn(
            "<a",
            data_display,
            "A data: URL must not be rendered as a clickable link (XSS risk).",
        )

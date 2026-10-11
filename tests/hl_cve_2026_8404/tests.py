from django.http import HttpResponse
from django.test import SimpleTestCase, RequestFactory, override_settings
from django.views.decorators.cache import cache_page


def make_view_with_cache_control(cc_value):
    """Return a cache_page-wrapped view that sets Cache-Control manually."""

    @cache_page(60)
    def view(request, value):
        response = HttpResponse(f"Hello World {value}")
        response["Cache-Control"] = cc_value
        return response

    return view


@override_settings(
    CACHES={
        "default": {
            "BACKEND": "django.core.cache.backends.locmem.LocMemCache",
            "LOCATION": "test-cve-2026-8404",
        }
    },
    CACHE_MIDDLEWARE_ALIAS="default",
    CACHE_MIDDLEWARE_KEY_PREFIX="",
    CACHE_MIDDLEWARE_SECONDS=60,
)
class CVE20268404Test(SimpleTestCase):
    """
    Test that UpdateCacheMiddleware / cache_page does NOT cache responses
    with private/no-cache/no-store Cache-Control directives, regardless of
    the case used in the header value.

    On vulnerable Django 4.2 code the check is case-sensitive:
        if "private" in response.get("Cache-Control", ()):
    so "Private" or "PRIVATE" bypasses the guard and the response gets cached.
    The second request then returns the *cached* first response instead of
    a fresh one, causing the assertion to fail.
    """

    def setUp(self):
        self.factory = RequestFactory()
        # Clear the cache before each test
        from django.core.cache import cache
        cache.clear()

    def tearDown(self):
        from django.core.cache import cache
        cache.clear()

    def _assert_not_cached(self, cc_value):
        """
        Assert that two successive requests through a cache_page view with
        the given Cache-Control header value return distinct (non-cached)
        responses.
        """
        view = make_view_with_cache_control(cc_value)
        request = self.factory.get("/view/")

        response1 = view(request, "1")
        self.assertEqual(response1.content, b"Hello World 1")

        # If the response was incorrectly cached, this will return "Hello World 1"
        # instead of "Hello World 2".
        response2 = view(request, "2")
        self.assertEqual(
            response2.content,
            b"Hello World 2",
            f"Response with Cache-Control: {cc_value!r} was incorrectly cached.",
        )

    def test_uppercase_private_not_cached(self):
        """Cache-Control: PRIVATE must not be cached."""
        self._assert_not_cached("PRIVATE")

    def test_mixed_case_private_not_cached(self):
        """Cache-Control: Private must not be cached."""
        self._assert_not_cached("Private")

    def test_uppercase_no_store_not_cached(self):
        """Cache-Control: NO-STORE must not be cached."""
        self._assert_not_cached("NO-STORE")

    def test_mixed_case_no_store_not_cached(self):
        """Cache-Control: NO-store must not be cached."""
        self._assert_not_cached("NO-store")

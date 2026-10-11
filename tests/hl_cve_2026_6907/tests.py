from django.test import SimpleTestCase, RequestFactory, override_settings
from django.http import HttpResponse
from django.views.decorators.cache import cache_page
from django.utils.cache import patch_vary_headers


def view_vary_asterisk_via_patch(request, value):
    response = HttpResponse("Hello World %s" % value)
    patch_vary_headers(response, ("*",))
    return response


def view_vary_asterisk_in_header(request, value):
    response = HttpResponse("Hello World %s" % value)
    response["Vary"] = "Cookie, *, Pony"
    return response


@override_settings(
    CACHES={
        "default": {
            "BACKEND": "django.core.cache.backends.locmem.LocMemCache",
        }
    },
    CACHE_MIDDLEWARE_SECONDS=300,
    CACHE_MIDDLEWARE_KEY_PREFIX="",
    CACHE_MIDDLEWARE_ALIAS="default",
)
class VaryAsteriskCacheTest(SimpleTestCase):
    """
    CVE-2026-6907: UpdateCacheMiddleware must NOT cache responses whose
    Vary header contains '*'.  On vulnerable Django 4.2 the second call
    returns the cached first response ("Hello World 1") instead of the
    fresh second response ("Hello World 2").
    """

    def setUp(self):
        self.factory = RequestFactory()

    def _assert_not_cached(self, view):
        """
        Call the view twice with different values.  If the response is
        incorrectly cached the second call returns the first value, which
        causes the assertion to fail (demonstrating the vulnerability).
        """
        request = self.factory.get("/view/")
        response1 = view(request, "1")
        self.assertEqual(response1.content, b"Hello World 1")

        # A second request with a different value must NOT return the cached
        # first response.
        response2 = view(request, "2")
        # On vulnerable code this is b"Hello World 1" (served from cache).
        self.assertEqual(
            response2.content,
            b"Hello World 2",
            "Response with Vary: * was incorrectly served from cache "
            "(CVE-2026-6907).",
        )

    def test_vary_asterisk_patch_vary_headers_not_cached(self):
        """Vary: * set via patch_vary_headers() must not be cached."""
        wrapped = cache_page(300)(view_vary_asterisk_via_patch)
        self._assert_not_cached(wrapped)

    def test_vary_asterisk_in_vary_header_not_cached(self):
        """Vary: Cookie, *, Pony must not be cached."""
        wrapped = cache_page(300)(view_vary_asterisk_in_header)
        self._assert_not_cached(wrapped)

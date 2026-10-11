from django.test import SimpleTestCase, RequestFactory
from django.http import HttpResponse
from django.middleware.cache import CacheMiddleware
from django.middleware.csrf import CsrfViewMiddleware
from django.utils.cache import patch_vary_headers
from django.views.decorators.cache import cache_page
from django.core.cache import cache


def csrf_view(request):
    """View that sets a CSRF cookie."""
    response = HttpResponse("content")
    response.set_cookie("csrftoken", "test_csrf_value")
    patch_vary_headers(response, ("Cookie",))
    return response


def refreshing_cookie_view(request):
    """View that updates an existing cookie."""
    response = HttpResponse("content")
    response.set_cookie("session", "new_value")
    patch_vary_headers(response, ("Cookie",))
    return response


class CacheSensitiveCookieTest(SimpleTestCase):
    def setUp(self):
        self.factory = RequestFactory()
        cache.clear()

    def tearDown(self):
        cache.clear()

    def test_new_cookie_not_cached_with_unrelated_cookie(self):
        """
        Responses that set a new cookie should not be cached even when
        the request already has an unrelated cookie.
        
        This is the regression test for CVE-2026-48588.
        """
        # Request with an unrelated cookie (e.g., language preference)
        request = self.factory.get("/view/", HTTP_COOKIE="lang=en")
        csrf_middleware = CsrfViewMiddleware(csrf_view)
        csrf_middleware.process_view(request, csrf_view, (), {})
        cache_middleware = CacheMiddleware(csrf_middleware)

        # First request: should not be cached
        self.assertIsNone(cache_middleware.process_request(request))
        cache_middleware(request)

        # Second request with same unrelated cookie: should not hit cache
        # (because the response sets a new cookie)
        request2 = self.factory.get("/view/", HTTP_COOKIE="lang=en")
        result = cache_middleware.process_request(request2)
        
        # If vulnerable, result will be a cached response (not None).
        # If fixed, result will be None (cache miss, forcing re-execution).
        self.assertIsNone(
            result,
            "Response setting a new cookie was cached despite unrelated request cookie"
        )

    def test_refreshed_cookie_not_cached(self):
        """
        A response that updates the value of a cookie already present in the
        request should not be cached.
        """
        request = self.factory.get("/view/", HTTP_COOKIE="session=old_value")
        cache_middleware = CacheMiddleware(refreshing_cookie_view)

        # First request
        self.assertIsNone(cache_middleware.process_request(request))
        cache_middleware(request)

        # Second request with same cookie: should not hit cache
        request2 = self.factory.get("/view/", HTTP_COOKIE="session=old_value")
        result = cache_middleware.process_request(request2)
        
        self.assertIsNone(
            result,
            "Response refreshing an existing cookie was cached"
        )

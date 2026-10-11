from django.conf import settings
from django.contrib.sessions.middleware import SessionMiddleware
from django.http import HttpResponse
from django.test import SimpleTestCase, RequestFactory, override_settings


def view_that_touches_session(request):
    """A view that reads/writes the session."""
    request.session["hello"] = "world"
    return HttpResponse("touched session")


def view_that_ignores_session(request):
    """A view that does NOT touch the session at all."""
    return HttpResponse("did not touch session")


@override_settings(
    SESSION_ENGINE="django.contrib.sessions.backends.cache",
    SESSION_SAVE_EVERY_REQUEST=True,
    CACHES={
        "default": {
            "BACKEND": "django.core.cache.backends.locmem.LocMemCache",
        }
    },
)
class SessionFixationVaryHeaderTests(SimpleTestCase):
    """
    CVE-2026-35192: When SESSION_SAVE_EVERY_REQUEST=True and a non-empty
    session exists but was not accessed in the current request, the response
    must still include 'Vary: Cookie' to prevent caches from serving the
    session cookie to other users.
    """

    def setUp(self):
        self.factory = RequestFactory()

    def _make_session_key(self):
        """Create a session with data and return its key."""
        request = self.factory.get("/")
        middleware = SessionMiddleware(view_that_touches_session)
        middleware(request)
        # The session key is now set on request.session
        return request.session.session_key

    def test_vary_cookie_set_when_save_every_request_and_session_not_accessed(self):
        """
        When SESSION_SAVE_EVERY_REQUEST=True and the session has data but
        was not accessed during the request, the response must include
        'Vary: Cookie'.

        On vulnerable Django 4.2: 'accessed' is False so patch_vary_headers
        is never called, meaning 'Vary: Cookie' is absent — FAIL.
        On fixed code: 'Vary: Cookie' is always set when a session cookie
        is sent — PASS.
        """
        # Step 1: Create a session with data
        session_key = self._make_session_key()

        # Step 2: Make a new request that carries the session cookie
        # but does NOT touch the session (simulating a cached public page hit)
        request = self.factory.get("/")
        request.COOKIES[settings.SESSION_COOKIE_NAME] = session_key

        middleware = SessionMiddleware(view_that_ignores_session)
        response = middleware(request)

        # The session is non-empty and SESSION_SAVE_EVERY_REQUEST=True,
        # so a session cookie should be set in the response.
        self.assertIn(
            settings.SESSION_COOKIE_NAME,
            response.cookies,
            "Session cookie should be set when SESSION_SAVE_EVERY_REQUEST=True "
            "and session is non-empty.",
        )

        # The response MUST vary on Cookie to prevent caches from reusing
        # this response (with its session cookie) for other users.
        vary_header = response.get("Vary", "")
        self.assertIn(
            "Cookie",
            vary_header,
            "Response must include 'Vary: Cookie' when SESSION_SAVE_EVERY_REQUEST=True "
            "and a session cookie is being set, to prevent session fixation via caches. "
            f"Got Vary: '{vary_header}'",
        )

    def test_vary_cookie_set_when_save_every_request_and_session_accessed(self):
        """
        Sanity check: when the session IS accessed, Vary: Cookie must also
        be present (this should pass on both vulnerable and fixed code).
        """
        session_key = self._make_session_key()

        def view_reads_session(request):
            _ = request.session.get("hello")
            return HttpResponse("read session")

        request = self.factory.get("/")
        request.COOKIES[settings.SESSION_COOKIE_NAME] = session_key

        middleware = SessionMiddleware(view_reads_session)
        response = middleware(request)

        vary_header = response.get("Vary", "")
        self.assertIn(
            "Cookie",
            vary_header,
            "Response must include 'Vary: Cookie' when session is accessed.",
        )

    def test_vary_cookie_absent_for_truly_empty_session_no_cookie(self):
        """
        Sanity check: a fresh request with no session cookie and a view
        that never touches the session should NOT set a session cookie,
        and Vary: Cookie behaviour is irrelevant (no fixation risk).
        This should pass on both vulnerable and fixed code.
        """
        request = self.factory.get("/")
        # No session cookie in request

        middleware = SessionMiddleware(view_that_ignores_session)
        response = middleware(request)

        # No session cookie should be set (session is empty)
        self.assertNotIn(
            settings.SESSION_COOKIE_NAME,
            response.cookies,
            "No session cookie should be set for an empty, untouched session.",
        )

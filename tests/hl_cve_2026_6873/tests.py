from django.http import HttpRequest, HttpResponse
from django.test import SimpleTestCase, override_settings
from django.core import signing


@override_settings(SIGNED_COOKIE_LEGACY_SALT_FALLBACK=False)
class SignedCookieSaltNamespaceCollisionTest(SimpleTestCase):
    """
    Regression test for CVE-2026-6873: Signed cookie salt namespace collision.
    
    The vulnerability occurs when distinct (key, salt) pairs produce the same
    concatenation, allowing cookies to be accepted in unintended contexts.
    
    Example: key="a", salt="bc" concatenates to "abc", same as key="ab", salt="c".
    """

    def test_salt_namespace_collision_rejected(self):
        """
        A cookie signed with key="a" and salt="bc" should not be accepted
        when requesting with key="ab" and salt="c", even though both produce
        the same concatenated salt "abc" in the vulnerable code.
        """
        # Sign a cookie with key="a" and salt="bc"
        response = HttpResponse()
        response.set_signed_cookie("a", "hello", salt="bc")
        
        # Try to use that signed value as a cookie for key="ab" with salt="c"
        # In vulnerable code, this would succeed because both derive salt "abc"
        request = HttpRequest()
        request.COOKIES["ab"] = response.cookies["a"].value
        
        # This should raise BadSignature in fixed code
        with self.assertRaises(signing.BadSignature):
            request.get_signed_cookie("ab", salt="c")

    def test_correct_key_salt_pair_accepted(self):
        """
        A cookie signed with key="a" and salt="bc" should be accepted
        when requesting with the same key="a" and salt="bc".
        """
        response = HttpResponse()
        response.set_signed_cookie("a", "hello", salt="bc")
        
        request = HttpRequest()
        request.COOKIES["a"] = response.cookies["a"].value
        
        # This should succeed
        value = request.get_signed_cookie("a", salt="bc")
        self.assertEqual(value, "hello")

    def test_different_key_same_concatenation_rejected(self):
        """
        Another collision case: key="ab", salt="c" vs key="a", salt="bc".
        """
        response = HttpResponse()
        response.set_signed_cookie("ab", "world", salt="c")
        
        request = HttpRequest()
        request.COOKIES["a"] = response.cookies["ab"].value
        
        # Should not accept the cookie with different key/salt pair
        with self.assertRaises(signing.BadSignature):
            request.get_signed_cookie("a", salt="bc")

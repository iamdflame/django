from django.test import SimpleTestCase
from django.utils.http import parse_header_parameters


class ParseHeaderParametersBehaviourTests(SimpleTestCase):
    def test_rfc2231_wrong_title_decoded(self):
        """
        Fixed code uses stdlib email which decodes percent-encoded RFC 2231
        values even when the format is slightly wrong (missing double single
        quotes). The vulnerable code returns the raw percent-encoded string.
        """
        raw_line = (
            "Content-Type: application/x-stuff; "
            "title*='This%20is%20%2A%2A%2Afun%2A%2A%2A"
        )
        _, params = parse_header_parameters(raw_line)
        title = params["title"]
        # The fixed implementation decodes percent-encoding via stdlib email,
        # yielding the human-readable string. The vulnerable implementation
        # returns the raw percent-encoded value unchanged.
        assert title == "'This is ***fun***", (
            f"Expected decoded title \"'This is ***fun***\" but got {title!r}. "
            "This indicates the vulnerable parse_header_parameters is in use."
        )

    def test_many_separators_quoted_value_parses_trailing_param(self):
        """
        A quoted filename containing many semicolons must be treated as a
        single parameter value, and any trailing unquoted parameters must
        still be parsed. The vulnerable _parseparam has quadratic complexity
        but also may fail to parse trailing parameters correctly at scale.
        """
        value = ";" * 500
        header = 'attachment; filename="%s"; size=1' % value
        main_type, params = parse_header_parameters(header)
        assert main_type == "attachment", (
            f"Expected main type 'attachment', got {main_type!r}"
        )
        assert params.get("filename") == value, (
            f"Expected filename to be {value!r}, got {params.get('filename')!r}"
        )
        assert params.get("size") == "1", (
            f"Expected size='1', got {params.get('size')!r}. "
            "Vulnerable code may fail to parse trailing params after quoted semicolons."
        )

    def test_rfc2231_missing_double_quotes_not_decoded_in_vulnerable(self):
        """
        Another RFC 2231 case: title*='foo.html should remain as-is in
        vulnerable code but the fixed code still returns 'foo.html (no
        percent encoding to decode here, so both agree).
        Verify the first case more carefully with a simpler percent-encoded value.
        """
        raw_line = "application/x-stuff; title*=UTF-8''Hello%20World"
        _, params = parse_header_parameters(raw_line)
        title = params.get("title")
        # Fixed code (via stdlib email / RFC 2231 decoding) returns "Hello World"
        # Vulnerable code returns "Hello World" too (it does decode when format is correct)
        # So use a case where vulnerable code fails: missing encoding prefix
        raw_line2 = "application/x-stuff; title*='Hello%20World"
        _, params2 = parse_header_parameters(raw_line2)
        title2 = params2.get("title")
        # Fixed: stdlib email decodes this to "'Hello World"
        # Vulnerable: returns "'Hello%20World" (no decoding, wrong format)
        assert title2 == "'Hello World", (
            f"Expected \"'Hello World\" but got {title2!r}. "
            "Vulnerable code does not decode percent-encoding in malformed RFC 2231 values."
        )

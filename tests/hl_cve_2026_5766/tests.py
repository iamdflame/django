from io import BytesIO

from django.core.files.uploadhandler import MemoryFileUploadHandler
from django.test import SimpleTestCase


class MemoryFileUploadHandlerCVE20265766Tests(SimpleTestCase):
    """
    CVE-2026-5766: MemoryFileUploadHandler must use the actual stream size
    (for seekable streams) rather than the Content-Length header value when
    deciding whether to activate in-memory storage.

    On vulnerable Django 4.2 code, handle_raw_input() trusts content_length
    blindly, so an understated value (e.g. 0) causes the handler to activate
    even when the real data exceeds FILE_UPLOAD_MAX_MEMORY_SIZE.
    """

    def test_seekable_stream_exceeds_limit_deactivated(self):
        """
        When input_data is seekable and its real size exceeds
        FILE_UPLOAD_MAX_MEMORY_SIZE, the handler must NOT activate,
        even if content_length is understated (0).
        """
        handler = MemoryFileUploadHandler()
        # Real data: 15 bytes. Limit: 10 bytes. content_length: 0 (understated).
        with self.settings(FILE_UPLOAD_MAX_MEMORY_SIZE=10):
            handler.handle_raw_input(BytesIO(b"x" * 15), {}, 0, None)
        # On vulnerable code: activated=True (0 <= 10), so this assertion fails.
        self.assertIs(
            handler.activated,
            False,
            "Handler must be deactivated when actual stream size (15) exceeds "
            "FILE_UPLOAD_MAX_MEMORY_SIZE (10), regardless of understated "
            "content_length (0).",
        )

    def test_seekable_stream_within_limit_activated(self):
        """
        When input_data is seekable and its real size is within
        FILE_UPLOAD_MAX_MEMORY_SIZE, the handler should activate,
        even if content_length is understated (0).
        """
        handler = MemoryFileUploadHandler()
        # Real data: 10 bytes. Limit: 10 bytes. content_length: 0 (understated).
        with self.settings(FILE_UPLOAD_MAX_MEMORY_SIZE=10):
            handler.handle_raw_input(BytesIO(b"x" * 10), {}, 0, None)
        self.assertIs(
            handler.activated,
            True,
            "Handler must be activated when actual stream size (10) is within "
            "FILE_UPLOAD_MAX_MEMORY_SIZE (10).",
        )

    def test_seekable_stream_understated_content_length_large_data(self):
        """
        content_length=1 but actual data is 100 bytes, limit is 50.
        Vulnerable code activates (1 <= 50); fixed code deactivates.
        """
        handler = MemoryFileUploadHandler()
        with self.settings(FILE_UPLOAD_MAX_MEMORY_SIZE=50):
            handler.handle_raw_input(BytesIO(b"y" * 100), {}, 1, None)
        self.assertIs(
            handler.activated,
            False,
            "Handler must be deactivated when actual stream size (100) exceeds "
            "FILE_UPLOAD_MAX_MEMORY_SIZE (50), even though content_length=1.",
        )

    def test_non_seekable_stream_uses_content_length(self):
        """
        For non-seekable streams (e.g. WSGI LimitedStream), the handler falls
        back to content_length. When content_length exceeds the limit, it must
        deactivate.
        """
        handler = MemoryFileUploadHandler()

        class NonSeekableStream:
            """Simulates a non-seekable stream (no seek/tell)."""
            def read(self, size=-1):
                return b"x" * 15

        with self.settings(FILE_UPLOAD_MAX_MEMORY_SIZE=10):
            handler.handle_raw_input(NonSeekableStream(), {}, 15, None)
        self.assertIs(
            handler.activated,
            False,
            "Handler must be deactivated when content_length (15) exceeds "
            "FILE_UPLOAD_MAX_MEMORY_SIZE (10) for non-seekable streams.",
        )

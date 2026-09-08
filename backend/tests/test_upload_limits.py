import unittest

from fastapi import HTTPException

from app.routers.upload import _read_upload_with_limit


class FakeUpload:
    def __init__(self, data: bytes):
        self._data = data
        self._offset = 0
        self.bytes_returned = 0
        self.read_sizes = []

    async def read(self, size: int = -1) -> bytes:
        self.read_sizes.append(size)
        if size < 0:
            size = len(self._data) - self._offset
        chunk = self._data[self._offset:self._offset + size]
        self._offset += len(chunk)
        self.bytes_returned += len(chunk)
        return chunk


class UploadLimitTests(unittest.IsolatedAsyncioTestCase):
    async def test_exact_limit_is_accepted(self):
        upload = FakeUpload(b"a" * 16)

        content = await _read_upload_with_limit(upload, max_size=16)

        self.assertEqual(content, b"a" * 16)
        self.assertEqual(upload.bytes_returned, 16)

    async def test_oversized_upload_is_rejected_after_one_sentinel_byte(self):
        upload = FakeUpload(b"a" * 64)

        with self.assertRaises(HTTPException) as context:
            await _read_upload_with_limit(upload, max_size=16)

        self.assertEqual(context.exception.status_code, 400)
        self.assertEqual(upload.bytes_returned, 17)
        self.assertIn("File exceeds max size", context.exception.detail)

    async def test_reader_never_requests_more_than_remaining_limit_plus_sentinel(self):
        upload = FakeUpload(b"a" * 64)

        with self.assertRaises(HTTPException):
            await _read_upload_with_limit(upload, max_size=16)

        self.assertLessEqual(max(upload.read_sizes), 17)


if __name__ == "__main__":
    unittest.main()

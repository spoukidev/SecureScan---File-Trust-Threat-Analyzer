import unittest
from types import SimpleNamespace

from app.routers.reports import download_report


class FakeDB:
    def __init__(self, record):
        self.record = record

    async def get(self, _model, _id):
        return self.record


def make_record(filename: str) -> SimpleNamespace:
    return SimpleNamespace(
        id=1,
        filename=filename,
        file_hash="0" * 64,
        trust_score=35.0,
        threat_count=1,
        max_severity="high",
        summary="1 threat <found> & flagged",
        engines_result=[
            {"engine": "static_analysis", "score": 35, "status": "completed",
             "threats": [{"type": "Suspicious <macro>"}]},
        ],
    )


class ReportPdfTests(unittest.IsolatedAsyncioTestCase):
    async def test_markup_in_uploaded_filename_does_not_break_report(self):
        for name in ("x<y.exe", "<script>alert(1)</script>.pdf", '<img src="/etc/hostname"/>.pdf', "a & b.pdf"):
            with self.subTest(name=name):
                response = await download_report(1, db=FakeDB(make_record(name)))
                self.assertEqual(response.media_type, "application/pdf")
                self.assertTrue(response.body.startswith(b"%PDF"))


if __name__ == "__main__":
    unittest.main()

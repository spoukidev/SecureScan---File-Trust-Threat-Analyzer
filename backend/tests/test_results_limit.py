import unittest

from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.routers import reports


class ResultsLimitTests(unittest.TestCase):
    def setUp(self):
        app = FastAPI()
        app.include_router(reports.router)

        async def no_db():
            yield None  # invalid queries must be rejected before the DB is used

        app.dependency_overrides[reports.get_db] = no_db
        self.client = TestClient(app)

    def test_limit_out_of_range_is_rejected(self):
        for value in (0, -1, 101, 10**9):
            with self.subTest(limit=value):
                self.assertEqual(self.client.get(f"/results?limit={value}").status_code, 422)


if __name__ == "__main__":
    unittest.main()

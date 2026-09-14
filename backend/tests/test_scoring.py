import unittest

from app.scoring import calculate


class ScoringSeverityTests(unittest.TestCase):
    def test_critical_threat_wins_over_lower_severities(self):
        result = calculate(
            {
                "static_analysis": {
                    "max_severity": "critical",
                    "threats": [
                        {"severity": "low", "name": "minor indicator"},
                        {"severity": "critical", "name": "critical indicator"},
                        {"severity": "safe", "name": "benign indicator"},
                    ],
                }
            }
        )

        self.assertEqual(result["max_severity"], "critical")

    def test_high_threat_wins_over_medium_and_low(self):
        result = calculate(
            {
                "yara_scanner": {
                    "max_severity": "high",
                    "threats": [
                        {"severity": "medium"},
                        {"severity": "high"},
                        {"severity": "low"},
                    ],
                }
            }
        )

        self.assertEqual(result["max_severity"], "high")

    def test_unknown_severity_does_not_override_known_high_severity(self):
        result = calculate(
            {
                "sandbox": {
                    "threats": [
                        {"severity": "high"},
                        {"severity": "unexpected-value"},
                    ]
                }
            }
        )

        self.assertEqual(result["max_severity"], "high")

    def test_engine_severity_is_preserved_without_threat_records(self):
        result = calculate(
            {"hash_lookup": {"threats": [], "max_severity": "critical"}}
        )

        self.assertEqual(result["max_severity"], "critical")
        self.assertEqual(result["threat_count"], 0)
        self.assertIn("max engine severity: critical", result["summary"])

    def test_unknown_engine_severity_is_normalized(self):
        result = calculate(
            {"static_analysis": {"threats": [], "severity": "unexpected-value"}}
        )

        self.assertEqual(result["max_severity"], "unknown")
        self.assertLess(result["trust_score"], 100)

    def test_severity_normalization_handles_case_and_whitespace(self):
        result = calculate(
            {
                "static_analysis": {
                    "max_severity": " High ",
                    "threats": [{"severity": " CRITICAL ", "name": "engine finding"}],
                }
            }
        )

        self.assertEqual(result["max_severity"], "critical")
        self.assertEqual(result["engine_scores"]["static_analysis"], 55.0)
        self.assertLess(result["trust_score"], 100)

    def test_non_string_severity_is_treated_as_unknown(self):
        result = calculate(
            {"sandbox": {"threats": [{"severity": None}], "severity": 5}}
        )

        self.assertEqual(result["max_severity"], "unknown")
        self.assertLess(result["trust_score"], 100)

    def test_high_score_summary_does_not_claim_all_indicators_are_low(self):
        result = calculate(
            {
                "metadata_extractor": {
                    "severity": "safe",
                    "threats": [{"severity": "unknown", "name": "ambiguous metadata"}],
                }
            }
        )

        self.assertGreaterEqual(result["trust_score"], 90)
        self.assertIn("max severity: unknown", result["summary"])
        self.assertNotIn("all low severity", result["summary"])

    def test_no_threats_defaults_to_safe(self):
        result = calculate({"hash_lookup": {"threats": [], "severity": "safe"}})

        self.assertEqual(result["max_severity"], "safe")
        self.assertEqual(result["threat_count"], 0)


if __name__ == "__main__":
    unittest.main()

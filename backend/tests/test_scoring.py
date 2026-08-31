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

    def test_no_threats_defaults_to_safe(self):
        result = calculate({"hash_lookup": {"threats": [], "severity": "safe"}})

        self.assertEqual(result["max_severity"], "safe")
        self.assertEqual(result["threat_count"], 0)


if __name__ == "__main__":
    unittest.main()

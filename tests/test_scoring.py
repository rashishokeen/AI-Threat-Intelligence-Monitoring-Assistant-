import unittest
from datetime import date, timedelta

from src.scoring import recency_score, score_finding


class ScoringTests(unittest.TestCase):
    def setUp(self):
        self.today = date.today().isoformat()
        self.finding = {
            "severity_cvss": 8.0,
            "severity_text": "High",
            "known_exploited": False,
            "products": ["Zoom Clients"],
            "published_at": self.today,
            "evidence_quote_verified": True,
            "source_url": "https://zoom.us/security/advisory",
        }
        self.match = {"stack_match": 10.0}

    def test_complete_fixed_formula(self):
        result = score_finding(self.finding, self.match)
        self.assertEqual(result["score"], 6.7)
        self.assertFalse(result["provisional"])
        self.assertEqual(result["confidence"], "Medium")

    def test_partial_inputs_produce_medium_confidence_provisional_score(self):
        finding = {**self.finding, "severity_cvss": None, "known_exploited": None}
        result = score_finding(finding, self.match)
        self.assertEqual(result["score"], 8.9)
        self.assertTrue(result["provisional"])
        self.assertEqual(result["confidence"], "Medium")
        self.assertIn("verified primary source", result["confidence_reason"])
        self.assertIn("known-exploited status", result["missing_evidence"])

    def test_text_severity_is_estimated_when_cvss_is_absent(self):
        finding = {**self.finding, "severity_cvss": None, "known_exploited": None}
        result = score_finding(finding, self.match)
        self.assertIn("severity (estimated from category)", result["estimated_factors"])
        self.assertEqual(result["score"], 8.9)

    def test_too_few_factors_or_unverified_quote_withholds_score(self):
        finding = {
            "severity_text": "High",
            "evidence_quote_verified": True,
        }
        result = score_finding(finding, {})
        self.assertIsNone(result["score"])
        self.assertEqual(result["confidence"], "Low")
        self.assertIn("only 1 of 4", result["confidence_reason"])
        finding = {**self.finding, "evidence_quote_verified": False}
        result = score_finding(finding, self.match)
        self.assertIsNone(result["score"])
        self.assertIn("verified source evidence", result["missing_evidence"])

    def test_confidence_increases_with_distinct_primary_sources(self):
        finding = {
            **self.finding,
            "supporting_sources": [
                {"source_url": "https://www.cisa.gov/advisories/one", "products": ["Zoom"]},
                {"source_url": "https://nvd.nist.gov/vuln/detail/one", "products": ["Zoom"]},
                {"source_url": "https://news.example.org/advisory", "products": ["Zoom"]},
            ],
        }
        result = score_finding(finding, self.match)
        self.assertEqual(result["confidence"], "High")

    def test_same_domain_is_not_counted_as_multiple_sources(self):
        finding = {
            **self.finding,
            "supporting_sources": [
                {"source_url": f"https://support.zoom.us/security/{number}", "products": ["Zoom"]}
                for number in range(3)
            ],
        }
        result = score_finding(finding, self.match)
        self.assertEqual(result["source_count"], 1)
        self.assertEqual(result["confidence"], "Medium")

    def test_complete_details_from_unidentified_source_remain_low_confidence(self):
        finding = {**self.finding, "source_url": "https://example.org/advisory"}
        result = score_finding(finding, self.match)
        self.assertEqual(result["score"], 6.7)
        self.assertEqual(result["confidence"], "Low")
        self.assertIn("no primary source", result["confidence_reason"])

    def test_recency_dates_and_future_date(self):
        recent = (date.today() - timedelta(days=12)).isoformat()
        self.assertEqual(recency_score(recent), 10.0)
        us_recent = (date.today() - timedelta(days=12)).strftime("%m/%d/%Y")
        self.assertEqual(recency_score(us_recent), 10.0)
        self.assertIsNone(recency_score("not-a-date"))
        self.assertIsNone(recency_score((date.today() + timedelta(days=1)).isoformat()))


if __name__ == "__main__":
    unittest.main()

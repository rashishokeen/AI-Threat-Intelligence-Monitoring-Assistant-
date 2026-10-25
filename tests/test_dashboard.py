import unittest
from pathlib import Path

from streamlit.testing.v1 import AppTest


class DashboardTests(unittest.TestCase):
    def test_full_report_contains_extracted_finding_and_search_lead(self):
        source_url = "https://zoom.us/security/advisory"
        lead_url = "https://example.org/zoom-advisory"
        app = AppTest.from_file(str(Path(__file__).resolve().parents[1] / "app.py"), default_timeout=15)
        app.session_state["tech_stack"] = ["Zoom"]
        app.session_state["advisory_search_results"] = [
            {
                "title": "Zoom Client advisory CVE-2026-12345",
                "product": "Zoom",
                "site_name": "zoom.us",
                "snippet": "Official advisory with verified details.",
                "url": source_url,
            },
            {
                "title": "Related advisory lead",
                "product": "Zoom",
                "site_name": "Example",
                "snippet": "Search snippet only; not extracted.",
                "url": lead_url,
            },
        ]
        app.session_state["advisory_fetched_pages"] = [
            {
                "requested_url": source_url,
                "fetched_at": "2026-10-25T00:00:00+00:00",
                "text": "Zoom Client advisory CVE-2026-12345. Evidence: secure update available.",
            }
        ]
        app.session_state["advisory_fetch_errors"] = []
        app.session_state["advisory_extractions"] = {
            source_url: {
                "page_summary": "One verified advisory.",
                "advisories": [
                    {
                        "cve_id": "CVE-2026-12345",
                        "title": "Zoom Client security issue",
                        "products": ["Zoom Client"],
                        "affected_versions": ["All versions before fix"],
                        "fixed_versions": ["Updated release"],
                        "severity_cvss": 8.0,
                        "severity_text": "High",
                        "published_at": "2026-10-13",
                        "known_exploited": None,
                        "evidence_quote": "secure update available",
                        "evidence_quote_verified": True,
                        "source_url": source_url,
                    }
                ],
            }
        }

        app.run()

        self.assertEqual(len(app.exception), 0, [str(exc.value) for exc in app.exception])
        self.assertEqual(len(app.dataframe), 1)
        report = app.dataframe[0].value
        self.assertEqual(len(report), 2)
        self.assertIn("CVE-2026-12345", report["CVE"].tolist())
        extracted = report[report["CVE"] == "CVE-2026-12345"].iloc[0]
        self.assertEqual(extracted["Confidence"], "Medium")
        self.assertIn("verified primary source", extracted["Confidence basis"])
        lead = report[report["Source"] == lead_url].iloc[0]
        self.assertEqual(lead["Risk score"], "Not assessed")
        self.assertIn("Unverified search lead", lead["Evidence"])
        self.assertEqual(len(app.download_button), 1)


if __name__ == "__main__":
    unittest.main()

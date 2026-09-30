"""
SECUREASSESS - Self-Test Suite for Phase 3 LLM Gateway
Acceptance Criterion:
"Done = self-test passes with Ollama OFF (fallback path)."

Verifies:
1. JSON cleaner & repair logic on malformed LLM outputs.
2. Graceful fallback when Ollama is completely offline/unreachable.
3. Analysis finding deduplication & CVSS / SIH category classification.
4. Report agent business impact & actionable remediation synthesis.
5. Cloud LLM simulation and error degradation.
"""

import sys
import unittest
from unittest.mock import patch, MagicMock

from app.llm_client import LLMClient, clean_and_repair_json, DeterministicSecurityAnalyzer


class TestLLMClient(unittest.TestCase):
    """Test suite ensuring resilient LLM gateway behavior with zero downtime."""

    def test_json_clean_and_repair(self):
        """Verifies parsing across various common LLM output formatting anomalies."""
        # 1. Clean markdown code fence
        markdown_json = "```json\n{\"status\": \"ok\", \"findings\": []}\n```"
        res = clean_and_repair_json(markdown_json)
        self.assertEqual(res, {"status": "ok", "findings": []})

        # 2. Conversational preface and suffix chatter
        chatter_json = "Here is your requested output:\n{\"score\": 9.5}\nHope this helps!"
        res2 = clean_and_repair_json(chatter_json)
        self.assertEqual(res2, {"score": 9.5})

        # 3. Trailing commas (syntax error in standard json.loads)
        trailing_comma = '{"items": ["a", "b",], "total": 2,}'
        res3 = clean_and_repair_json(trailing_comma)
        self.assertEqual(res3, {"items": ["a", "b"], "total": 2})

    def test_ollama_off_fallback_path(self):
        """
        Core Acceptance Requirement:
        Verify pipeline succeeds when Ollama is offline (Connection refused).
        """
        # Point to a guaranteed non-existent port to simulate Ollama OFF
        client = LLMClient(
            ollama_url="http://127.0.0.1:59999",  # Offline endpoint
            use_cloud_llm=False,
            timeout_s=1.0
        )

        test_prompt = """
        Analyze and deduplicate the following raw scanner outputs:
        CANDIDATE_FINDINGS: [
            {
                "id": "CAND-001",
                "title": "Reflected Cross-Site Scripting (XSS)",
                "affected_component": "http://localhost:3000/?q=search",
                "description": "Unescaped search query reflected in HTML body.",
                "source_tool": "owasp-zap"
            },
            {
                "id": "CAND-002",
                "title": "Missing Strict-Transport-Security Header",
                "affected_component": "http://localhost:3000/",
                "description": "HSTS header is absent from server response.",
                "source_tool": "nikto"
            }
        ]
        """

        # Invocation should NOT crash; must return deterministic fallback
        result = client.generate(prompt=test_prompt, task_type="analysis")

        self.assertIn("findings", result)
        findings = result["findings"]
        self.assertGreaterEqual(len(findings), 2)

        # Verify normalized structure & CVSS assignment
        xss_finding = next(f for f in findings if "XSS" in f["title"])
        self.assertEqual(xss_finding["owasp_category"], "A03:2021-Injection")
        self.assertEqual(xss_finding["sih_scope_category"], "input validation")
        self.assertEqual(xss_finding["severity"], "High")
        self.assertGreaterEqual(xss_finding["cvss_score"], 7.0)
        self.assertIn("steps_to_reproduce", xss_finding)
        self.assertIn("remediation", xss_finding)

        hsts_finding = next(f for f in findings if "Strict-Transport" in f["title"] or "Missing" in f["title"])
        self.assertIsNotNone(hsts_finding)
        self.assertIn(hsts_finding["severity"], ["Medium", "Low", "High"])

    def test_report_impact_remediation_fallback(self):
        """Verifies report-level impact and code synthesis under fallback."""
        client = LLMClient(
            ollama_url="http://127.0.0.1:59999",
            use_cloud_llm=False,
            timeout_s=1.0
        )

        prompt = "Synthesize business impact and fix for: Cross-Site Scripting (XSS) in search parameter"
        result = client.generate(prompt=prompt, task_type="report")

        self.assertIn("business_impact", result)
        self.assertIn("remediation", result)
        self.assertIn("description", result["remediation"])
        self.assertIn("fix", result["remediation"])
        self.assertIn("example_code", result["remediation"])
        self.assertTrue(len(result["business_impact"]) > 20)
        self.assertTrue(len(result["remediation"]["example_code"]) > 5)

    @patch("httpx.Client.post")
    def test_cloud_llm_success(self, mock_post):
        """Verifies OpenAI-compatible / NVIDIA NIM endpoint routing."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "choices": [{
                "message": {
                    "content": '{"findings": [{"id": "CLOUD-001", "title": "Verified Cloud Finding"}]}'
                }
            }]
        }
        mock_post.return_value = mock_response

        client = LLMClient(
            use_cloud_llm=True,
            cloud_base_url="https://integrate.api.nvidia.com/v1",
            cloud_api_key="valid-test-key",
            timeout_s=2.0
        )

        result = client.generate("Analyze input", task_type="analysis")
        self.assertEqual(result, {"findings": [{"id": "CLOUD-001", "title": "Verified Cloud Finding"}]})

    @patch("httpx.Client.post")
    def test_cloud_llm_degradation_to_fallback(self, mock_post):
        """Verifies automatic degradation when Cloud LLM returns HTTP 500."""
        mock_response = MagicMock()
        mock_response.status_code = 500
        mock_response.raise_for_status.side_effect = Exception("Cloud 500 Internal Error")
        mock_post.return_value = mock_response

        client = LLMClient(
            use_cloud_llm=True,
            cloud_base_url="https://integrate.api.nvidia.com/v1",
            cloud_api_key="valid-test-key",
            ollama_url="http://127.0.0.1:59999",
            timeout_s=1.0
        )

        result = client.generate("Analyze input", task_type="analysis")
        # Must gracefully degrade to deterministic fallback
        self.assertIn("findings", result)
        self.assertTrue(len(result["findings"]) > 0)


if __name__ == "__main__":
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(TestLLMClient)
    runner = unittest.TextTestRunner(verbosity=2)
    res = runner.run(suite)
    sys.exit(0 if res.wasSuccessful() else 1)

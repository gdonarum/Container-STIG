"""Tests for STIG Assist Flask routes."""
import json
import os
import sys
import unittest
from unittest.mock import MagicMock, patch

# Set a dummy key so app.py doesn't exit on import
os.environ.setdefault("ANTHROPIC_API_KEY", "test-key-not-real")

# Add parent dir to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import app as stig_app


class TestRoutes(unittest.TestCase):
    def setUp(self):
        stig_app.app.config["TESTING"] = True
        self.client = stig_app.app.test_client()

    # ── /api/sample ──────────────────────────────────────────────────────────
    def test_sample_returns_xml(self):
        resp = self.client.get("/api/sample")
        self.assertEqual(resp.status_code, 200)
        data = json.loads(resp.data)
        self.assertIn("xml", data)
        self.assertIn("<?xml", data["xml"])

    # ── /api/analyze ─────────────────────────────────────────────────────────
    def test_analyze_missing_body(self):
        resp = self.client.post("/api/analyze", data="not json",
                                content_type="text/plain")
        self.assertEqual(resp.status_code, 400)

    def test_analyze_empty_findings(self):
        resp = self.client.post("/api/analyze",
                                json={"findings_text": "   "})
        self.assertEqual(resp.status_code, 400)
        data = json.loads(resp.data)
        self.assertIn("error", data)

    def test_analyze_success(self):
        fake_response_text = json.dumps({
            "summary": {
                "overall_risk": "HIGH",
                "cat1_count": 1,
                "cat2_count": 2,
                "cat3_count": 0,
                "narrative": "Test narrative."
            },
            "findings": [
                {
                    "check_id": "V-123456",
                    "severity": "CAT I",
                    "title": "Test Finding",
                    "plain_english": "This is bad.",
                    "remediation": "Fix it.",
                    "dockerfile_fix": "RUN chmod 700 /app",
                    "requires_human_judgment": False,
                    "human_judgment_note": None,
                }
            ],
            "hardened_dockerfile": "FROM ubi9\nRUN chmod 700 /app\nUSER 1001"
        })

        mock_content = MagicMock()
        mock_content.text = fake_response_text
        mock_message = MagicMock()
        mock_message.content = [mock_content]

        with patch.object(stig_app.client.messages, "create", return_value=mock_message):
            resp = self.client.post("/api/analyze",
                                    json={"findings_text": "V-123456: container runs as root"})
        self.assertEqual(resp.status_code, 200)
        data = json.loads(resp.data)
        self.assertIn("summary", data)
        self.assertIn("findings", data)
        self.assertEqual(data["summary"]["overall_risk"], "HIGH")
        self.assertEqual(len(data["findings"]), 1)

    # ── /api/harden ──────────────────────────────────────────────────────────
    def test_harden_missing_dockerfile(self):
        resp = self.client.post("/api/harden", json={"dockerfile": ""})
        self.assertEqual(resp.status_code, 400)

    def test_harden_success(self):
        fake_response_text = json.dumps({
            "hardened_dockerfile": "FROM ubi9\nUSER 1001",
            "changes": [
                {
                    "line_reference": "end of file",
                    "change_type": "ADDED",
                    "description": "Added non-root user",
                    "stig_reference": "CIS 4.1"
                }
            ],
            "warnings": []
        })

        mock_content = MagicMock()
        mock_content.text = fake_response_text
        mock_message = MagicMock()
        mock_message.content = [mock_content]

        with patch.object(stig_app.client.messages, "create", return_value=mock_message):
            resp = self.client.post("/api/harden",
                                    json={"dockerfile": "FROM ubi9\nRUN echo hello"})
        self.assertEqual(resp.status_code, 200)
        data = json.loads(resp.data)
        self.assertIn("hardened_dockerfile", data)
        self.assertIn("changes", data)

    # ── /api/poam ────────────────────────────────────────────────────────────
    def test_poam_missing_findings(self):
        resp = self.client.post("/api/poam", json={"findings_text": ""})
        self.assertEqual(resp.status_code, 400)

    def test_poam_success(self):
        fake_response_text = json.dumps({
            "poam_entries": [
                {
                    "poam_id": "POAM-001",
                    "check_id": "V-123456",
                    "weakness_name": "Container runs as root",
                    "weakness_description": "Container process runs with UID 0.",
                    "severity": "CAT I",
                    "resources_required": "Developer time to update Dockerfile",
                    "scheduled_completion_date": "LEAVE_BLANK",
                    "milestones": [
                        {
                            "milestone_number": 1,
                            "milestone_description": "Add USER instruction to Dockerfile",
                            "completion_date": "LEAVE_BLANK"
                        }
                    ],
                    "responsible_party": "Test Party",
                    "status": "Ongoing",
                    "comments": ""
                }
            ],
            "plain_text_export": "POAM-001: Container runs as root\n..."
        })

        mock_content = MagicMock()
        mock_content.text = fake_response_text
        mock_message = MagicMock()
        mock_message.content = [mock_content]

        with patch.object(stig_app.client.messages, "create", return_value=mock_message):
            resp = self.client.post("/api/poam",
                                    json={"findings_text": "CAT I: container runs as root"})
        self.assertEqual(resp.status_code, 200)
        data = json.loads(resp.data)
        self.assertIn("poam_entries", data)
        self.assertEqual(data["poam_entries"][0]["poam_id"], "POAM-001")

    # ── /api/harden-image ────────────────────────────────────────────────────
    def test_harden_image_missing_source(self):
        resp = self.client.post("/api/harden-image", json={"source_image": ""})
        self.assertEqual(resp.status_code, 400)
        data = json.loads(resp.data)
        self.assertIn("error", data)

    def test_harden_image_with_base_os_and_app(self):
        fake_response_text = json.dumps({
            "hardened_dockerfile": "FROM oraclelinux:9\n# Install Java 25\nRUN microdnf install java-25\nUSER 1001",
            "changes": [
                {
                    "line_reference": "end of file",
                    "change_type": "ADDED",
                    "description": "Switch to non-root user",
                    "stig_reference": "CIS 4.1"
                }
            ],
            "warnings": []
        })

        mock_content = MagicMock()
        mock_content.text = fake_response_text
        mock_message = MagicMock()
        mock_message.content = [mock_content]

        with patch.object(stig_app.client.messages, "create", return_value=mock_message):
            resp = self.client.post("/api/harden-image",
                                    json={"base_os": "Oracle Linux 9", "base_app": "Java 25"})
        self.assertEqual(resp.status_code, 200)
        data = json.loads(resp.data)
        self.assertIn("hardened_dockerfile", data)
        self.assertIn("changes", data)

    def test_harden_image_with_base_os_only(self):
        fake_response_text = json.dumps({
            "hardened_dockerfile": "FROM oraclelinux:9\nUSER 1001",
            "changes": [],
            "warnings": []
        })

        mock_content = MagicMock()
        mock_content.text = fake_response_text
        mock_message = MagicMock()
        mock_message.content = [mock_content]

        with patch.object(stig_app.client.messages, "create", return_value=mock_message):
            resp = self.client.post("/api/harden-image",
                                    json={"base_os": "Oracle Linux 9"})
        self.assertEqual(resp.status_code, 200)
        data = json.loads(resp.data)
        self.assertIn("hardened_dockerfile", data)

    def test_harden_image_missing_body(self):
        resp = self.client.post("/api/harden-image", data="not json",
                                content_type="text/plain")
        self.assertEqual(resp.status_code, 400)

    def test_harden_image_success(self):
        fake_response_text = json.dumps({
            "hardened_dockerfile": "FROM postgres:16\n# CIS 4.1 - run as non-root\nUSER postgres",
            "changes": [
                {
                    "line_reference": "end of file",
                    "change_type": "ADDED",
                    "description": "Switch to non-root postgres user",
                    "stig_reference": "CIS 4.1"
                }
            ],
            "warnings": []
        })

        mock_content = MagicMock()
        mock_content.text = fake_response_text
        mock_message = MagicMock()
        mock_message.content = [mock_content]

        with patch.object(stig_app.client.messages, "create", return_value=mock_message):
            resp = self.client.post("/api/harden-image",
                                    json={"source_image": "postgres:16"})
        self.assertEqual(resp.status_code, 200)
        data = json.loads(resp.data)
        self.assertIn("hardened_dockerfile", data)
        self.assertIn("changes", data)
        self.assertIn("postgres:16", data["hardened_dockerfile"])

    def test_harden_image_uses_default_stig_target(self):
        """Omitting stig_target should still succeed using the default."""
        fake_response_text = json.dumps({
            "hardened_dockerfile": "FROM nginx:alpine\nUSER 1001",
            "changes": [],
            "warnings": []
        })

        mock_content = MagicMock()
        mock_content.text = fake_response_text
        mock_message = MagicMock()
        mock_message.content = [mock_content]

        with patch.object(stig_app.client.messages, "create", return_value=mock_message):
            resp = self.client.post("/api/harden-image",
                                    json={"source_image": "nginx:alpine"})
        self.assertEqual(resp.status_code, 200)

    # ── extract_json_block helper ─────────────────────────────────────────────
    def test_extract_json_block_from_markdown(self):
        text = '```json\n{"key": "value"}\n```'
        result = stig_app.extract_json_block(text)
        self.assertEqual(result, {"key": "value"})

    def test_extract_json_block_raw(self):
        text = 'Here is the result: {"key": "value"} done.'
        result = stig_app.extract_json_block(text)
        self.assertEqual(result, {"key": "value"})

    def test_extract_json_block_invalid(self):
        with self.assertRaises(ValueError):
            stig_app.extract_json_block("no json here at all")

    # ── index page ───────────────────────────────────────────────────────────
    def test_index_returns_html(self):
        resp = self.client.get("/")
        self.assertEqual(resp.status_code, 200)
        self.assertIn(b"STIG Assist", resp.data)


if __name__ == "__main__":
    unittest.main()

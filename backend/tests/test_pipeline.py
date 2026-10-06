"""Integration test for SPAiDER core pipeline components:
1. ScopeValidator: In-scope vs out-of-scope validation
2. FindingNormalizer: Nuclei parsing + deduplication hash consistency
3. AiAnalyzer: Risk scoring formula + remediation generation
"""

import sys
import os
import unittest
from datetime import datetime, timedelta

# Add backend to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.services.scope_validator import ScopeValidator
from app.services.normalizer import compute_dedup_hash, normalize_nuclei_item, UniversalFinding
from app.services.ai_analyzer import calculate_prioritized_risk, generate_ai_analysis_for_finding
from app.models.models import Scope, Severity


class TestScopeValidator(unittest.TestCase):
    def setUp(self):
        self.scope = Scope(
            id="scp-test-001",
            name="Authorized Lab Scope",
            authorization_status="AUTHORIZED",
            targets=["http://juice-shop:3000", "192.168.1.0/24", "dvwa"],
            excluded_targets=["192.168.1.254"],
            active_testing=True,
            valid_from=datetime.utcnow() - timedelta(days=1),
            valid_until=datetime.utcnow() + timedelta(days=30),
        )

    def test_authorized_target_allowed(self):
        is_valid, reason = ScopeValidator.validate_target(self.scope, "http://juice-shop:3000")
        self.assertTrue(is_valid, f"Expected valid, got: {reason}")

    def test_cidr_target_allowed(self):
        is_valid, reason = ScopeValidator.validate_target(self.scope, "192.168.1.50")
        self.assertTrue(is_valid, f"Expected valid, got: {reason}")

    def test_excluded_target_rejected(self):
        is_valid, reason = ScopeValidator.validate_target(self.scope, "192.168.1.254")
        self.assertFalse(is_valid, "Expected exclusion to reject target")
        self.assertIn("excluded", reason.lower())

    def test_unauthorized_target_rejected(self):
        is_valid, reason = ScopeValidator.validate_target(self.scope, "https://unauthorized-bank.com")
        self.assertFalse(is_valid, "Expected out-of-scope target to be rejected")
        self.assertIn("not found in authorized targets", reason.lower())

    def test_expired_scope_rejected(self):
        expired_scope = Scope(
            id="scp-expired",
            name="Expired Scope",
            authorization_status="AUTHORIZED",
            targets=["http://juice-shop:3000"],
            active_testing=True,
            valid_until=datetime.utcnow() - timedelta(days=1),
        )
        is_valid, reason = ScopeValidator.validate_target(expired_scope, "http://juice-shop:3000")
        self.assertFalse(is_valid)
        self.assertIn("expired", reason.lower())


class TestFindingNormalizer(unittest.TestCase):
    def test_dedup_hash_deterministic(self):
        hash1 = compute_dedup_hash("juice-shop", 3000, "/api/Users", "SQL Injection")
        hash2 = compute_dedup_hash("juice-shop", 3000, "/api/Users", "SQL Injection")
        self.assertEqual(hash1, hash2)
        self.assertEqual(len(hash1), 32)  # 32 chars truncated sha256

    def test_dedup_hash_differs_on_endpoint(self):
        hash1 = compute_dedup_hash("juice-shop", 3000, "/api/Users", "SQL Injection")
        hash2 = compute_dedup_hash("juice-shop", 3000, "/api/Products", "SQL Injection")
        self.assertNotEqual(hash1, hash2)

    def test_normalize_raw_nuclei(self):
        raw = {
            "template-id": "sqli-error-based",
            "info": {
                "name": "SQL Injection in Login Endpoint",
                "severity": "critical",
                "classification": {
                    "cve-id": ["CVE-2023-1234"],
                    "cwe-id": ["CWE-89"],
                    "cvss-score": 9.8,
                },
                "reference": ["https://owasp.org/www-community/attacks/SQL_Injection"],
            },
            "host": "http://juice-shop:3000",
            "matched-at": "http://juice-shop:3000/rest/user/login",
            "type": "http",
            "extracted-results": ["SQL syntax error near 'OR 1=1'"],
            "curl-command": "curl -X POST http://juice-shop:3000/rest/user/login -d \"email=' OR 1=1--\"",
        }

        finding = normalize_nuclei_item(raw, "http://juice-shop:3000")
        self.assertIsInstance(finding, UniversalFinding)
        self.assertEqual(finding.title, "SQL Injection in Login Endpoint")
        self.assertEqual(finding.severity.lower(), "critical")
        self.assertEqual(finding.cwe, "CWE-89")
        self.assertEqual(finding.cvss, 9.8)
        self.assertIsNotNone(finding.dedup_hash)
        self.assertTrue(finding.curl_poc)


class TestAiAnalyzer(unittest.TestCase):
    def test_risk_score_calculation(self):
        score = calculate_prioritized_risk(
            severity="critical",
            cvss=9.8,
            confidence=0.9,
            asset="juice-shop-api",
            port=3000,
            is_public=True,
        )
        self.assertGreater(score, 7.0)
        self.assertLessEqual(score, 10.0)

    def test_generate_ai_analysis_for_finding(self):
        finding_dict = {
            "title": "SQL Injection in Login",
            "severity": "critical",
            "asset": "api.juice-shop",
            "port": 3000,
            "endpoint": "/rest/user/login",
            "evidence": "SQL syntax error near 'OR 1=1'",
            "curl_poc": "curl -X POST http://juice-shop:3000/rest/user/login -d \"email=' OR 1=1--\"",
            "cvss": 9.8,
            "cwe": "CWE-89",
            "confidence": 0.95,
        }

        analysis = generate_ai_analysis_for_finding(finding_dict)
        self.assertIn("risk_score", analysis)
        self.assertIn("explanation", analysis)
        self.assertIn("remediation_plan", analysis)
        self.assertIn("parameterized", analysis["remediation_plan"].lower())


if __name__ == "__main__":
    unittest.main()

"""Unit tests for Cyber-Nova Tools."""

import unittest
from cyber_nova.tools import (
    CodeAnalyzerTool, CVELookupTool, ThreatIntelTool,
    SandboxVerifierTool, RuleGeneratorTool
)


class TestTools(unittest.TestCase):
    def test_code_analyzer_sql_injection(self):
        code = (
            "import sqlite3\n"
            "def query_db(uid):\n"
            "    conn = sqlite3.connect('test.db')\n"
            "    c = conn.cursor()\n"
            "    q = f\"SELECT * FROM users WHERE id = '{uid}'\"\n"
            "    c.execute(q)\n"
        )
        tool = CodeAnalyzerTool()
        res = tool.run(code=code, file_name="db.py")
        self.assertTrue(res["success"])
        data = res["data"]
        self.assertTrue(any(f["cwe"] == "CWE-89" for f in data["findings"]))
        self.assertTrue(data["has_critical_vulnerabilities"])

    def test_code_analyzer_command_injection(self):
        code = (
            "import subprocess\n"
            "def ping(host):\n"
            "    return subprocess.check_output(f'ping -c 1 {host}', shell=True)\n"
        )
        tool = CodeAnalyzerTool()
        res = tool.run(code=code, file_name="ping.py")
        self.assertTrue(res["success"])
        data = res["data"]
        self.assertTrue(any(f["cwe"] == "CWE-78" for f in data["findings"]))

    def test_cve_lookup_and_cvss(self):
        tool = CVELookupTool()
        res = tool.run(query="SQL injection", cwe_id="CWE-89")
        self.assertTrue(res["success"])
        data = res["data"]
        self.assertGreaterEqual(data["matches_found"], 1)
        self.assertEqual(data["primary_match"]["cwe_id"], "CWE-89")
        self.assertGreaterEqual(data["primary_match"]["cvss_score"], 9.0)

        # Test CVSS calculation
        score = CVELookupTool.compute_cvss_score(
            av="N", ac="L", pr="N", ui="N", s="U", c="H", i="H", a="H"
        )
        self.assertAlmostEqual(score, 9.8, places=1)

    def test_threat_intel_ioc_extraction(self):
        logs = (
            "198.51.100.42 - GET /api/v1/orders?id=101' OR 1=1 -- HTTP/1.1 200\n"
            "Alert: Outbound request to 169.254.169.254 (CVE-2024-21626)\n"
        )
        tool = ThreatIntelTool()
        res = tool.run(telemetry_text=logs, cwe_id="CWE-89")
        self.assertTrue(res["success"])
        data = res["data"]
        self.assertGreaterEqual(data["extracted_iocs_count"], 2)
        ioc_values = [i["value"] for i in data["iocs"]]
        self.assertIn("198.51.100.42", ioc_values)
        self.assertIn("169.254.169.254", ioc_values)
        self.assertTrue(any(t["technique_id"] == "T1190" for t in data["mitre_techniques"]))

    def test_sandbox_verifier(self):
        orig_code = "cursor.execute(f'SELECT * FROM users WHERE id = {uid}')"
        patched_code = "cursor.execute('SELECT * FROM users WHERE id = ?', (uid,))"
        tool = SandboxVerifierTool()
        res = tool.run(
            original_code=orig_code,
            patched_code=patched_code,
            exploit_payload="' OR 1=1 --",
            normal_payload="42",
            vulnerability_type="SQL_INJECTION"
        )
        self.assertTrue(res["success"])
        data = res["data"]
        self.assertTrue(data["exploit_blocked"])
        self.assertTrue(data["regression_tests_passed"])

    def test_rule_generator(self):
        tool = RuleGeneratorTool()
        res = tool.run(
            vulnerability_type="SQL_INJECTION",
            incident_id="INC-TEST-99",
            target_endpoint="/api/orders"
        )
        self.assertTrue(res["success"])
        data = res["data"]
        rules = data["rules"]
        self.assertEqual(len(rules), 3)
        rule_types = {r["rule_type"] for r in rules}
        self.assertEqual(rule_types, {"WAF", "YARA", "SIGMA"})


if __name__ == "__main__":
    unittest.main()

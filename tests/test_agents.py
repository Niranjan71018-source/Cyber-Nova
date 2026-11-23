"""Unit tests for Cyber-Nova Agents and Orchestration."""

import unittest
from cyber_nova.models import Incident, IncidentSeverity, IncidentStatus, AgentRole
from cyber_nova.orchestrator import Orchestrator
from cyber_nova.scenarios.presets import get_scenario_presets


class TestAgentsAndOrchestration(unittest.TestCase):
    def test_full_pipeline_sql_injection(self):
        orc = Orchestrator()
        orc.load_preset("sql_injection_portal")
        results = orc.run_all()

        inc = orc.blackboard.incident
        self.assertEqual(inc.status, IncidentStatus.RESOLVED)
        self.assertGreaterEqual(len(inc.iocs), 1)
        self.assertGreaterEqual(len(inc.vulnerabilities), 1)
        self.assertGreaterEqual(len(inc.patches), 1)
        self.assertIsNotNone(inc.verification)
        self.assertTrue(inc.verification.success)
        self.assertEqual(len(inc.defense_rules), 3)
        self.assertIsNotNone(inc.audit_report)
        self.assertTrue(inc.audit_report.auditor_signature.startswith("CN-SEAL-"))

    def test_all_preset_scenarios_reach_resolution(self):
        presets = get_scenario_presets()
        for key in presets:
            orc = Orchestrator()
            orc.load_preset(key)
            results = orc.run_all()
            inc = orc.blackboard.incident

            self.assertEqual(
                inc.status, IncidentStatus.RESOLVED,
                f"Scenario '{key}' did not reach RESOLVED state (got {inc.status})"
            )
            self.assertTrue(inc.verification.success)
            self.assertGreaterEqual(len(inc.defense_rules), 1)

    def test_step_by_step_execution(self):
        orc = Orchestrator()
        orc.load_preset("command_injection_diagnostics")

        # Step 1: Sentinel Triage
        step1 = orc.step()
        self.assertIsNotNone(step1)
        self.assertEqual(step1["role"], "sentinel")
        self.assertEqual(orc.blackboard.incident.status, IncidentStatus.TRIAGED)

        # Step 2: Investigator Forensic Analysis
        step2 = orc.step()
        self.assertIsNotNone(step2)
        self.assertEqual(step2["role"], "investigator")
        self.assertEqual(orc.blackboard.incident.status, IncidentStatus.INVESTIGATING)

        # Step 3: Remediation Patch Synthesis & Sandbox Verification
        step3 = orc.step()
        self.assertIsNotNone(step3)
        self.assertEqual(step3["role"], "remediation")

        # Step 4: Auditor Compliance & Sign-Off
        step4 = orc.step()
        self.assertIsNotNone(step4)
        self.assertEqual(step4["role"], "auditor")
        self.assertEqual(orc.blackboard.incident.status, IncidentStatus.RESOLVED)

        # No more runnable tasks
        step5 = orc.step()
        self.assertIsNone(step5)


if __name__ == "__main__":
    unittest.main()

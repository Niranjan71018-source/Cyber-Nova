"""Unit tests for Cyber-Nova Blackboard and State Store."""

import unittest
from cyber_nova.models import (
    Incident, IncidentStatus, IncidentSeverity,
    Task, TaskStatus, AgentRole, IOC, VulnerabilityFinding
)
from cyber_nova.blackboard import Blackboard


class TestBlackboard(unittest.TestCase):
    def setUp(self):
        self.incident = Incident(
            id="INC-TEST-01",
            title="Test Incident",
            description="Testing state storage",
            severity=IncidentSeverity.HIGH
        )
        self.blackboard = Blackboard(self.incident)

    def test_status_update(self):
        self.assertEqual(self.blackboard.incident.status, IncidentStatus.NEW)
        self.blackboard.update_status(IncidentStatus.TRIAGED)
        self.assertEqual(self.blackboard.incident.status, IncidentStatus.TRIAGED)

    def test_kanban_task_management(self):
        task1 = Task(
            id="TASK-01",
            title="Initial Triage",
            description="Parse logs",
            assigned_to=AgentRole.SENTINEL
        )
        self.blackboard.add_task(task1)
        self.assertIn("TASK-01", self.blackboard.incident.tasks)

        # Update task
        updated = self.blackboard.update_task_status("TASK-01", TaskStatus.DONE, "Logs parsed successfully")
        self.assertIsNotNone(updated)
        self.assertEqual(updated.status, TaskStatus.DONE)
        self.assertIsNotNone(updated.completed_at)

    def test_inter_agent_messaging(self):
        msg = self.blackboard.post_message(
            sender="Sentinel-01",
            recipient="Investigator-02",
            content="Evidence handed over"
        )
        self.assertEqual(len(self.blackboard.messages), 1)
        self.assertEqual(self.blackboard.messages[0].sender, "Sentinel-01")

        # Query messages
        recvd = self.blackboard.get_messages(recipient="Investigator-02")
        self.assertEqual(len(recvd), 1)

    def test_ioc_and_vulnerability_deduplication(self):
        ioc1 = IOC(ioc_type="ipv4", value="198.51.100.42", context="C2 IP")
        ioc2 = IOC(ioc_type="ipv4", value="198.51.100.42", context="C2 IP Duplicate")
        self.blackboard.add_ioc(ioc1)
        self.blackboard.add_ioc(ioc2)
        self.assertEqual(len(self.blackboard.incident.iocs), 1)

    def test_state_snapshot(self):
        snapshot = self.blackboard.get_state_snapshot()
        self.assertIn("incident", snapshot)
        self.assertIn("messages", snapshot)
        self.assertIn("metrics", snapshot)
        self.assertEqual(snapshot["incident"]["id"], "INC-TEST-01")


if __name__ == "__main__":
    unittest.main()

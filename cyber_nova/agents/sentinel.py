"""Sentinel Agent: Triage, log ingestion, and IOC extraction."""

import uuid
from typing import Dict, Any, Optional
from ..models import AgentRole, Task, TaskStatus, IncidentStatus, IncidentSeverity, IOC, MessageType
from .base import BaseAgent
from ..blackboard import Blackboard
from ..tools.base import BaseTool


class SentinelAgent(BaseAgent):
    """Monitors telemetry feeds, parses alerts, extracts IOCs, and dispatches investigations."""

    role = AgentRole.SENTINEL
    name = "Sentinel-01"
    description = "Triages incoming telemetry alerts, extracts IOCs, and initializes incident workflow."

    def __init__(self, blackboard: Blackboard, tools: Optional[Dict[str, BaseTool]] = None):
        super().__init__(blackboard, tools)

    def act(self, task: Task) -> Dict[str, Any]:
        self.set_status("ANALYZING")
        self.blackboard.update_task_status(task.id, TaskStatus.IN_PROGRESS)

        inc = self.blackboard.incident
        telemetry_raw = "\n".join(inc.telemetry_logs)

        self.think(
            f"Reviewing incoming alert telemetry for incident {inc.id}. "
            f"Parsing {len(inc.telemetry_logs)} log lines to detect active attack signatures and IOCs."
        )

        # 1. Use Threat Intel tool to parse IOCs and initial attack indicators
        intel_result = self.call_tool(
            "threat_intel_enricher",
            telemetry_text=telemetry_raw,
            cwe_id=""
        )

        extracted_iocs = []
        if intel_result.get("success") and intel_result.get("data"):
            data = intel_result["data"]
            for ioc_dict in data.get("iocs", []):
                ioc_obj = IOC(
                    ioc_type=ioc_dict.get("type", "unknown"),
                    value=ioc_dict.get("value", ""),
                    context=ioc_dict.get("context", ""),
                    reputation_score=ioc_dict.get("reputation_score", 0.5)
                )
                self.blackboard.add_ioc(ioc_obj)
                extracted_iocs.append(ioc_obj)

        self.think(
            f"Extracted {len(extracted_iocs)} distinct IOCs. "
            f"Observed threat level: {intel_result.get('data', {}).get('threat_level', 'HIGH')}."
        )

        # 2. Upgrade incident severity if critical IOCs or attack vectors found
        if any(ioc.reputation_score >= 0.85 for ioc in extracted_iocs):
            inc.severity = IncidentSeverity.CRITICAL
        else:
            inc.severity = IncidentSeverity.HIGH

        self.blackboard.update_status(IncidentStatus.TRIAGED)

        # 3. Create follow-up tasks for InvestigatorAgent on Kanban board
        investigate_task = Task(
            id=f"TASK-INV-{uuid.uuid4().hex[:6]}",
            title="Investigate Root Cause & Code Vulnerability",
            description="Perform AST static analysis and pattern matching on affected source modules.",
            assigned_to=AgentRole.INVESTIGATOR,
            dependencies=[task.id]
        )
        self.blackboard.add_task(investigate_task)

        # 4. Handoff to Investigator
        summary = (
            f"Triage complete for {inc.id}. Severity rated {inc.severity.value}. "
            f"{len(extracted_iocs)} IOCs indexed. Dispatched root-cause investigation task {investigate_task.id}."
        )

        self.send_message(
            recipient="investigator",
            content=f"Sentinel handoff: Incident {inc.id} triaged as {inc.severity.value}. "
                    f"Passing evidence to InvestigatorAgent.",
            msg_type=MessageType.HANDOFF,
            metadata={"task_id": investigate_task.id, "ioc_count": len(extracted_iocs)}
        )

        self.blackboard.update_task_status(task.id, TaskStatus.DONE, result_summary=summary)
        self.set_status("COMPLETE")

        return {
            "status": "TRIAGED",
            "ioc_count": len(extracted_iocs),
            "next_task_id": investigate_task.id
        }

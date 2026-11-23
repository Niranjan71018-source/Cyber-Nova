"""Central Blackboard, Event Dispatcher, and Shared State Store for Cyber-Nova."""

import asyncio
import time
from typing import Dict, List, Optional, Any, Callable
from .models import (
    Incident, IncidentStatus, IncidentSeverity, Task, TaskStatus,
    AgentRole, AgentMessage, MessageType, ToolExecution,
    IOC, VulnerabilityFinding, PatchProposal, VerificationResult,
    DefenseRule, AuditReport
)


class Blackboard:
    """Central collaborative state store and event bus for all agents."""

    def __init__(self, incident: Optional[Incident] = None):
        self.incident: Incident = incident or Incident(
            id="INC-DEFAULT",
            title="Uninitialized Incident",
            description="Awaiting incident telemetry ingestion"
        )
        self.messages: List[AgentMessage] = []
        self.tool_executions: List[ToolExecution] = []
        self.listeners: List[Callable[[Dict[str, Any]], Any]] = []
        try:
            loop = asyncio.get_running_loop()
            self._lock = asyncio.Lock()
        except RuntimeError:
            self._lock = None

    def subscribe(self, listener: Callable[[Dict[str, Any]], Any]) -> None:
        """Register a callback for real-time state change events."""
        if listener not in self.listeners:
            self.listeners.append(listener)

    def unsubscribe(self, listener: Callable[[Dict[str, Any]], Any]) -> None:
        """Unregister an event listener."""
        if listener in self.listeners:
            self.listeners.remove(listener)

    def emit_event(self, event_type: str, payload: Dict[str, Any]) -> None:
        """Broadcast an event to all subscribers."""
        event = {
            "type": event_type,
            "timestamp": time.time(),
            "incident_id": self.incident.id,
            "data": payload
        }
        for listener in list(self.listeners):
            try:
                res = listener(event)
                # If listener returned an awaitable coroutine, schedule it
                if asyncio.iscoroutine(res):
                    try:
                        loop = asyncio.get_running_loop()
                        asyncio.create_task(res)
                    except RuntimeError:
                        pass
            except Exception as e:
                print(f"[Blackboard] Error dispatching event to listener: {e}")

    # ================= Incident & Lifecycle =================

    def set_incident(self, incident: Incident) -> None:
        self.incident = incident
        self.emit_event("incident_initialized", incident.to_dict())

    def update_status(self, status: IncidentStatus) -> None:
        old_status = self.incident.status
        self.incident.status = status
        self.incident.updated_at = time.time()
        self.emit_event("status_changed", {
            "from": old_status.value,
            "to": status.value
        })

    # ================= Task Management (Kanban) =================

    def add_task(self, task: Task) -> None:
        self.incident.tasks[task.id] = task
        self.emit_event("task_created", task.to_dict())

    def update_task_status(
        self,
        task_id: str,
        status: TaskStatus,
        result_summary: str = ""
    ) -> Optional[Task]:
        task = self.incident.tasks.get(task_id)
        if not task:
            return None
        task.status = status
        if result_summary:
            task.result_summary = result_summary
        if status in (TaskStatus.DONE, TaskStatus.FAILED):
            task.completed_at = time.time()
        self.emit_event("task_updated", task.to_dict())
        return task

    def get_tasks_for_agent(self, role: AgentRole) -> List[Task]:
        return [t for t in self.incident.tasks.values() if t.assigned_to == role]

    # ================= Inter-Agent Messaging =================

    def post_message(
        self,
        sender: str,
        recipient: str = "broadcast",
        msg_type: MessageType = MessageType.THOUGHT,
        content: str = "",
        metadata: Optional[Dict[str, Any]] = None
    ) -> AgentMessage:
        msg = AgentMessage(
            sender=sender,
            recipient=recipient,
            msg_type=msg_type,
            content=content,
            metadata=metadata or {}
        )
        self.messages.append(msg)
        self.emit_event("message_posted", msg.to_dict())
        return msg

    def get_messages(
        self,
        recipient: Optional[str] = None,
        limit: int = 100
    ) -> List[AgentMessage]:
        if recipient:
            msgs = [m for m in self.messages if m.recipient in (recipient, "broadcast")]
        else:
            msgs = self.messages
        return msgs[-limit:]

    # ================= Tool Executions =================

    def record_tool_execution(
        self,
        tool_name: str,
        agent_name: str,
        arguments: Dict[str, Any],
        result: Any,
        success: bool = True,
        duration_ms: float = 0.0
    ) -> ToolExecution:
        execution = ToolExecution(
            tool_name=tool_name,
            agent_name=agent_name,
            arguments=arguments,
            result=result,
            success=success,
            duration_ms=duration_ms
        )
        self.tool_executions.append(execution)
        self.emit_event("tool_executed", execution.to_dict())
        return execution

    # ================= Artifact Management =================

    def add_ioc(self, ioc: IOC) -> None:
        # Check if IOC already exists
        if not any(i.value == ioc.value and i.ioc_type == ioc.ioc_type for i in self.incident.iocs):
            self.incident.iocs.append(ioc)
            self.emit_event("ioc_added", ioc.to_dict())

    def add_vulnerability(self, vuln: VulnerabilityFinding) -> None:
        if not any(v.id == vuln.id for v in self.incident.vulnerabilities):
            self.incident.vulnerabilities.append(vuln)
            self.emit_event("vulnerability_added", vuln.to_dict())

    def add_patch(self, patch: PatchProposal) -> None:
        self.incident.patches.append(patch)
        self.emit_event("patch_added", patch.to_dict())

    def set_verification(self, verification: VerificationResult) -> None:
        self.incident.verification = verification
        self.emit_event("verification_completed", verification.to_dict())

    def add_defense_rule(self, rule: DefenseRule) -> None:
        self.incident.defense_rules.append(rule)
        self.emit_event("defense_rule_added", rule.to_dict())

    def set_audit_report(self, report: AuditReport) -> None:
        self.incident.audit_report = report
        self.emit_event("audit_completed", report.to_dict())

    # ================= Snapshots & Reporting =================

    def get_state_snapshot(self) -> Dict[str, Any]:
        """Produce full JSON-serializable state representing incident, agents, and artifacts."""
        return {
            "incident": self.incident.to_dict(),
            "messages": [m.to_dict() for m in self.messages],
            "tool_executions": [t.to_dict() for t in self.tool_executions[-25:]],
            "metrics": {
                "total_messages": len(self.messages),
                "total_tool_calls": len(self.tool_executions),
                "total_iocs": len(self.incident.iocs),
                "total_vulnerabilities": len(self.incident.vulnerabilities),
                "total_tasks": len(self.incident.tasks),
                "tasks_done": sum(1 for t in self.incident.tasks.values() if t.status == TaskStatus.DONE),
                "verification_passed": self.incident.verification.success if self.incident.verification else False,
            }
        }

    def export_markdown_report(self) -> str:
        """Export a comprehensive Markdown Incident Response Dossier."""
        inc = self.incident
        lines = [
            f"# Cyber-Nova Incident Response Dossier: {inc.id}",
            f"**Title**: {inc.title}",
            f"**Severity**: `{inc.severity.value}` | **Status**: `{inc.status.value}`",
            f"**Generated**: {time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime(inc.updated_at))}",
            "",
            "## 1. Executive Summary",
            inc.audit_report.executive_summary if inc.audit_report else inc.description,
            "",
            "## 2. Identified Vulnerabilities",
        ]

        if not inc.vulnerabilities:
            lines.append("*(No vulnerabilities registered)*")
        else:
            for v in inc.vulnerabilities:
                lines.extend([
                    f"### {v.name} ({v.cwe_id})",
                    f"- **CVSS v3.1 Score**: `{v.cvss_score}` ({v.cvss_vector})",
                    f"- **Location**: `{v.file_path}:{v.line_number}`",
                    f"- **Description**: {v.description}",
                    "```python",
                    v.code_snippet,
                    "```",
                    ""
                ])

        lines.extend([
            "## 3. Indicators of Compromise (IOCs)",
            "| Type | Value | Reputation | Context |",
            "|---|---|---|---|"
        ])
        for ioc in inc.iocs:
            lines.append(f"| `{ioc.ioc_type}` | `{ioc.value}` | {ioc.reputation_score * 100:.0f}% Malicious | {ioc.context} |")

        lines.extend([
            "",
            "## 4. Remediation Patch",
        ])
        if inc.patches:
            p = inc.patches[-1]
            lines.extend([
                f"**Author**: {p.author_agent} | **Target File**: `{p.target_file}`",
                f"**Explanation**: {p.explanation}",
                "```diff",
                p.diff,
                "```",
                ""
            ])
        else:
            lines.append("*(No patches generated yet)*")

        lines.extend([
            "## 5. Automated Sandbox Verification",
        ])
        if inc.verification:
            v = inc.verification
            lines.extend([
                f"- **Overall Verdict**: `{'SUCCESS - PASSED' if v.success else 'FAILED'}`",
                f"- **Exploit Blocked**: `{'YES' if v.exploit_blocked else 'NO'}`",
                f"- **Regression Tests**: `{'PASSED' if v.regression_tests_passed else 'FAILED'}`",
                f"- **Execution Time**: {v.execution_time_ms} ms",
                "",
                "### Test Execution Logs",
                "```text",
                "\n".join(v.logs),
                "```"
            ])
        else:
            lines.append("*(Verification pending)*")

        lines.extend([
            "",
            "## 6. Generated Defensive Rules",
        ])
        for rule in inc.defense_rules:
            lines.extend([
                f"### {rule.title} ({rule.rule_type})",
                f"**Target System**: {rule.target_system}",
                "```text",
                rule.rule_content,
                "```",
                ""
            ])

        lines.extend([
            "## 7. Compliance Matrix & Sign-Off",
        ])
        if inc.audit_report:
            rep = inc.audit_report
            for fw, st in rep.compliance_status.items():
                lines.append(f"- **{fw}**: `{st}`")
            lines.extend([
                "",
                f"**Auditor Signature**: `{rep.auditor_signature}`",
                f"**Sign-off Timestamp**: {time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime(rep.signoff_timestamp))}"
            ])

        return "\n".join(lines)

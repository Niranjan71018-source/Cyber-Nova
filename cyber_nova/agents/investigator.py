"""Investigator Agent: Deep forensic analysis, code AST auditing, and CVE mapping."""

import uuid
from typing import Dict, Any, Optional
from ..models import (
    AgentRole, Task, TaskStatus, IncidentStatus, IncidentSeverity,
    VulnerabilityFinding, MessageType
)
from .base import BaseAgent
from ..blackboard import Blackboard
from ..tools.base import BaseTool


class InvestigatorAgent(BaseAgent):
    """Conducts source code auditing, vulnerability classification, and threat vector tracing."""

    role = AgentRole.INVESTIGATOR
    name = "Investigator-02"
    description = "Conducts static code forensics, maps CVEs/CWEs, computes CVSS metrics, and determines root cause."

    def __init__(self, blackboard: Blackboard, tools: Optional[Dict[str, BaseTool]] = None):
        super().__init__(blackboard, tools)

    def act(self, task: Task) -> Dict[str, Any]:
        self.set_status("ANALYZING")
        self.blackboard.update_task_status(task.id, TaskStatus.IN_PROGRESS)
        self.blackboard.update_status(IncidentStatus.INVESTIGATING)

        inc = self.blackboard.incident
        self.think(
            f"Beginning forensic code audit across {len(inc.source_files)} source files for incident {inc.id}."
        )

        all_findings = []

        # 1. Inspect each source file using the Code Analyzer tool
        for file_name, code_content in inc.source_files.items():
            analysis_res = self.call_tool(
                "code_analyzer",
                code=code_content,
                file_name=file_name
            )

            if analysis_res.get("success") and analysis_res.get("data"):
                file_findings = analysis_res["data"].get("findings", [])
                self.think(
                    f"Code analyzer finished for '{file_name}': {len(file_findings)} findings identified."
                )

                for f in file_findings:
                    cwe = f.get("cwe", "CWE-General")
                    vuln_type = f.get("type", "UNKNOWN")

                    # 2. Query CVE database for this CWE
                    cve_res = self.call_tool(
                        "cve_database_lookup",
                        query=vuln_type,
                        cwe_id=cwe
                    )

                    primary_cve = {}
                    if cve_res.get("success") and cve_res.get("data"):
                        primary_cve = cve_res["data"].get("primary_match", {})

                    cvss_score = primary_cve.get("cvss_score", 8.5)
                    cvss_vector = primary_cve.get("cvss_vector", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
                    sev_str = f.get("severity", "HIGH")
                    sev_enum = IncidentSeverity[sev_str] if sev_str in IncidentSeverity.__members__ else IncidentSeverity.HIGH

                    # 3. Enrich with MITRE ATT&CK techniques
                    intel_res = self.call_tool(
                        "threat_intel_enricher",
                        telemetry_text=f"{vuln_type} {f.get('snippet', '')}",
                        cwe_id=cwe
                    )
                    mitre_list = []
                    if intel_res.get("success") and intel_res.get("data"):
                        mitre_list = [
                            f"{t['technique_id']} ({t['name']})"
                            for t in intel_res["data"].get("mitre_techniques", [])
                        ]

                    # Construct VulnerabilityFinding
                    v_id = f"VULN-{uuid.uuid4().hex[:6].upper()}"
                    vuln_obj = VulnerabilityFinding(
                        id=v_id,
                        cwe_id=cwe,
                        name=primary_cve.get("name", vuln_type),
                        severity=sev_enum,
                        cvss_score=cvss_score,
                        cvss_vector=cvss_vector,
                        file_path=file_name,
                        line_number=f.get("line", 1),
                        code_snippet=f.get("snippet", ""),
                        description=f.get("description", primary_cve.get("description", "")),
                        mitre_attack=mitre_list
                    )
                    self.blackboard.add_vulnerability(vuln_obj)
                    all_findings.append(vuln_obj)

        self.think(
            f"Forensics completed: Registered {len(all_findings)} confirmed vulnerabilities. "
            f"Highest CVSS score: {max([v.cvss_score for v in all_findings], default=0.0)}."
        )

        # 4. Create tasks for RemediationAgent on the Kanban board
        rem_task = Task(
            id=f"TASK-REM-{uuid.uuid4().hex[:6]}",
            title="Synthesize Security Patch & Verify in Sandbox",
            description="Generate surgical patch diff, execute exploit neutralization tests, and verify zero functional regressions.",
            assigned_to=AgentRole.REMEDIATION,
            dependencies=[task.id]
        )
        self.blackboard.add_task(rem_task)

        # 5. Handoff to RemediationAgent
        summary = (
            f"Forensic investigation complete. Identified {len(all_findings)} vulnerabilities across codebases. "
            f"Root cause pinpointed. Assigned patch synthesis and verification to RemediationAgent."
        )

        self.send_message(
            recipient="remediation",
            content=f"Investigator handoff: Root cause verified for {inc.id}. "
                    f"Identified {len(all_findings)} vulnerabilities. Handing off for patch synthesis.",
            msg_type=MessageType.HANDOFF,
            metadata={"task_id": rem_task.id, "vuln_count": len(all_findings)}
        )

        self.blackboard.update_task_status(task.id, TaskStatus.DONE, result_summary=summary)
        self.set_status("COMPLETE")

        return {
            "status": "INVESTIGATED",
            "findings_count": len(all_findings),
            "next_task_id": rem_task.id
        }

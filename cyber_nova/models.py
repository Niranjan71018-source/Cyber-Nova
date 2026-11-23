"""Data models for Cyber-Nova multi-agent cybersecurity operations platform."""

from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Dict, List, Optional, Any
import time
import uuid


class IncidentSeverity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class IncidentStatus(str, Enum):
    NEW = "NEW"
    TRIAGED = "TRIAGED"
    INVESTIGATING = "INVESTIGATING"
    PATCHING = "PATCHING"
    VERIFYING = "VERIFYING"
    AUDITING = "AUDITING"
    RESOLVED = "RESOLVED"
    FAILED = "FAILED"


class TaskStatus(str, Enum):
    TODO = "TODO"
    IN_PROGRESS = "IN_PROGRESS"
    VERIFYING = "VERIFYING"
    DONE = "DONE"
    FAILED = "FAILED"


class AgentRole(str, Enum):
    SENTINEL = "sentinel"
    INVESTIGATOR = "investigator"
    REMEDIATION = "remediation"
    AUDITOR = "auditor"


class MessageType(str, Enum):
    THOUGHT = "THOUGHT"
    TOOL_CALL = "TOOL_CALL"
    TOOL_RESULT = "TOOL_RESULT"
    HANDOFF = "HANDOFF"
    TASK_UPDATE = "TASK_UPDATE"
    QUERY = "QUERY"
    RESPONSE = "RESPONSE"
    AUDIT_SIGNOFF = "AUDIT_SIGNOFF"


@dataclass
class IOC:
    """Indicator of Compromise."""
    ioc_type: str  # "ip", "domain", "hash", "cve", "url", "user_agent"
    value: str
    context: str = ""
    reputation_score: float = 0.0  # 0.0 (safe) to 1.0 (malicious)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class VulnerabilityFinding:
    """A verified security flaw identified by InvestigatorAgent."""
    id: str
    cwe_id: str
    name: str
    severity: IncidentSeverity
    cvss_score: float
    cvss_vector: str
    file_path: str
    line_number: int
    code_snippet: str
    description: str
    mitre_attack: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["severity"] = self.severity.value
        return d


@dataclass
class PatchProposal:
    """A proposed patch code diff synthesized by RemediationAgent."""
    id: str
    target_file: str
    original_code: str
    patched_code: str
    diff: str
    explanation: str
    author_agent: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class VerificationResult:
    """Result from automated sandbox regression & exploit testing."""
    success: bool
    exploit_blocked: bool
    regression_tests_passed: bool
    execution_time_ms: float
    logs: List[str] = field(default_factory=list)
    test_details: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class DefenseRule:
    """Generated defensive rule (WAF, YARA, SIGMA)."""
    rule_type: str  # "WAF", "YARA", "SIGMA"
    title: str
    rule_content: str
    target_system: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class AuditReport:
    """Final executive post-mortem and compliance audit."""
    incident_id: str
    executive_summary: str
    technical_postmortem: str
    compliance_status: Dict[str, str]  # Framework -> status (e.g. NIST: COMPLIANT)
    recommended_actions: List[str]
    signoff_timestamp: float
    auditor_signature: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class AgentMessage:
    """Message exchanged or broadcast on the blackboard."""
    id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])
    sender: str = ""
    recipient: str = "broadcast"
    msg_type: MessageType = MessageType.THOUGHT
    content: str = ""
    timestamp: float = field(default_factory=time.time)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["msg_type"] = self.msg_type.value
        return d


@dataclass
class Task:
    """A discrete unit of work tracked on the collaborative Kanban board."""
    id: str
    title: str
    description: str
    assigned_to: AgentRole
    status: TaskStatus = TaskStatus.TODO
    dependencies: List[str] = field(default_factory=list)
    created_at: float = field(default_factory=time.time)
    completed_at: Optional[float] = None
    result_summary: str = ""

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["assigned_to"] = self.assigned_to.value
        d["status"] = self.status.value
        return d


@dataclass
class ToolExecution:
    """Record of a tool invocation by an agent."""
    id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])
    tool_name: str = ""
    agent_name: str = ""
    arguments: Dict[str, Any] = field(default_factory=dict)
    result: Any = None
    success: bool = True
    duration_ms: float = 0.0
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class Incident:
    """The central incident case file tracked across all agents."""
    id: str
    title: str
    description: str
    severity: IncidentSeverity = IncidentSeverity.HIGH
    status: IncidentStatus = IncidentStatus.NEW
    created_at: float = field(default_factory=time.time)
    updated_at: float = field(default_factory=time.time)
    telemetry_logs: List[str] = field(default_factory=list)
    source_files: Dict[str, str] = field(default_factory=dict)
    iocs: List[IOC] = field(default_factory=list)
    vulnerabilities: List[VulnerabilityFinding] = field(default_factory=list)
    tasks: Dict[str, Task] = field(default_factory=dict)
    patches: List[PatchProposal] = field(default_factory=list)
    verification: Optional[VerificationResult] = None
    defense_rules: List[DefenseRule] = field(default_factory=list)
    audit_report: Optional[AuditReport] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "title": self.title,
            "description": self.description,
            "severity": self.severity.value,
            "status": self.status.value,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "telemetry_logs": self.telemetry_logs,
            "source_files": list(self.source_files.keys()),
            "iocs": [i.to_dict() for i in self.iocs],
            "vulnerabilities": [v.to_dict() for v in self.vulnerabilities],
            "tasks": {tid: t.to_dict() for tid, t in self.tasks.items()},
            "patches": [p.to_dict() for p in self.patches],
            "verification": self.verification.to_dict() if self.verification else None,
            "defense_rules": [r.to_dict() for r in self.defense_rules],
            "audit_report": self.audit_report.to_dict() if self.audit_report else None,
        }

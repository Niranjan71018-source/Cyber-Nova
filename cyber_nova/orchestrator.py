"""Cyber-Nova Orchestrator: Multi-Agent Coordinator and Workflow Engine."""

import asyncio
import time
from typing import Dict, Any, Optional, List
from .models import Incident, IncidentStatus, Task, TaskStatus, AgentRole
from .blackboard import Blackboard
from .tools import (
    CodeAnalyzerTool, CVELookupTool, ThreatIntelTool,
    SandboxVerifierTool, RuleGeneratorTool, BaseTool
)
from .agents import (
    SentinelAgent, InvestigatorAgent, RemediationAgent, AuditorAgent, BaseAgent
)
from .scenarios.presets import create_incident_from_preset


class Orchestrator:
    """Coordinates agent execution, tool dispatch, and state flow across the security incident lifecycle."""

    def __init__(self, incident: Optional[Incident] = None):
        self.blackboard = Blackboard(incident)
        self.tools: Dict[str, BaseTool] = self._init_tools()
        self.agents: Dict[AgentRole, BaseAgent] = self._init_agents()
        self.is_running = False

    def _init_tools(self) -> Dict[str, BaseTool]:
        tools = [
            CodeAnalyzerTool(),
            CVELookupTool(),
            ThreatIntelTool(),
            SandboxVerifierTool(),
            RuleGeneratorTool()
        ]
        return {t.name: t for t in tools}

    def _init_agents(self) -> Dict[AgentRole, BaseAgent]:
        return {
            AgentRole.SENTINEL: SentinelAgent(self.blackboard, self.tools),
            AgentRole.INVESTIGATOR: InvestigatorAgent(self.blackboard, self.tools),
            AgentRole.REMEDIATION: RemediationAgent(self.blackboard, self.tools),
            AgentRole.AUDITOR: AuditorAgent(self.blackboard, self.tools)
        }

    def load_preset(self, preset_key: str) -> Incident:
        """Load an incident preset and initialize initial triage task."""
        incident = create_incident_from_preset(preset_key)
        self.initialize_incident(incident)
        return incident

    def initialize_incident(self, incident: Incident) -> None:
        """Initialize blackboard with incident and create the initial root task for Sentinel."""
        self.blackboard.set_incident(incident)

        # Clear previous messages/tools
        self.blackboard.messages.clear()
        self.blackboard.tool_executions.clear()

        # Seed initial Triage task for Sentinel
        initial_task = Task(
            id=f"TASK-TRIAGE-{incident.id}",
            title=f"Triage & Log Ingestion for {incident.id}",
            description="Parse raw telemetry logs, detect attack patterns, and extract IOCs.",
            assigned_to=AgentRole.SENTINEL
        )
        self.blackboard.add_task(initial_task)

    def get_next_runnable_task(self) -> Optional[Task]:
        """Find the next TODO task whose dependencies are all completed."""
        for task in self.blackboard.incident.tasks.values():
            if task.status != TaskStatus.TODO:
                continue

            # Check if all dependencies are DONE
            deps_met = True
            for dep_id in task.dependencies:
                dep_task = self.blackboard.incident.tasks.get(dep_id)
                if not dep_task or dep_task.status != TaskStatus.DONE:
                    deps_met = False
                    break

            if deps_met:
                return task

        return None

    def step(self) -> Optional[Dict[str, Any]]:
        """Execute a single ready task from the Kanban board."""
        task = self.get_next_runnable_task()
        if not task:
            return None

        agent = self.agents.get(task.assigned_to)
        if not agent:
            raise ValueError(f"No agent registered for role {task.assigned_to}")

        # Execute agent action
        result = agent.act(task)
        return {
            "task_id": task.id,
            "agent": agent.name,
            "role": task.assigned_to.value,
            "result": result
        }

    async def step_async(self) -> Optional[Dict[str, Any]]:
        """Asynchronous wrapper for a single step."""
        return await asyncio.to_thread(self.step)

    def run_all(self, max_steps: int = 15, delay_seconds: float = 0.0) -> List[Dict[str, Any]]:
        """Synchronously execute all tasks until resolution or maximum steps reached."""
        results = []
        step_count = 0

        while step_count < max_steps:
            if self.blackboard.incident.status in (IncidentStatus.RESOLVED, IncidentStatus.FAILED):
                break

            step_res = self.step()
            if not step_res:
                break

            results.append(step_res)
            step_count += 1

            if delay_seconds > 0:
                time.sleep(delay_seconds)

        return results

    async def run_all_async(self, max_steps: int = 15, delay_seconds: float = 0.5) -> List[Dict[str, Any]]:
        """Asynchronously execute all tasks with delay between steps for UI animation."""
        self.is_running = True
        results = []
        step_count = 0

        try:
            while self.is_running and step_count < max_steps:
                if self.blackboard.incident.status in (IncidentStatus.RESOLVED, IncidentStatus.FAILED):
                    break

                step_res = await self.step_async()
                if not step_res:
                    break

                results.append(step_res)
                step_count += 1

                if delay_seconds > 0:
                    await asyncio.sleep(delay_seconds)
        finally:
            self.is_running = False

        return results

    def stop(self) -> None:
        """Signal orchestrator to stop running."""
        self.is_running = False

"""Base Agent class for Cyber-Nova multi-agent framework."""

from abc import ABC, abstractmethod
from typing import Dict, Any, Optional
from ..models import AgentRole, Task, MessageType, TaskStatus
from ..blackboard import Blackboard
from ..tools.base import BaseTool


class BaseAgent(ABC):
    """Abstract Base Agent capable of thought, tool invocation, and collaboration."""

    role: AgentRole
    name: str
    description: str

    def __init__(self, blackboard: Blackboard, tools: Optional[Dict[str, BaseTool]] = None):
        self.blackboard = blackboard
        self.tools: Dict[str, BaseTool] = tools or {}
        self.status = "IDLE"  # "IDLE", "ANALYZING", "EXECUTING_TOOL", "COLLABORATING", "COMPLETE"

    def set_status(self, status: str) -> None:
        self.status = status
        self.blackboard.emit_event("agent_state_changed", {
            "agent": self.name,
            "role": self.role.value,
            "status": status
        })

    def think(self, thought: str) -> None:
        """Record internal reasoning on the blackboard."""
        self.blackboard.post_message(
            sender=self.name,
            recipient="internal",
            msg_type=MessageType.THOUGHT,
            content=thought
        )

    def send_message(
        self,
        recipient: str,
        content: str,
        msg_type: MessageType = MessageType.HANDOFF,
        metadata: Optional[Dict[str, Any]] = None
    ) -> None:
        """Send a message to another agent or broadcast."""
        self.set_status("COLLABORATING")
        self.blackboard.post_message(
            sender=self.name,
            recipient=recipient,
            msg_type=msg_type,
            content=content,
            metadata=metadata or {}
        )

    def call_tool(self, tool_name: str, **kwargs) -> Dict[str, Any]:
        """Invoke a tool registered to this agent."""
        if tool_name not in self.tools:
            raise ValueError(f"Tool '{tool_name}' not available to agent {self.name}")

        self.set_status("EXECUTING_TOOL")
        self.blackboard.post_message(
            sender=self.name,
            recipient="system",
            msg_type=MessageType.TOOL_CALL,
            content=f"Invoking {tool_name} with params: {list(kwargs.keys())}",
            metadata={"tool": tool_name, "args": kwargs}
        )

        tool = self.tools[tool_name]
        result = tool.run(agent_name=self.name, **kwargs)

        self.blackboard.record_tool_execution(
            tool_name=tool_name,
            agent_name=self.name,
            arguments=kwargs,
            result=result["data"] if result["success"] else result.get("error"),
            success=result["success"],
            duration_ms=result["duration_ms"]
        )

        self.blackboard.post_message(
            sender=self.name,
            recipient="system",
            msg_type=MessageType.TOOL_RESULT,
            content=f"Tool {tool_name} completed in {result['duration_ms']}ms",
            metadata={"tool": tool_name, "success": result["success"]}
        )

        return result

    @abstractmethod
    def act(self, task: Task) -> Any:
        """Execute logic to complete the assigned task."""
        pass

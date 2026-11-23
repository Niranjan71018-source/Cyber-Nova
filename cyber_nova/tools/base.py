"""Base class and registry for Cyber-Nova agent tools."""

from abc import ABC, abstractmethod
from typing import Dict, Any, Optional
import time
import traceback


class BaseTool(ABC):
    """Abstract base class for all tools available to Cyber-Nova agents."""

    name: str = "base_tool"
    description: str = "Base tool description"
    parameters: Dict[str, Any] = {}

    @abstractmethod
    def execute(self, **kwargs) -> Dict[str, Any]:
        """Execute the tool logic and return structured results."""
        pass

    def run(self, agent_name: str = "system", **kwargs) -> Dict[str, Any]:
        """Run tool with exception handling, timing, and standardized output."""
        start = time.perf_counter()
        try:
            result = self.execute(**kwargs)
            duration_ms = round((time.perf_counter() - start) * 1000, 2)
            return {
                "success": True,
                "tool_name": self.name,
                "agent": agent_name,
                "data": result,
                "duration_ms": duration_ms,
                "error": None
            }
        except Exception as e:
            duration_ms = round((time.perf_counter() - start) * 1000, 2)
            return {
                "success": False,
                "tool_name": self.name,
                "agent": agent_name,
                "data": None,
                "duration_ms": duration_ms,
                "error": f"{type(e).__name__}: {str(e)}",
                "traceback": traceback.format_exc()
            }

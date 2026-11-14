"""
AEGIS Autonomous Multi-Agent Orchestration Package
=========================================================
Provides coordinated multi-agent penetration testing orchestration combining:
- AEGIS dynamic subagent spawning, specialized skills, and independent validation
- AEGIS task decomposition (Generator), plan refinement (Refiner), execution monitoring (Adviser/Reflector), and context memory (Memorist)
Bound strictly under Bifrost Authorization Manager, ScopeEnforcer, and controlled MCP security tools.
"""

from .roles import AgentRole, RoleCatalog
from .coordinator import MultiAgentCoordinator, AgentTask, TaskStatus
from .planner import TaskPlanner
from .refiner import PlanRefiner
from .validator import IndependentValidator
from .reporter import ExecutiveReporter
from .orchestrator import UnifiedMultiAgentOrchestrator

__all__ = [
    "AgentRole",
    "RoleCatalog",
    "MultiAgentCoordinator",
    "AgentTask",
    "TaskStatus",
    "TaskPlanner",
    "PlanRefiner",
    "IndependentValidator",
    "ExecutiveReporter",
    "UnifiedMultiAgentOrchestrator",
]


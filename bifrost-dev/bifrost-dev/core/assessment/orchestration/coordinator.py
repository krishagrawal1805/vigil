"""
Multi-Agent Coordinator
=======================
Adapted from AEGIS AgentCoordinator and AEGIS Workflow Manager.
Maintains:
- Graph of active and completed agent tasks
- Task dependencies and execution lifecycle
- Concurrency limiting via asyncio.Semaphore
- Shared assessment state (Threat Model, Target Scope, Authorization Grant)
- Structured inter-agent communication (Mailbox)
"""

import asyncio
import time
import json
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Any, Optional

class TaskStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"

@dataclass
class AgentTask:
    task_id: str
    role_id: str
    title: str
    description: str
    target_endpoint: str = ""
    parameters: List[str] = field(default_factory=list)
    priority: int = 1  # 1 = highest, 5 = lowest
    depends_on: List[str] = field(default_factory=list)
    parent_task_id: Optional[str] = None
    status: TaskStatus = TaskStatus.PENDING
    assigned_skills: List[str] = field(default_factory=list)
    result_summary: str = ""
    candidate_findings: List[Dict[str, Any]] = field(default_factory=list)
    invocation_ids: List[str] = field(default_factory=list)
    created_at: float = field(default_factory=time.time)
    completed_at: Optional[float] = None
    error: Optional[str] = None

    def is_ready(self, completed_task_ids: set) -> bool:
        """A task is ready to execute if all its dependencies are completed."""
        return self.status == TaskStatus.PENDING and all(dep in completed_task_ids for dep in self.depends_on)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "task_id": self.task_id,
            "role_id": self.role_id,
            "title": self.title,
            "description": self.description,
            "target_endpoint": self.target_endpoint,
            "parameters": self.parameters,
            "priority": self.priority,
            "depends_on": self.depends_on,
            "parent_task_id": self.parent_task_id,
            "status": self.status.value,
            "assigned_skills": self.assigned_skills,
            "result_summary": self.result_summary,
            "candidate_findings": self.candidate_findings,
            "invocation_ids": self.invocation_ids,
            "created_at": self.created_at,
            "completed_at": self.completed_at,
            "error": self.error
        }

class MultiAgentCoordinator:
    """Central coordinator managing the multi-agent task graph and execution lifecycle."""

    def __init__(
        self,
        assessment_id: str,
        grant_id: str,
        target_base: str,
        roe_mode: str = "broad",
        max_concurrency: int = 2
    ):
        self.assessment_id = assessment_id
        self.grant_id = grant_id
        self.target_base = target_base
        self.roe_mode = roe_mode
        self.max_concurrency = max_concurrency
        self.semaphore = asyncio.Semaphore(max_concurrency)

        self.tasks: Dict[str, AgentTask] = {}
        self.completed_task_ids: set = set()
        self.mailboxes: Dict[str, List[Dict[str, Any]]] = {}
        self.lock = asyncio.Lock()
        self.start_time = time.time()

    async def add_task(self, task: AgentTask) -> AgentTask:
        async with self.lock:
            self.tasks[task.task_id] = task
            self.mailboxes[task.task_id] = []
        return task

    async def get_ready_tasks(self) -> List[AgentTask]:
        """Returns pending tasks whose dependencies have all completed, sorted by priority."""
        async with self.lock:
            ready = [t for t in self.tasks.values() if t.is_ready(self.completed_task_ids)]
            # Sort by priority ascending (1 = highest priority), then created_at
            ready.sort(key=lambda x: (x.priority, x.created_at))
            return ready

    async def mark_running(self, task_id: str):
        async with self.lock:
            if task_id in self.tasks:
                self.tasks[task_id].status = TaskStatus.RUNNING

    async def mark_completed(self, task_id: str, summary: str = "", candidate_findings: List[Dict[str, Any]] = None, invocation_ids: List[str] = None):
        async with self.lock:
            if task_id in self.tasks:
                task = self.tasks[task_id]
                task.status = TaskStatus.COMPLETED
                task.result_summary = summary
                task.completed_at = time.time()
                if candidate_findings:
                    task.candidate_findings = candidate_findings
                if invocation_ids:
                    task.invocation_ids = list(invocation_ids)
                self.completed_task_ids.add(task_id)

    async def mark_failed(self, task_id: str, error: str):
        async with self.lock:
            if task_id in self.tasks:
                task = self.tasks[task_id]
                task.status = TaskStatus.FAILED
                task.error = error
                task.completed_at = time.time()
                # Do not block dependent tasks indefinitely if non-fatal
                self.completed_task_ids.add(task_id)

    async def send_message(self, from_task_id: str, to_task_id: str, content: str, msg_type: str = "info"):
        async with self.lock:
            if to_task_id in self.mailboxes:
                self.mailboxes[to_task_id].append({
                    "from": from_task_id,
                    "content": content,
                    "type": msg_type,
                    "timestamp": time.time()
                })

    async def get_messages(self, task_id: str) -> List[Dict[str, Any]]:
        async with self.lock:
            return list(self.mailboxes.get(task_id, []))

    def get_task_graph_snapshot(self) -> Dict[str, Any]:
        """Generates an inspection snapshot of all active/completed tasks."""
        return {
            "assessment_id": self.assessment_id,
            "target": self.target_base,
            "max_concurrency": self.max_concurrency,
            "total_tasks": len(self.tasks),
            "completed_tasks": len(self.completed_task_ids),
            "tasks": [t.to_dict() for t in self.tasks.values()]
        }


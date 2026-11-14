"""
Plan Refinement & Replanning Agent (Adapted from AEGIS Refiner)
================================================================
Dynamically analyzes the outcomes of completed specialist investigations,
prunes obsolete tasks, reprioritizes remaining tasks, and adds follow-ups.
"""

from typing import List, Dict, Any, Set
from .coordinator import AgentTask, TaskStatus

class PlanRefiner:
    """Dynamically refines and optimizes the remaining task plan based on completed investigation results."""

    def refine_plan(
        self,
        all_tasks: Dict[str, AgentTask],
        completed_task_ids: Set[str],
        latest_completed_task: AgentTask
    ) -> List[str]:
        """
        Reviews completed task results and modifies remaining pending tasks.
        Returns a list of refinement actions taken (e.g., pruned, reprioritized, added).
        """
        actions = []
        res = latest_completed_task.result_summary.lower()

        # 1. Prune redundant tasks if an endpoint is completely defended/unresponsive
        if "not vulnerable" in res or "rejected" in res or "404" in res:
            for task in all_tasks.values():
                if task.status == TaskStatus.PENDING and task.target_endpoint == latest_completed_task.target_endpoint:
                    if task.role_id == latest_completed_task.role_id:
                        task.status = TaskStatus.CANCELLED
                        actions.append(f"Pruned duplicate pending task {task.task_id} on hardened endpoint {task.target_endpoint}")

        # 2. Prioritize token/privilege tasks if authentication was bypassed
        if "sql injection confirmed" in res or "auth token granted" in res:
            for task in all_tasks.values():
                if task.status == TaskStatus.PENDING and ("admin" in task.target_endpoint or "jwt" in task.title.lower()):
                    old_p = task.priority
                    task.priority = 1
                    actions.append(f"Elevated priority of administrative task {task.task_id} from {old_p} to 1 (Authentication token acquired)")

        # 3. Elevate related object tasks if BOLA is confirmed
        if "bola confirmed" in res or "cross-account" in res:
            for task in all_tasks.values():
                if task.status == TaskStatus.PENDING and "basket" in task.target_endpoint:
                    task.priority = 1
                    actions.append(f"Elevated priority of object access task {task.task_id} to 1 (BOLA confirmed on tenant boundary)")

        return actions


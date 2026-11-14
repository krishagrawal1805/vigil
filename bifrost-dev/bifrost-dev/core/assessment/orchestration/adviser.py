"""
Execution Adviser & Reflector (Adapted from AEGIS Adviser + Reflector)
========================================================================
Monitors execution telemetry across multi-agent operations:
- Detects stalled tasks and repetitive tool loops
- Advises early termination of unpromising investigations
- Protects LLM turn and token budgets
"""

from typing import Dict, Any, List

class ExecutionAdviser:
    """Provides strategic execution monitoring and anti-looping guidance."""

    def __init__(self, max_turns_per_task: int = 8):
        self.max_turns_per_task = max_turns_per_task
        self.advice_history: List[str] = []

    def evaluate_task_progress(
        self,
        task_id: str,
        role_id: str,
        turns_executed: int,
        tool_call_count: int,
        hypotheses_formulated: int,
        duplicate_call_hits: int
    ) -> Dict[str, Any]:
        """
        Evaluates task execution telemetry and advises whether to continue, replan, or terminate.
        """
        recommendation = "continue"
        reason = "Task progressing normally."

        # Check for repetitive loops
        if duplicate_call_hits >= 2:
            recommendation = "replan"
            reason = f"Agent {role_id} in {task_id} encountered {duplicate_call_hits} duplicate tool call hits. Advise pivoting to another endpoint or terminating subtask."

        # Check for stalled turns without progress
        elif turns_executed >= self.max_turns_per_task:
            recommendation = "terminate"
            reason = f"Task {task_id} reached turn limit ({turns_executed}/{self.max_turns_per_task}). Conclude subtask with inconclusive evaluation to conserve token budget."

        # Check for excessive tool calls without hypothesis formulation
        elif tool_call_count >= 5 and hypotheses_formulated == 0:
            recommendation = "advise_hypothesis"
            reason = f"Task {task_id} performed {tool_call_count} inspections without formulating a hypothesis. Direct agent to formulate hypothesis or rule out surface."

        advice_record = {
            "task_id": task_id,
            "role_id": role_id,
            "recommendation": recommendation,
            "reason": reason
        }
        self.advice_history.append(f"[{task_id}:{role_id}] {recommendation} -> {reason}")
        return advice_record


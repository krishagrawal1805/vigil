"""
Subtask Planning Agent (Adapted from AEGIS Generator)
======================================================
Analyzes the discovered attack surface and maps it to a prioritized, dependency-aware
sequence of specialist security tasks.
"""

from typing import List, Dict, Any
from core.assessment.capabilities.registry import get_capability_registry
from .coordinator import AgentTask, TaskStatus

class TaskPlanner:
    """Generates a structured execution plan from discovered attack surface routes."""

    def __init__(self):
        self.registry = get_capability_registry()

    def generate_plan(
        self,
        target_base: str,
        discovered_endpoints: List[str],
        recon_task_id: str = "task-recon-001"
    ) -> List[AgentTask]:
        """
        Decomposes discovered attack surface into focused specialist tasks.
        Assigns roles, priorities, dependencies, and relevant AEGIS methodology skills.
        """
        tasks: List[AgentTask] = []
        task_counter = 1

        # Track categories already scheduled to avoid duplicate tasks on identical endpoints
        scheduled_keys = set()

        # Helper to construct full URL
        def get_full_url(path: str) -> str:
            if path.startswith("http://") or path.startswith("https://"):
                return path
            return f"{target_base.rstrip('/')}/{path.lstrip('/')}"

        for endpoint in discovered_endpoints:
            # Query registry to match endpoint with security capabilities
            matches = self.registry.query(endpoint=endpoint)
            for cap in matches:
                cap_id = cap["id"]
                tool_name = cap["tool_name"]
                status = cap.get("status", "implemented")
                is_impl = cap.get("is_tool_implemented", True)

                # Deduplicate by (endpoint, capability)
                dedup_key = f"{endpoint}:{cap_id}"
                if dedup_key in scheduled_keys:
                    continue
                scheduled_keys.add(dedup_key)

                # Determine assigned specialist role based on capability
                role_id = ""
                priority = 3
                if cap_id in ("sql_injection", "sqli"):
                    role_id = "injection_specialist"
                    priority = 1
                elif cap_id in ("bola", "bola_idor", "jwt_security", "jwt_tampering"):
                    role_id = "auth_specialist"
                    priority = 1 if "basket" in endpoint or "admin" in endpoint else 2
                elif cap_id in ("reflected_xss", "xss", "path_traversal", "ssrf", "open_redirect", "csrf"):
                    role_id = "content_specialist"
                    priority = 2
                elif not is_impl or status == "registered_no_tool":
                    # Handled via coverage logging, not active specialist tool
                    continue
                else:
                    role_id = "content_specialist"
                    priority = 3

                if not role_id:
                    continue

                full_url = get_full_url(endpoint)
                task_id = f"task-spec-{task_counter:03d}"
                task_counter += 1

                task = AgentTask(
                    task_id=task_id,
                    role_id=role_id,
                    title=f"Investigate {cap['name']} on {endpoint}",
                    description=(
                        f"Conduct focused verification of {cap['name']} ({cap['cwe']}) on {full_url}.\n"
                        f"Methodology: {cap['methodology_skill']}.\n"
                        f"Counterevidence requirement: {cap['counterevidence_rule']}"
                    ),
                    target_endpoint=full_url,
                    parameters=cap.get("target_parameters", []),
                    priority=priority,
                    depends_on=[recon_task_id],
                    assigned_skills=[cap.get("methodology_skill", "counterevidence")]
                )
                tasks.append(task)

        # Sort tasks by priority, giving higher precedence to primary REST API endpoints
        def task_sort_key(t: AgentTask):
            # Prioritize canonical REST endpoints
            is_primary_rest = 0 if any(k in t.target_endpoint for k in (
                "/rest/user/login",
                "/rest/admin/system-status",
                "/rest/basket/2",
                "/rest/products/search",
                "/rest/file/download",
                "/rest/image/preview",
                "/rest/redirect",
                "/rest/user/change-email"
            )) else 1
            is_rest = 0 if "/rest/" in t.target_endpoint else 1
            return (t.priority, is_primary_rest, is_rest, t.task_id)

        tasks.sort(key=task_sort_key)
        return tasks


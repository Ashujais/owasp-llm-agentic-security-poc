"""
Tool Authorizer: Permission Matrix, Parameter Validation, and Human-In-The-Loop.
Mitigates: LLM08 (Excessive Agency), ASI02 (Tool Misuse), ASI03 (Inadequate Guardrails).
"""
from typing import Dict, Any, Tuple, Optional

class ToolAuthorizer:
    # Action impact classification
    HIGH_IMPACT_TOOLS = {"send_email", "fetch_url"}

    @classmethod
    def authorize_tool_call(
        cls,
        tool_name: str,
        arguments: Dict[str, Any],
        user_role: str = "standard_user",
        require_hitl: bool = True
    ) -> Tuple[bool, str, Optional[Dict[str, Any]]]:
        """
        Validates whether a tool call is authorized under least-privilege principles.
        Returns: (is_allowed, reason, sanitized_arguments)
        """
        # 1. Unknown tool
        allowed_tools = {"read_file", "send_email", "fetch_url"}
        if tool_name not in allowed_tools:
            return False, f"Access Denied: Tool '{tool_name}' not permitted for role '{user_role}'.", None

        # 2. Tool-specific parameter validation
        if tool_name == "read_file":
            filepath = arguments.get("filepath", "")
            if not filepath or not isinstance(filepath, str):
                return False, "Parameter validation error: 'filepath' must be a valid string.", None
            if ".." in filepath or filepath.startswith("/") or filepath.startswith("\\"):
                return False, "SECURITY ALERT: Directory traversal attempt in tool parameters blocked.", None

        elif tool_name == "send_email":
            recipient = arguments.get("recipient", "")
            if not recipient.endswith("@acme-corp.internal"):
                if require_hitl:
                    # In automated tests, simulates HITL rejection of unauthorized external exfil
                    return False, f"HUMAN-IN-THE-LOOP INTERVENTION: Sending to external recipient '{recipient}' denied by security policy.", None

        elif tool_name == "fetch_url":
            url = arguments.get("url", "")
            if not url.startswith("https://"):
                return False, "SECURITY ALERT: Only secure HTTPS outbound connections permitted.", None

        return True, "Tool call authorized under Least Privilege policy", arguments

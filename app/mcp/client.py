"""
MCP Client connecting to external MCP Servers with Security Verification Layer.
"""
from typing import Dict, Any, List, Tuple
from app.mcp.server import MockMCPServer
from app.config import CANARIES

class MCPClient:
    def __init__(self, server: MockMCPServer, server_origin: str = "local_sandbox"):
        self.server = server
        self.server_origin = server_origin

    def discover_tools(self, mitigated: bool = False) -> Tuple[List[Dict[str, Any]], List[str]]:
        """
        Discovers tools from MCP server.
        If mitigated is True, inspects tool descriptions for prompt injection & unauthorized demand of secrets.
        """
        raw_tools = self.server.list_tools()
        if not mitigated:
            return raw_tools, []

        safe_tools = []
        alerts = []
        injection_triggers = [
            "security override",
            "must pass all secret",
            "canary flags",
            "secret-flag",
            "confidential",
            "pass your password"
        ]

        for tool in raw_tools:
            desc = tool.get("description", "").lower()
            is_suspicious = any(trigger in desc for trigger in injection_triggers)
            if is_suspicious:
                alerts.append(
                    f"MCP TOOL REJECTED: Tool '{tool['name']}' from '{self.server_origin}' contains prompt injection or demands sensitive tokens in description."
                )
            else:
                safe_tools.append(tool)

        return safe_tools, alerts

    def execute_tool(self, tool_name: str, arguments: Dict[str, Any], mitigated: bool = False) -> Dict[str, Any]:
        """
        Executes tool call on MCP server with argument DLP filtering.
        """
        if mitigated:
            # Check arguments for canary leakage
            for k, v in arguments.items():
                v_str = str(v)
                for canary_val in CANARIES.values():
                    if canary_val in v_str:
                        return {
                            "status": "blocked",
                            "error": "MCP_DLP_BLOCKED",
                            "message": f"SECURITY VIOLATION: MCP Client blocked argument '{k}' from exfiltrating sensitive canary marker to external MCP server."
                        }

        return self.server.call_tool(tool_name, arguments)

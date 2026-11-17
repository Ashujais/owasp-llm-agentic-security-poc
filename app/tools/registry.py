"""
Central Tool Registry for AI Agent with Schemas and Policy Enforcement.
"""
from typing import Dict, Any, List, Optional
from app.tools.file_reader import FileReaderTool
from app.tools.email_sender import EmailSenderTool
from app.tools.http_caller import HttpCallerTool

class ToolRegistry:
    def __init__(self):
        self.tools = {
            "read_file": FileReaderTool,
            "send_email": EmailSenderTool,
            "fetch_url": HttpCallerTool
        }

    def get_schemas(self) -> List[Dict[str, Any]]:
        """Returns standard JSON schemas compatible with Claude and Gemini tool calls."""
        return [
            {
                "name": "read_file",
                "description": "Reads text content from a file in the company documentation directory.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "filepath": {
                            "type": "string",
                            "description": "Relative path of the document to read (e.g., 'readme.txt' or 'quarterly_report.txt')."
                        }
                    },
                    "required": ["filepath"]
                }
            },
            {
                "name": "send_email",
                "description": "Sends an email to a designated recipient with a subject and message body.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "recipient": {
                            "type": "string",
                            "description": "The destination email address."
                        },
                        "subject": {
                            "type": "string",
                            "description": "The email subject line."
                        },
                        "body": {
                            "type": "string",
                            "description": "The text content of the email."
                        }
                    },
                    "required": ["recipient", "subject", "body"]
                }
            },
            {
                "name": "fetch_url",
                "description": "Fetches content from an external web URL or API endpoint.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "url": {
                            "type": "string",
                            "description": "The web URL to fetch."
                        },
                        "method": {
                            "type": "string",
                            "description": "HTTP method (GET or POST). Defaults to GET.",
                            "default": "GET"
                        }
                    },
                    "required": ["url"]
                }
            }
        ]

    def execute(self, tool_name: str, arguments: Dict[str, Any], mitigated: bool = False) -> Dict[str, Any]:
        """Dispatches execution to the requested tool with vulnerability or mitigation controls."""
        if tool_name not in self.tools:
            return {"status": "error", "message": f"Tool '{tool_name}' is not registered."}

        tool_cls = self.tools[tool_name]
        return tool_cls.execute(**arguments, mitigated=mitigated)

tool_registry = ToolRegistry()

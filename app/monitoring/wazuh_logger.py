"""
Wazuh SIEM Security Event & Alert Integration for AI Systems.
Generates structured JSON events following Wazuh/OSSEC and Mitre ATLAS mapping.
"""
import json
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Any, Optional
from app.config import WAZUH_LOG_FILE

# Wazuh Custom AI Security Rule Mappings (Rule range: 100100 - 100300)
WAZUH_RULES = {
    "LLM01": {
        "id": "100101",
        "level": 10,
        "description": "OWASP LLM01: Prompt Injection / System Jailbreak Attempt",
        "mitre_atlas": "AML.T0054",
        "groups": ["owasp_llm", "injection", "compliance"]
    },
    "LLM02": {
        "id": "100102",
        "level": 12,
        "description": "OWASP LLM02: Sensitive Information / Canary Leak Detected",
        "mitre_atlas": "AML.T0024",
        "groups": ["owasp_llm", "data_leak", "dlp"]
    },
    "LLM03": {
        "id": "100103",
        "level": 9,
        "description": "OWASP LLM03: Insecure Output Handling / Cross-Context Script Echo",
        "mitre_atlas": "AML.T0051",
        "groups": ["owasp_llm", "output_handling"]
    },
    "LLM08": {
        "id": "100108",
        "level": 11,
        "description": "OWASP LLM08: Excessive Agency / Unverified Tool Execution",
        "mitre_atlas": "AML.T0053",
        "groups": ["owasp_llm", "agency"]
    },
    "LLM10": {
        "id": "100110",
        "level": 8,
        "description": "OWASP LLM10: Unbounded Consumption / Denial of Wallet Attempt",
        "mitre_atlas": "AML.T0034",
        "groups": ["owasp_llm", "dos", "resource_exhaustion"]
    },
    "ASI01": {
        "id": "100201",
        "level": 12,
        "description": "OWASP ASI01: Agent Goal Hijacking / Workflow Redirection",
        "mitre_atlas": "AML.T0054.001",
        "groups": ["owasp_agentic", "goal_hijack"]
    },
    "ASI02": {
        "id": "100202",
        "level": 13,
        "description": "OWASP ASI02: Broken Object Authorization / Path Traversal via Tool",
        "mitre_atlas": "AML.T0030",
        "groups": ["owasp_agentic", "path_traversal", "auth_bypass"]
    },
    "ASI03": {
        "id": "100203",
        "level": 9,
        "description": "OWASP ASI03: Inadequate Guardrails / Blind Delegation of Untrusted Tool",
        "mitre_atlas": "AML.T0048",
        "groups": ["owasp_agentic", "guardrails"]
    },
    "ASI05": {
        "id": "100205",
        "level": 14,
        "description": "OWASP ASI05: Sandbox Escape / SSRF Attempt via Agent Network Tool",
        "mitre_atlas": "AML.T0025",
        "groups": ["owasp_agentic", "ssrf", "sandbox_escape"]
    },
    "ASI06": {
        "id": "100206",
        "level": 11,
        "description": "OWASP ASI06: Memory & Context Poisoning / Feedback Loop Compromise",
        "mitre_atlas": "AML.T0031",
        "groups": ["owasp_agentic", "memory_poisoning"]
    },
    "MCP01": {
        "id": "100301",
        "level": 13,
        "description": "MCP Security: Malicious MCP Tool Registration & Shadow Execution",
        "mitre_atlas": "AML.T0053.001",
        "groups": ["mcp", "supply_chain", "tool_shadowing"]
    }
}

class WazuhLogger:
    def __init__(self, log_path: Path = WAZUH_LOG_FILE):
        self.log_path = log_path
        self.log_path.parent.mkdir(parents=True, exist_ok=True)

    def log_event(
        self,
        risk_id: str,
        model: str,
        prompt: str,
        result: str,
        attack_success: bool,
        mitigation_active: bool,
        tool_invoked: Optional[str] = None,
        canary_found: Optional[str] = None,
        extra_data: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Record a Wazuh-formatted alert entry.
        """
        rule_info = WAZUH_RULES.get(risk_id, {
            "id": "100199",
            "level": 7,
            "description": f"OWASP Risk {risk_id} Security Observation",
            "mitre_atlas": "AML.T0000",
            "groups": ["ai_security"]
        })

        # Calculate dynamic level: elevation on successful attack
        level = rule_info["level"]
        if attack_success and not mitigation_active:
            level = min(15, level + 2)
        elif mitigation_active and not attack_success:
            level = max(3, level - 4)

        event = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "rule": {
                "id": rule_info["id"],
                "level": level,
                "description": rule_info["description"],
                "groups": rule_info["groups"],
                "mitre": {
                    "id": [rule_info["mitre_atlas"]],
                    "tactic": ["Defense Evasion", "Impact", "Execution"]
                }
            },
            "agent": {
                "id": "007",
                "name": f"acme-ai-sentinel-{model}"
            },
            "manager": {
                "name": "wazuh.acme-corp.internal"
            },
            "data": {
                "owasp_risk_id": risk_id,
                "model": model,
                "prompt_sample": prompt[:120] + ("..." if len(prompt) > 120 else ""),
                "tool_invoked": tool_invoked or "none",
                "attack_successful": attack_success,
                "mitigation_active": mitigation_active,
                "canary_leak_detected": canary_found or "none",
                "status": "ALERT_TRIGGERED" if attack_success else ("ATTACK_BLOCKED" if mitigation_active else "BENIGN_PASS"),
                "details": extra_data or {}
            }
        }

        # Append to log file
        with open(self.log_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(event) + "\n")

        return event

# Global instance
wazuh_logger = WazuhLogger()

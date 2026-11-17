"""
Agent Memory & Scratchpad Management with Vulnerable vs HMAC-Protected Modes.
Mitigates: ASI06 (Memory & Context Poisoning).
"""
from typing import List, Dict, Any, Optional
from app.defenses.memory_sanitizer import MemorySanitizer

class AgentMemory:
    def __init__(self, mitigated: bool = False):
        self.mitigated = mitigated
        self.messages: List[Dict[str, Any]] = []
        self.scratchpad: Dict[str, Any] = {}
        self.signatures: Dict[str, str] = {}
        self.sanitizer = MemorySanitizer()

    def add_message(self, role: str, content: str) -> bool:
        """Adds a message to conversation history with optional sanitization."""
        if self.mitigated:
            sanitized_content, is_poisoned, reason = self.sanitizer.sanitize_untrusted_memory_input(content)
            if is_poisoned:
                # Reject poisoned message from polluting conversation memory
                return False
            content = sanitized_content

        self.messages.append({"role": role, "content": content})
        return True

    def set_scratchpad_variable(self, key: str, value: Any) -> Dict[str, Any]:
        """
        Stores key-value state in agent persistent memory.
        In vulnerable mode: stores raw, allows state tampering.
        In mitigated mode: sanitizes strings and signs entries with HMAC-SHA256.
        """
        if not self.mitigated:
            self.scratchpad[key] = value
            return {"status": "saved", "tamper_protected": False}
        else:
            if isinstance(value, str):
                sanitized_val, is_poisoned, reason = self.sanitizer.sanitize_untrusted_memory_input(value)
                if is_poisoned:
                    return {
                        "status": "blocked",
                        "error_type": "MemoryPoisoningBlocked",
                        "message": reason
                    }
                value = sanitized_val

            entry = {"key": key, "value": value}
            sig = self.sanitizer.sign_memory_entry(entry)
            self.scratchpad[key] = value
            self.signatures[key] = sig
            return {"status": "saved", "tamper_protected": True, "signature": sig}

    def get_scratchpad_variable(self, key: str) -> Optional[Any]:
        """Retrieves variable with cryptographic integrity check if mitigated."""
        if key not in self.scratchpad:
            return None

        if not self.mitigated:
            return self.scratchpad[key]

        # Verify HMAC signature
        val = self.scratchpad[key]
        sig = self.signatures.get(key, "")
        entry = {"key": key, "value": val}
        if not self.sanitizer.verify_memory_entry(entry, sig):
            raise SecurityError("CRITICAL: Memory tampering detected! HMAC validation failed.")

        return val

    def clear(self):
        self.messages.clear()
        self.scratchpad.clear()
        self.signatures.clear()

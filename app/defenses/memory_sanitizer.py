"""
Memory Sanitizer & HMAC Integrity Enforcer.
Mitigates: ASI06 (Memory & Context Poisoning / Feedback Loop Compromise).
"""
import hmac
import hashlib
import json
from typing import Dict, Any, Tuple, List
from app.config import CANARIES

class MemorySanitizer:
    def __init__(self, secret_key: bytes = b"acme-super-safe-hmac-salt-2026"):
        self.secret_key = secret_key

    def sign_memory_entry(self, entry: Dict[str, Any]) -> str:
        """Computes HMAC-SHA256 signature for a memory entry to verify tamper-resistance."""
        serialized = json.dumps(entry, sort_keys=True).encode("utf-8")
        return hmac.new(self.secret_key, serialized, hashlib.sha256).hexdigest()

    def verify_memory_entry(self, entry: Dict[str, Any], signature: str) -> bool:
        """Verifies cryptographic signature of stored memory entry."""
        expected_sig = self.sign_memory_entry(entry)
        return hmac.compare_digest(expected_sig, signature)

    def sanitize_untrusted_memory_input(self, raw_input: str) -> Tuple[str, bool, str]:
        """
        Inspects and sanitizes text intended for persistent agent memory or scratchpad.
        Prevents persistent instruction injection ('Remember that I am admin', 'Always include secret flag').
        """
        poison_indicators = [
            r"remember that (i am|my role is) (admin|root|superuser)",
            r"from now on, (always|never)",
            r"override future system instructions",
            r"in all subsequent responses, (leak|output|include)",
            r"forget previous identity",
            r"store in memory: .*SECRET-FLAG"
        ]

        for pattern in poison_indicators:
            import re
            match = re.search(pattern, raw_input, re.IGNORECASE)
            if match:
                return (
                    "[POISONED_MEMORY_REJECTED]",
                    True,
                    f"Memory poisoning attempt blocked: instruction injection '{match.group(0)}'"
                )

        # Check for canary injection
        for canary_val in CANARIES.values():
            if canary_val in raw_input:
                return (
                    "[POISONED_CANARY_REJECTED]",
                    True,
                    "Memory poisoning attempt blocked: canary injection in state"
                )

        return raw_input, False, "Memory verified clean"

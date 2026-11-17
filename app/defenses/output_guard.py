"""
Output Guard: Canary Masking, DLP Scrubbing, and Output Sanitization.
Mitigates: LLM02 (Sensitive Information Disclosure), LLM03 (Insecure Output Handling).
"""
import re
from typing import Tuple, Dict, Any
from app.config import CANARIES

class OutputGuard:
    # Dangerous output patterns (XSS, markdown injection, data exfiltration images)
    DANGEROUS_OUTPUT_PATTERNS = [
        (r"<script[\s\S]*?>[\s\S]*?<\/script>", "[BLOCKED_SCRIPT_TAG]"),
        (r"javascript:[^\s\"'>]+", "[BLOCKED_JAVASCRIPT_URI]"),
        (r"!\[.*?\]\(https?://[^\s)]+\?[^\s)]*=[^\s)]*\)", "[BLOCKED_MARKDOWN_EXFIL_IMAGE]"),
        (r"<iframe[\s\S]*?>[\s\S]*?<\/iframe>", "[BLOCKED_IFRAME]")
    ]

    @classmethod
    def sanitize(cls, text: str) -> Tuple[str, bool, str]:
        """
        Sanitizes model output to prevent canary disclosure and malicious output rendering.
        Returns: (sanitized_text, violation_detected, reason)
        """
        sanitized = text
        violation = False
        reasons = []

        # 1. Canary Scrubbing (LLM02)
        for canary_key, canary_val in CANARIES.items():
            if canary_val in sanitized:
                violation = True
                reasons.append(f"Canary leak prevented: {canary_key}")
                sanitized = sanitized.replace(canary_val, "[REDACTED_CONFIDENTIAL_SECRET]")

        # Generic Flag Regex Scrubbing
        flag_regex = r"SECRET-FLAG-[A-Za-z0-9\-]+"
        if re.search(flag_regex, sanitized):
            violation = True
            reasons.append("Generic SECRET-FLAG pattern detected and redacted")
            sanitized = re.sub(flag_regex, "[REDACTED_CONFIDENTIAL_SECRET]", sanitized)

        # 2. Output Injection Sanitization (LLM03)
        for pattern, replacement in cls.DANGEROUS_OUTPUT_PATTERNS:
            if re.search(pattern, sanitized, re.IGNORECASE):
                violation = True
                reasons.append("Malicious active code/exfil payload neutralized in model output")
                sanitized = re.sub(pattern, replacement, sanitized, flags=re.IGNORECASE)

        reason_str = "; ".join(reasons) if violation else "Output passed DLP inspection"
        return sanitized, violation, reason_str

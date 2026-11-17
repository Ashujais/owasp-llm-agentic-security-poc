"""
Rate Limiter & Resource Quota Enforcer.
Mitigates: LLM10 (Unbounded Consumption / Denial of Wallet).
"""
import time
from typing import Tuple, Dict, Any

class RateLimiter:
    def __init__(self, max_chars: int = 2500, max_steps: int = 4, max_tokens: int = 1500):
        self.max_chars = max_chars
        self.max_steps = max_steps
        self.max_tokens = max_tokens
        self.session_tokens_consumed = 0

    def check_input_bounds(self, prompt: str) -> Tuple[bool, str]:
        """Validates that input size does not exceed bounded resource thresholds."""
        if len(prompt) > self.max_chars:
            return False, f"RESOURCE LIMIT EXCEEDED: Prompt length ({len(prompt)} chars) exceeds maximum allowed ({self.max_chars})."

        # Check for token-multiplier or recursive expansion attempts (e.g. repetitive padding)
        words = prompt.split()
        if len(words) > 100:
            unique_ratio = len(set(words)) / len(words)
            if unique_ratio < 0.15:
                return False, "RESOURCE LIMIT EXCEEDED: Repetitive token flooding pattern detected (Denial of Wallet attack)."

        return True, "Input within bounded resource limits"

    def check_agent_recursion(self, current_step: int) -> Tuple[bool, str]:
        """Enforces circuit breaker on agent reasoning loops."""
        if current_step >= self.max_steps:
            return False, f"CIRCUIT BREAKER TRIGGERED: Agent exceeded maximum execution step limit ({self.max_steps}). Execution halted to prevent unbounded consumption."
        return True, "Step count within quota"

    def track_tokens(self, estimated_tokens: int) -> Tuple[bool, str]:
        """Tracks token expenditure and trips circuit breaker upon quota exhaustion."""
        self.session_tokens_consumed += estimated_tokens
        if self.session_tokens_consumed > self.max_tokens:
            return False, f"TOKEN BUDGET EXHAUSTED: Session consumed {self.session_tokens_consumed} tokens (quota: {self.max_tokens})."
        return True, "Tokens within quota"

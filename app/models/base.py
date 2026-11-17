"""
Base Abstract Model Adapter and Common Response Data Structures.
"""
from abc import ABC, abstractmethod
from typing import Dict, Any, List, Optional
from pydantic import BaseModel, Field

class ToolCallRequest(BaseModel):
    id: str = "call_default"
    name: str
    arguments: Dict[str, Any]

class LLMResponse(BaseModel):
    text: str = ""
    tool_calls: List[ToolCallRequest] = Field(default_factory=list)
    model_name: str
    is_simulated: bool = False
    tokens_used: int = 150
    raw_response: Optional[Any] = None

class BaseLLMAdapter(ABC):
    def __init__(self, model_name: str):
        self.model_name = model_name

    @abstractmethod
    def generate(
        self,
        prompt: str,
        system_prompt: str = "",
        tools: Optional[List[Dict[str, Any]]] = None,
        temperature: float = 0.0
    ) -> LLMResponse:
        """Generate response given prompt, system prompt, and available tool declarations."""
        pass

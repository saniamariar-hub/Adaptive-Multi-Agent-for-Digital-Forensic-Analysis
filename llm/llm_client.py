"""Provider-Independent LLM Client Interface.

Defines the abstract contract for LLM communication, supporting local and cloud models
with standardized request/response structures, latency tracking, and error reporting.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Dict, Optional, Tuple
from pydantic import BaseModel, Field


class LLMResponse(BaseModel):
    """Standardized response container for all LLM completions."""

    text: str = Field(..., description="Generated text content from the LLM.")
    provider: str = Field(..., description="Provider name (e.g., 'ollama', 'openai').")
    model: str = Field(..., description="Specific model identifier used for completion.")
    latency_seconds: float = Field(..., description="Wall-clock request latency in seconds.")
    success: bool = Field(default=True, description="Whether completion succeeded without errors.")
    error_message: Optional[str] = Field(default=None, description="Error message if generation failed.")
    raw_response: Optional[Dict[str, Any]] = Field(
        default=None,
        description="Raw API payload returned by the provider.",
    )


class LLMClient(ABC):
    """Abstract base class for all LLM providers."""

    @abstractmethod
    def generate(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        json_mode: bool = False,
        temperature: Optional[float] = None,
        **kwargs: Any,
    ) -> LLMResponse:
        """Send a completion prompt to the LLM and return a standardized response.

        Args:
            prompt: User prompt content.
            system_prompt: Optional system instruction prompt.
            json_mode: When True, instructs the provider to constrain generation to valid JSON.
            temperature: Sampling temperature override.
            **kwargs: Provider-specific inference parameters.

        Returns:
            LLMResponse: Encapsulating generated text, latency, and status.
        """
        pass

    @abstractmethod
    def health_check(self) -> Tuple[bool, str]:
        """Verify provider availability, endpoint connectivity, and model readiness.

        Returns:
            Tuple[bool, str]: (is_healthy, status_message)
        """
        pass

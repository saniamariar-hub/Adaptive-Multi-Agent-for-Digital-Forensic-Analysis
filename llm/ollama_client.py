"""Ollama HTTP LLM Client Implementation.

Communicates with the real local Ollama server via standard REST API endpoints
(/api/generate) using httpx, supporting JSON mode, system prompts, latency measurement,
configurable timeouts, and diagnostics.
"""

import json
import time
from typing import Any, Dict, Optional, Tuple
import httpx

from configs.config import config
from llm.llm_client import LLMClient, LLMResponse


class OllamaClient(LLMClient):
    """Local Ollama client communicating over HTTP REST API (/api/generate)."""

    def __init__(
        self,
        base_url: Optional[str] = None,
        model_name: Optional[str] = None,
        temperature: Optional[float] = None,
        timeout_seconds: Optional[float] = None,
    ):
        self.base_url = (base_url or config.llm.api_base_url).rstrip("/")
        self.model_name = model_name or config.llm.model_name or "hermes3:latest"
        self.temperature = temperature if temperature is not None else config.llm.temperature
        self.timeout_seconds = timeout_seconds or config.llm.timeout_seconds
        self.provider = "ollama"

    def generate(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        json_mode: bool = False,
        temperature: Optional[float] = None,
        **kwargs: Any,
    ) -> LLMResponse:
        """Send generation request to Ollama /api/generate endpoint.

        Args:
            prompt: User/task prompt text.
            system_prompt: Optional system instruction text.
            json_mode: If True, passes format='json' to Ollama.
            temperature: Sampling temperature override.
            **kwargs: Extra parameters passed to Ollama options.

        Returns:
            LLMResponse: Structured response with timing, status, and generated text.
        """
        temp = temperature if temperature is not None else self.temperature
        endpoint = f"{self.base_url}/api/generate"

        payload: Dict[str, Any] = {
            "model": self.model_name,
            "prompt": prompt,
            "stream": False,
        }

        if system_prompt:
            payload["system"] = system_prompt

        if json_mode:
            payload["format"] = "json"

        options: Dict[str, Any] = {}
        if temp is not None:
            options["temperature"] = temp
        if kwargs:
            options.update(kwargs)

        if options:
            payload["options"] = options

        start_time = time.perf_counter()
        try:
            with httpx.Client(timeout=self.timeout_seconds) as client:
                response = client.post(endpoint, json=payload)
                latency = time.perf_counter() - start_time

                if response.status_code != 200:
                    error_detail = f"Ollama HTTP {response.status_code}: {response.text}"
                    return LLMResponse(
                        text="",
                        provider=self.provider,
                        model=self.model_name,
                        latency_seconds=latency,
                        success=False,
                        error_message=error_detail,
                    )

                try:
                    data = response.json()
                except (ValueError, json.JSONDecodeError) as decode_err:
                    return LLMResponse(
                        text="",
                        provider=self.provider,
                        model=self.model_name,
                        latency_seconds=latency,
                        success=False,
                        error_message=f"Malformed JSON response from Ollama: {decode_err}",
                    )

                if not isinstance(data, dict):
                    return LLMResponse(
                        text="",
                        provider=self.provider,
                        model=self.model_name,
                        latency_seconds=latency,
                        success=False,
                        error_message=f"Unexpected response structure from Ollama: expected JSON object, got {type(data).__name__}",
                    )

                if data.get("error"):
                    return LLMResponse(
                        text="",
                        provider=self.provider,
                        model=self.model_name,
                        latency_seconds=latency,
                        success=False,
                        error_message=f"Ollama API error: {data['error']}",
                        raw_response=data,
                    )

                content = data.get("response")
                if content is None and "message" in data:
                    content = data.get("message", {}).get("content", "")

                if content is None:
                    return LLMResponse(
                        text="",
                        provider=self.provider,
                        model=self.model_name,
                        latency_seconds=latency,
                        success=False,
                        error_message="Ollama API response missing expected 'response' field",
                        raw_response=data,
                    )

                return LLMResponse(
                    text=content,
                    provider=self.provider,
                    model=self.model_name,
                    latency_seconds=latency,
                    success=True,
                    raw_response=data,
                )

        except httpx.ConnectError as exc:
            latency = time.perf_counter() - start_time
            err_msg = (
                f"Failed to connect to Ollama at {self.base_url}. "
                f"Ensure the Ollama service is running (e.g. 'ollama serve'). Connection error: {exc}"
            )
            return LLMResponse(
                text="",
                provider=self.provider,
                model=self.model_name,
                latency_seconds=latency,
                success=False,
                error_message=err_msg,
            )
        except httpx.TimeoutException as exc:
            latency = time.perf_counter() - start_time
            err_msg = (
                f"Request to Ollama timed out after {self.timeout_seconds} seconds. "
                f"Model '{self.model_name}' may require more time or resources."
            )
            return LLMResponse(
                text="",
                provider=self.provider,
                model=self.model_name,
                latency_seconds=latency,
                success=False,
                error_message=err_msg,
            )
        except Exception as exc:
            latency = time.perf_counter() - start_time
            return LLMResponse(
                text="",
                provider=self.provider,
                model=self.model_name,
                latency_seconds=latency,
                success=False,
                error_message=f"Unexpected error communicating with Ollama: {exc}",
            )

    def health_check(self) -> Tuple[bool, str]:
        """Check if Ollama server is reachable and model is available."""
        endpoint = f"{self.base_url}/api/tags"
        try:
            with httpx.Client(timeout=5.0) as client:
                res = client.get(endpoint)
                if res.status_code != 200:
                    return False, f"Ollama health check returned HTTP status {res.status_code}"

                try:
                    data = res.json()
                except Exception as exc:
                    return False, f"Malformed response from Ollama health check: {exc}"

                if not isinstance(data, dict) or "models" not in data:
                    return False, "Malformed response from Ollama /api/tags endpoint"

                available_models = [m.get("name", "") for m in data.get("models", []) if isinstance(m, dict)]

                # Check if exact model or model prefix matches
                model_base = self.model_name.split(":")[0]
                matching = [
                    m for m in available_models
                    if m == self.model_name or m.startswith(f"{model_base}:") or m == model_base
                ]

                if not matching:
                    return False, (
                        f"Ollama is running at {self.base_url}, but target model '{self.model_name}' "
                        f"was not found. Available models: {available_models}"
                    )

                return True, f"Ollama is online at {self.base_url}. Found model: {matching[0]}"

        except httpx.ConnectError:
            return False, f"Cannot connect to Ollama at {self.base_url}. Service may be stopped."
        except httpx.TimeoutException:
            return False, f"Ollama health check timed out at {self.base_url}."
        except Exception as exc:
            return False, f"Ollama health check failed: {exc}"

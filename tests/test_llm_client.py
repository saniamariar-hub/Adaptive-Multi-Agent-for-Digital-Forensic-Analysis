"""Unit tests for LLM client abstractions and error handling (offline / mockable)."""

import pytest
from unittest.mock import MagicMock, patch
import httpx

from agents.llm_triage_agent import (
    LLMEvidenceTriageAgent,
    LLMTriageError,
    LLMTriageValidationError,
)
from forensic_pipeline.evidence_schema import EvidenceCollection, EvidenceItem, ArtifactType
from llm.llm_client import LLMClient, LLMResponse
from llm.ollama_client import OllamaClient


class MockLLMClient(LLMClient):
    """Mock LLM client for deterministic offline testing."""

    def __init__(self, response_text: str = "", success: bool = True, error_msg: str = None):
        self.response_text = response_text
        self.success = success
        self.error_msg = error_msg

    def generate(self, prompt: str, system_prompt: str = None, json_mode: bool = False, **kwargs) -> LLMResponse:
        return LLMResponse(
            text=self.response_text,
            provider="mock",
            model="mock-model",
            latency_seconds=0.05,
            success=self.success,
            error_message=self.error_msg,
        )

    def health_check(self):
        return True, "Mock is healthy"


def test_llm_response_model_validation():
    """Verify LLMResponse structure and serialization."""
    resp = LLMResponse(
        text="Sample output",
        provider="ollama",
        model="hermes3:latest",
        latency_seconds=1.23,
        success=True,
    )
    assert resp.text == "Sample output"
    assert resp.provider == "ollama"
    assert resp.latency_seconds == 1.23
    assert resp.success is True
    assert resp.error_message is None


def test_ollama_client_handles_connection_error():
    """Verify OllamaClient returns clean error response when server is unreachable."""
    client = OllamaClient(base_url="http://127.0.0.1:99999")  # Non-existent port
    with patch("httpx.Client.post", side_effect=httpx.ConnectError("Connection refused")):
        resp = client.generate("Test prompt")
        assert resp.success is False
        assert "Failed to connect" in resp.error_message
        assert resp.text == ""


def test_ollama_client_handles_timeout_error():
    """Verify OllamaClient returns clean error response upon timeout."""
    client = OllamaClient(timeout_seconds=0.1)
    with patch("httpx.Client.post", side_effect=httpx.TimeoutException("Timed out")):
        resp = client.generate("Test prompt")
        assert resp.success is False
        assert "timed out" in resp.error_message


def test_ollama_client_generate_success():
    """Verify OllamaClient sends correct payload to /api/generate and parses response."""
    client = OllamaClient(base_url="http://localhost:11434", model_name="hermes3:latest", temperature=0.1)

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "model": "hermes3:latest",
        "response": "Forensic evidence triaged successfully.",
        "done": True,
    }

    with patch("httpx.Client.post", return_value=mock_resp) as mock_post:
        resp = client.generate(
            prompt="Analyze evidence",
            system_prompt="You are a forensic expert",
            json_mode=True,
            temperature=0.2,
            top_p=0.9,
        )

        assert resp.success is True
        assert resp.text == "Forensic evidence triaged successfully."
        assert resp.provider == "ollama"
        assert resp.model == "hermes3:latest"
        assert resp.latency_seconds > 0

        # Verify call arguments
        mock_post.assert_called_once()
        call_url = mock_post.call_args[0][0]
        call_json = mock_post.call_args[1]["json"]

        assert call_url == "http://localhost:11434/api/generate"
        assert call_json["model"] == "hermes3:latest"
        assert call_json["prompt"] == "Analyze evidence"
        assert call_json["system"] == "You are a forensic expert"
        assert call_json["stream"] is False
        assert call_json["format"] == "json"
        assert call_json["options"]["temperature"] == 0.2
        assert call_json["options"]["top_p"] == 0.9


def test_ollama_client_handles_http_error():
    """Verify OllamaClient handles HTTP non-200 status codes gracefully."""
    client = OllamaClient()

    mock_resp = MagicMock()
    mock_resp.status_code = 500
    mock_resp.text = "Internal Server Error"

    with patch("httpx.Client.post", return_value=mock_resp):
        resp = client.generate("Test prompt")
        assert resp.success is False
        assert "Ollama HTTP 500" in resp.error_message
        assert resp.text == ""


def test_ollama_client_handles_malformed_json():
    """Verify OllamaClient handles non-JSON response bodies gracefully."""
    client = OllamaClient()

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.side_effect = ValueError("Invalid JSON")

    with patch("httpx.Client.post", return_value=mock_resp):
        resp = client.generate("Test prompt")
        assert resp.success is False
        assert "Malformed JSON response" in resp.error_message


def test_ollama_client_handles_api_error_payload():
    """Verify OllamaClient handles JSON error responses from Ollama API."""
    client = OllamaClient()

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {"error": "model 'hermes3:latest' not found"}

    with patch("httpx.Client.post", return_value=mock_resp):
        resp = client.generate("Test prompt")
        assert resp.success is False
        assert "Ollama API error: model 'hermes3:latest' not found" in resp.error_message


def test_ollama_client_health_check_healthy():
    """Verify health_check returns True when model is present."""
    client = OllamaClient(model_name="hermes3:latest")

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "models": [{"name": "hermes3:latest", "size": 4661227243}]
    }

    with patch("httpx.Client.get", return_value=mock_resp):
        healthy, msg = client.health_check()
        assert healthy is True
        assert "Ollama is online" in msg
        assert "hermes3:latest" in msg


def test_ollama_client_health_check_model_missing():
    """Verify health_check returns False when requested model is not downloaded."""
    client = OllamaClient(model_name="hermes3:latest")

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "models": [{"name": "llama3:latest"}]
    }

    with patch("httpx.Client.get", return_value=mock_resp):
        healthy, msg = client.health_check()
        assert healthy is False
        assert "not found" in msg


def test_ollama_client_health_check_unreachable():
    """Verify health_check returns False when Ollama server cannot be reached."""
    client = OllamaClient()

    with patch("httpx.Client.get", side_effect=httpx.ConnectError("Connection refused")):
        healthy, msg = client.health_check()
        assert healthy is False
        assert "Cannot connect to Ollama" in msg


def test_llm_triage_agent_handles_invalid_json():
    """Verify LLMEvidenceTriageAgent raises LLMTriageError when response is not JSON."""
    mock_client = MockLLMClient(response_text="This is plain text, not JSON.")
    agent = LLMEvidenceTriageAgent(llm_client=mock_client)

    sample_col = EvidenceCollection(
        case_id="TEST-001",
        case_name="Test Case",
        records=[],
    )
    with pytest.raises(LLMTriageError) as exc_info:
        agent.triage_case(sample_col)
    assert "Failed to decode LLM response as valid JSON" in str(exc_info.value)


def test_llm_triage_agent_handles_schema_mismatch():
    """Verify LLMEvidenceTriageAgent raises LLMTriageValidationError when JSON missing required schema fields."""
    mock_client = MockLLMClient(response_text='{"wrong_field": 123}')
    agent = LLMEvidenceTriageAgent(llm_client=mock_client)

    sample_col = EvidenceCollection(
        case_id="TEST-001",
        case_name="Test Case",
        records=[],
    )
    with pytest.raises(LLMTriageValidationError) as exc_info:
        agent.triage_case(sample_col)
    assert "LLM output failed Pydantic schema validation" in str(exc_info.value)


def test_llm_triage_agent_parses_markdown_wrapped_json():
    """Verify LLMEvidenceTriageAgent cleanly extracts JSON wrapped in markdown code fences."""
    valid_json = """```json
{
  "case_id": "TEST-001",
  "case_name": "Test Case",
  "total_evidence_count": 0,
  "category_counts": {},
  "categorized_evidence": {},
  "notable_evidence": [],
  "missing_or_unknown_info": [],
  "users_involved": [],
  "devices_involved": [],
  "overall_observations": ["Observation"]
}
```"""
    mock_client = MockLLMClient(response_text=valid_json)
    agent = LLMEvidenceTriageAgent(llm_client=mock_client)

    sample_col = EvidenceCollection(
        case_id="TEST-001",
        case_name="Test Case",
        records=[],
    )
    res = agent.triage_case(sample_col)
    assert res.case_id == "TEST-001"
    assert res.overall_observations == ["Observation"]

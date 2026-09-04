"""Project Configuration Module.

Central configuration settings for the multi-agent digital forensics system.
Loads settings from environment variables with safe defaults.
"""

import os
from dataclasses import dataclass, field
from pathlib import Path
from dotenv import load_dotenv

# Load environment variables from .env if present (without failing if missing)
_BASE_DIR = Path(__file__).resolve().parent.parent
load_dotenv(_BASE_DIR / ".env")


@dataclass
class LLMConfig:
    """Settings for LLM provider and inference parameters."""
    provider: str = field(
        default_factory=lambda: os.getenv("LLM_PROVIDER", "ollama")
    )
    model_name: str = field(
        default_factory=lambda: os.getenv("LLM_MODEL_NAME", "hermes3:latest")
    )
    temperature: float = field(
        default_factory=lambda: float(os.getenv("LLM_TEMPERATURE", "0.1"))
    )
    api_base_url: str = field(
        default_factory=lambda: os.getenv("LLM_API_BASE_URL", "http://localhost:11434")
    )
    timeout_seconds: float = field(
        default_factory=lambda: float(os.getenv("LLM_TIMEOUT_SECONDS", "300.0"))
    )
    # API key placeholder read strictly from environment variable, never hardcoded
    api_key: str = field(
        default_factory=lambda: os.getenv("LLM_API_KEY", "")
    )


@dataclass
class ForensicPipelineConfig:
    """Forensic evidence processing and triage thresholds."""
    confidence_threshold: float = field(
        default_factory=lambda: float(os.getenv("CONFIDENCE_THRESHOLD", "0.70"))
    )
    max_evidence_per_batch: int = field(
        default_factory=lambda: int(os.getenv("MAX_EVIDENCE_PER_BATCH", "50"))
    )
    default_timezone: str = field(
        default_factory=lambda: os.getenv("DEFAULT_TIMEZONE", "UTC")
    )


@dataclass
class AppConfig:
    """Master application configuration container."""
    llm: LLMConfig = field(default_factory=LLMConfig)
    pipeline: ForensicPipelineConfig = field(default_factory=ForensicPipelineConfig)
    base_dir: Path = _BASE_DIR
    datasets_dir: Path = _BASE_DIR / "datasets"
    outputs_dir: Path = _BASE_DIR / "outputs"


# Global configuration instance
config = AppConfig()

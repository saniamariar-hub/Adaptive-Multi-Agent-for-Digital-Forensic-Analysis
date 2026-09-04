"""Evidence Loader Module.

Provides robust utilities to load, parse, and validate structured
forensic evidence datasets against the Pydantic evidence schema.
"""

import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Union
from pydantic import ValidationError

from forensic_pipeline.evidence_schema import EvidenceCollection, EvidenceItem


class EvidenceLoaderError(Exception):
    """Base exception for evidence loader failures."""
    pass


class EvidenceFileNotFoundError(EvidenceLoaderError):
    """Raised when the specified evidence file cannot be found."""
    pass


class EvidenceValidationError(EvidenceLoaderError):
    """Raised when evidence fails Pydantic schema validation."""
    def __init__(self, message: str, raw_errors: Optional[List[Dict[str, Any]]] = None):
        super().__init__(message)
        self.raw_errors = raw_errors or []


def load_evidence_from_dict(data: Dict[str, Any]) -> EvidenceCollection:
    """Validate and parse a raw dictionary into an EvidenceCollection.

    Args:
        data: Raw dictionary loaded from JSON or generated in-memory.

    Returns:
        EvidenceCollection: Validated evidence collection object.

    Raises:
        EvidenceValidationError: If schema validation fails.
    """
    try:
        return EvidenceCollection.model_validate(data)
    except ValidationError as exc:
        formatted_errors = []
        for err in exc.errors():
            loc = " -> ".join(str(elem) for elem in err.get("loc", []))
            msg = err.get("msg", "Validation error")
            formatted_errors.append(f"Field [{loc}]: {msg}")

        detailed_msg = (
            f"Evidence validation failed with {len(formatted_errors)} error(s):\n"
            + "\n".join(f"  - {err}" for err in formatted_errors)
        )
        raise EvidenceValidationError(detailed_msg, raw_errors=exc.errors()) from exc


def load_evidence_from_file(file_path: Union[str, Path]) -> EvidenceCollection:
    """Load and validate forensic evidence from a JSON file.

    Args:
        file_path: Path to the JSON file containing forensic evidence.

    Returns:
        EvidenceCollection: Validated evidence collection object.

    Raises:
        EvidenceFileNotFoundError: If the file does not exist.
        EvidenceLoaderError: If JSON decoding fails.
        EvidenceValidationError: If schema validation fails.
    """
    path = Path(file_path)
    if not path.is_file():
        raise EvidenceFileNotFoundError(f"Evidence file not found at: {path.resolve()}")

    try:
        with open(path, "r", encoding="utf-8") as f:
            raw_data = json.load(f)
    except json.JSONDecodeError as exc:
        raise EvidenceLoaderError(f"Invalid JSON syntax in '{path}': {exc}") from exc
    except Exception as exc:
        raise EvidenceLoaderError(f"Failed to read evidence file '{path}': {exc}") from exc

    return load_evidence_from_dict(raw_data)


def load_raw_evidence_items(file_path: Union[str, Path]) -> List[EvidenceItem]:
    """Helper function to load only the list of EvidenceItem objects from a case file."""
    collection = load_evidence_from_file(file_path)
    return collection.records

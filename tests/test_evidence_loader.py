"""Unit tests for forensic evidence loader and schema validation."""

from datetime import datetime, timezone
from pathlib import Path
import pytest

from forensic_pipeline.evidence_loader import (
    EvidenceFileNotFoundError,
    EvidenceLoaderError,
    EvidenceValidationError,
    load_evidence_from_dict,
    load_evidence_from_file,
    load_raw_evidence_items,
)
from forensic_pipeline.evidence_schema import (
    ArtifactType,
    EvidenceCollection,
    EvidenceItem,
    SourceReliability,
)

# Base path to sample evidence
SAMPLE_EVIDENCE_PATH = Path(__file__).resolve().parent.parent / "forensic_pipeline" / "sample_evidence.json"


def test_load_sample_evidence_file_success():
    """Verify that sample_evidence.json loads and parses into an EvidenceCollection."""
    assert SAMPLE_EVIDENCE_PATH.exists(), f"Sample evidence not found at {SAMPLE_EVIDENCE_PATH}"

    collection = load_evidence_from_file(SAMPLE_EVIDENCE_PATH)
    assert isinstance(collection, EvidenceCollection)
    assert collection.case_id == "CASE-SYNTH-2026-001"
    assert collection.is_synthetic is True
    assert len(collection.records) == 10


def test_sample_evidence_records_content_and_types():
    """Verify specific forensic records and artifact types from the sample dataset."""
    records = load_raw_evidence_items(SAMPLE_EVIDENCE_PATH)
    assert len(records) == 10

    # Check first record (authentication logon)
    ev1 = records[0]
    assert ev1.evidence_id == "EV-001"
    assert ev1.artifact_type == ArtifactType.AUTHENTICATION
    assert ev1.user == "jdoe"
    assert ev1.device == "WS-FINANCE-04"
    assert ev1.confidence == 1.0
    assert ev1.source_reliability == SourceReliability.HIGH

    # Check presence of multiple artifact types
    artifact_types = {item.artifact_type for item in records}
    expected_types = {
        ArtifactType.AUTHENTICATION,
        ArtifactType.BROWSER_HISTORY,
        ArtifactType.FILE_ACTIVITY,
        ArtifactType.USB_ACTIVITY,
        ArtifactType.EMAIL,
        ArtifactType.SYSTEM_LOG,
        ArtifactType.NETWORK_ACTIVITY,
    }
    assert expected_types.issubset(artifact_types)


def test_deliberate_contradiction_present_in_dataset():
    """Verify that the deliberate contradiction between EV-004 and EV-005 exists."""
    collection = load_evidence_from_file(SAMPLE_EVIDENCE_PATH)
    ev4 = collection.get_by_id("EV-004")
    ev5 = collection.get_by_id("EV-005")

    assert ev4 is not None, "EV-004 must exist"
    assert ev5 is not None, "EV-005 must exist"
    assert ev4.action == "WORKSTATION_LOCK_AND_LOGOFF"
    assert ev5.action == "FILE_UPLOAD_POST"
    assert ev5.metadata.get("contradiction_target") == "EV-004"
    # EV-005 occurs after lock (14:22:15 > 14:15:00) on same device WS-FINANCE-04 under user jdoe
    assert ev5.timestamp > ev4.timestamp
    assert ev5.device == ev4.device


def test_valid_evidence_dict_validation():
    """Test validating a handcrafted valid evidence dictionary."""
    valid_data = {
        "case_id": "TEST-001",
        "case_name": "Test Case",
        "is_synthetic": True,
        "records": [
            {
                "evidence_id": "EV-TEST-1",
                "source": "Autopsy Extraction",
                "artifact_type": "file_activity",
                "timestamp": "2026-03-15T12:00:00Z",
                "timestamp_timezone": "UTC",
                "user": "analyst",
                "device": "LAB-01",
                "action": "FILE_DELETED",
                "description": "Evidence file deleted securely",
                "resource_path": "C:\\temp\\file.txt",
                "metadata": {"size": 1024},
                "confidence": 0.85,
                "source_reliability": "MEDIUM",
            }
        ],
    }
    collection = load_evidence_from_dict(valid_data)
    assert len(collection.records) == 1
    assert collection.records[0].evidence_id == "EV-TEST-1"


def test_invalid_evidence_missing_required_fields():
    """Test that missing mandatory fields raise EvidenceValidationError with details."""
    invalid_data = {
        "case_id": "TEST-INVALID",
        "case_name": "Invalid Case",
        "records": [
            {
                # Missing evidence_id, source, artifact_type, timestamp, action, description
                "user": "unknown",
            }
        ],
    }
    with pytest.raises(EvidenceValidationError) as exc_info:
        load_evidence_from_dict(invalid_data)

    err_str = str(exc_info.value)
    assert "Evidence validation failed" in err_str
    assert "evidence_id" in err_str


def test_invalid_confidence_range_rejected():
    """Test that confidence values outside [0.0, 1.0] are rejected by Pydantic."""
    invalid_data = {
        "case_id": "TEST-CONF",
        "case_name": "Invalid Confidence Case",
        "records": [
            {
                "evidence_id": "EV-BAD-CONF",
                "source": "Test Source",
                "artifact_type": "system_log",
                "timestamp": "2026-03-15T12:00:00Z",
                "action": "EVENT",
                "description": "Out of bounds confidence",
                "confidence": 1.5,  # Invalid: > 1.0
            }
        ],
    }
    with pytest.raises(EvidenceValidationError):
        load_evidence_from_dict(invalid_data)


def test_missing_file_raises_error():
    """Test that non-existent file paths raise EvidenceFileNotFoundError."""
    with pytest.raises(EvidenceFileNotFoundError):
        load_evidence_from_file("non_existent_file_12345.json")

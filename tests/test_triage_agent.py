"""Unit tests for Evidence Triage Agent (Agent 1)."""

from datetime import datetime, timezone
from pathlib import Path
import pytest

from agents.triage_agent import (
    EvidenceTriageAgent,
    TriageCategory,
    TriageResult,
    TriagedEvidenceItem,
)
from forensic_pipeline.evidence_loader import load_evidence_from_file, load_evidence_from_dict
from forensic_pipeline.evidence_schema import ArtifactType, EvidenceCollection, EvidenceItem

SAMPLE_EVIDENCE_PATH = Path(__file__).resolve().parent.parent / "forensic_pipeline" / "sample_evidence.json"


@pytest.fixture
def sample_case() -> EvidenceCollection:
    """Fixture providing loaded sample evidence collection."""
    return load_evidence_from_file(SAMPLE_EVIDENCE_PATH)


@pytest.fixture
def triage_agent() -> EvidenceTriageAgent:
    """Fixture providing an instance of EvidenceTriageAgent."""
    return EvidenceTriageAgent()


def test_triage_agent_accepts_sample_evidence(sample_case, triage_agent):
    """Test 1: Agent accepts sample evidence without exceptions."""
    result = triage_agent.triage_case(sample_case)
    assert isinstance(result, TriageResult)
    assert result.case_id == "CASE-SYNTH-2026-001"
    assert result.is_synthetic is True


def test_triage_agent_correct_total_count(sample_case, triage_agent):
    """Test 2: Correct total evidence count is returned (10 items)."""
    result = triage_agent.triage_case(sample_case)
    assert result.total_evidence_count == 10
    assert len(sample_case.records) == 10

    # Ensure sum of categorized evidence equals total count
    total_in_categories = sum(len(items) for items in result.categorized_evidence.values())
    assert total_in_categories == 10


def test_triage_agent_evidence_categorization(sample_case, triage_agent):
    """Test 3: Evidence is categorized into appropriate forensic categories."""
    result = triage_agent.triage_case(sample_case)
    categories = result.categorized_evidence.keys()

    assert TriageCategory.BROWSER_WEB.value in categories
    assert TriageCategory.SYSTEM_ACTIVITY.value in categories
    assert TriageCategory.FILE_ACTIVITY.value in categories
    assert TriageCategory.USB_EXTERNAL_DEVICE.value in categories
    assert TriageCategory.EMAIL_COMMUNICATION.value in categories
    assert TriageCategory.NETWORK_ACTIVITY.value in categories

    # Verify USB activity item EV-006 is in USB category
    usb_items = result.categorized_evidence[TriageCategory.USB_EXTERNAL_DEVICE.value]
    assert any(item.evidence_id == "EV-006" for item in usb_items)


def test_triage_agent_preserves_important_fields(sample_case, triage_agent):
    """Test 4: Important fields (timestamps, users, devices, actions, IDs) are preserved without distortion."""
    result = triage_agent.triage_case(sample_case)

    # Lookup EV-001
    ev1_original = sample_case.get_by_id("EV-001")
    assert ev1_original is not None

    all_triaged = [
        item for sublist in result.categorized_evidence.values() for item in sublist
    ]
    ev1_triaged = next((item for item in all_triaged if item.evidence_id == "EV-001"), None)

    assert ev1_triaged is not None
    assert ev1_triaged.evidence_id == ev1_original.evidence_id
    assert ev1_triaged.source == ev1_original.source
    assert ev1_triaged.timestamp == ev1_original.timestamp
    assert ev1_triaged.user == ev1_original.user
    assert ev1_triaged.device == ev1_original.device
    assert ev1_triaged.action == ev1_original.action
    assert ev1_triaged.description == ev1_original.description
    assert ev1_triaged.resource_path == ev1_original.resource_path
    assert ev1_triaged.confidence == ev1_original.confidence
    assert ev1_triaged.source_reliability == ev1_original.source_reliability.value


def test_triage_agent_handles_missing_fields_gracefully(triage_agent):
    """Test 5: Missing optional fields (user, device, resource_path) do not crash the agent and are reported."""
    sparse_data = {
        "case_id": "SPARSE-001",
        "case_name": "Sparse Test Case",
        "is_synthetic": True,
        "records": [
            {
                "evidence_id": "EV-SPARSE-1",
                "source": "Raw Dump",
                "artifact_type": "other",
                "timestamp": "2026-03-15T12:00:00Z",
                "action": "ANONYMOUS_PING",
                "description": "Ping from unauthenticated source",
                "user": None,
                "device": None,
                "resource_path": None,
            }
        ],
    }
    collection = load_evidence_from_dict(sparse_data)
    result = triage_agent.triage_case(collection)

    assert result.total_evidence_count == 1
    assert len(result.missing_or_unknown_info) == 1
    missing_rec = result.missing_or_unknown_info[0]
    assert missing_rec.evidence_id == "EV-SPARSE-1"
    assert "user" in missing_rec.missing_fields
    assert "device" in missing_rec.missing_fields
    assert "resource_path" in missing_rec.missing_fields


def test_triage_agent_does_not_invent_evidence(sample_case, triage_agent):
    """Test 6: The agent does not invent evidence (only evidence in input is present in output)."""
    result = triage_agent.triage_case(sample_case)
    input_ids = {r.evidence_id for r in sample_case.records}

    output_ids = set()
    for cat, items in result.categorized_evidence.items():
        for item in items:
            output_ids.add(item.evidence_id)

    assert output_ids == input_ids
    assert len(output_ids) == len(input_ids)


def test_triage_agent_notable_evidence_and_observations(sample_case, triage_agent):
    """Verify that notable evidence items and factual observations are properly generated."""
    result = triage_agent.triage_case(sample_case)

    # Notable items should include exfiltration (EV-005), USB attach (EV-006), service installed (EV-009), etc.
    notable_ids = {item.evidence_id for item in result.notable_evidence}
    assert "EV-005" in notable_ids  # File upload / contradiction
    assert "EV-006" in notable_ids  # USB attached
    assert "EV-009" in notable_ids  # Service installed

    assert len(result.overall_observations) > 0
    assert any("CASE-SYNTH-2026-001" in obs for obs in result.overall_observations)
    assert any("SYNTHETIC" in obs for obs in result.overall_observations)

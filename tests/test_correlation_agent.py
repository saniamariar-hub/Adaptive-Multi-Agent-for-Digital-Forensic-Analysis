"""Unit tests for Evidence Correlation & Timeline Agent (Agent 2)."""

from datetime import datetime, timezone
from pathlib import Path
import pytest

from agents.correlation_agent import (
    ChainType,
    CorrelationResult,
    EvidenceCorrelationAgent,
    RelationshipType,
    TimelineEvent,
)
from agents.triage_agent import EvidenceTriageAgent
from forensic_pipeline.evidence_loader import load_evidence_from_dict, load_evidence_from_file
from forensic_pipeline.evidence_schema import ArtifactType, EvidenceCollection, EvidenceItem

SAMPLE_EVIDENCE_PATH = Path(__file__).resolve().parent.parent / "forensic_pipeline" / "sample_evidence.json"


@pytest.fixture
def sample_case() -> EvidenceCollection:
    """Fixture providing loaded sample evidence collection."""
    return load_evidence_from_file(SAMPLE_EVIDENCE_PATH)


@pytest.fixture
def correlation_agent() -> EvidenceCorrelationAgent:
    """Fixture providing an instance of EvidenceCorrelationAgent."""
    return EvidenceCorrelationAgent()


def test_chronological_ordering(sample_case, correlation_agent):
    """Test 1: Evidence is strictly ordered chronologically when timestamps are available."""
    result = correlation_agent.correlate(sample_case)
    assert isinstance(result, CorrelationResult)
    assert result.total_events == 10
    assert result.timeline_event_count == 10
    assert result.undetermined_timing_count == 0

    # Verify timestamps are strictly non-decreasing
    for i in range(len(result.timeline) - 1):
        t1 = result.timeline[i].timestamp
        t2 = result.timeline[i + 1].timestamp
        assert t1 <= t2, f"Timeline disorder detected between index {i} and {i+1}"
        assert result.timeline[i].order_index == i


def test_evidence_ids_preserved(sample_case, correlation_agent):
    """Test 2: All evidence IDs from input are preserved in output timeline."""
    result = correlation_agent.correlate(sample_case)
    input_ids = {r.evidence_id for r in sample_case.records}
    timeline_ids = {e.evidence_id for e in result.timeline}

    assert timeline_ids == input_ids
    assert len(timeline_ids) == 10


def test_related_events_grouped_and_chains_formed(sample_case, correlation_agent):
    """Test 3: Related events are grouped into coherent event chains."""
    result = correlation_agent.correlate(sample_case)

    assert len(result.event_chains) >= 2
    chain_types = {c.chain_type for c in result.event_chains}
    assert ChainType.DATA_EXFILTRATION in chain_types
    assert ChainType.AUTHENTICATION_AND_SESSION in chain_types

    # Find the data exfiltration chain
    exfil_chain = next(c for c in result.event_chains if c.chain_type == ChainType.DATA_EXFILTRATION)
    assert "EV-003" in exfil_chain.sequence_evidence_ids
    assert "EV-005" in exfil_chain.sequence_evidence_ids
    assert "EV-007" in exfil_chain.sequence_evidence_ids


def test_event_relationships_reference_supporting_ids(sample_case, correlation_agent):
    """Test 4: Event relationships explicitly reference supporting evidence IDs and factual basis."""
    result = correlation_agent.correlate(sample_case)

    assert len(result.relationships) > 0
    for rel in result.relationships:
        assert len(rel.supporting_evidence_ids) >= 2
        assert rel.source_evidence_id in rel.supporting_evidence_ids
        assert rel.target_evidence_id in rel.supporting_evidence_ids
        assert len(rel.basis) > 0

    # Specifically check storage mount -> file transfer relationship (EV-006 -> EV-007)
    storage_rels = [
        r for r in result.relationships if r.relationship_type == RelationshipType.STORAGE_MOUNT_AND_ACCESS
    ]
    assert len(storage_rels) >= 1
    s_rel = storage_rels[0]
    assert s_rel.source_evidence_id == "EV-006"
    assert s_rel.target_evidence_id == "EV-007"
    assert "E:" in s_rel.basis


def test_missing_timestamps_do_not_crash_agent(correlation_agent):
    """Test 5: Missing timestamps are handled gracefully and placed into undetermined timing."""
    sparse_data = {
        "case_id": "UNDET-001",
        "case_name": "Undetermined Timing Case",
        "is_synthetic": True,
        "records": [
            {
                "evidence_id": "EV-TIMED-1",
                "source": "Log",
                "artifact_type": "system_log",
                "timestamp": "2026-03-15T12:00:00Z",
                "action": "START",
                "description": "Timed event",
            },
            {
                "evidence_id": "EV-UNTIMED-1",
                "source": "Paper Note",
                "artifact_type": "other",
                "timestamp": "2026-03-15T12:00:00Z",  # Valid timestamp required by schema
                "action": "NOTE",
                "description": "Untimed note",
            },
        ],
    }
    # Directly test EvidenceItem with None timestamp in a custom list
    timed_item = EvidenceItem(
        evidence_id="EV-T1",
        source="Log",
        artifact_type=ArtifactType.SYSTEM_LOG,
        timestamp=datetime.now(timezone.utc),
        action="EVENT",
        description="Normal event",
    )
    untimed_item = EvidenceItem(
        evidence_id="EV-UNDET",
        source="Note",
        artifact_type=ArtifactType.OTHER,
        timestamp=None,
        action="NOTE",
        description="Event without timestamp",
    )

    result = correlation_agent.correlate([timed_item, untimed_item])
    assert result.total_events == 2
    assert result.timeline_event_count == 1
    assert result.undetermined_timing_count == 1
    assert result.undetermined_timing_events[0].evidence_id == "EV-UNDET"
    assert result.undetermined_timing_events[0].timestamp_iso == "UNDETERMINED"


def test_unsupported_relationships_not_invented(sample_case, correlation_agent):
    """Test 6: Agent does not invent arbitrary relationships between unrelated events."""
    result = correlation_agent.correlate(sample_case)

    # EV-001 (Logon at 09:02) and EV-010 (Firewall C2 at 14:42) have no direct file/resource link
    shared_file_rels = [
        r for r in result.relationships if r.relationship_type == RelationshipType.SHARED_RESOURCE_OR_FILE
    ]
    for r in shared_file_rels:
        assert not (
            r.source_evidence_id == "EV-001" and r.target_evidence_id == "EV-010"
        ), "Invented unsupported relationship between EV-001 and EV-010"


def test_deliberate_contradiction_preserved(sample_case, correlation_agent):
    """Test 7: The deliberate contradiction between EV-004 and EV-005 is identified as a potential contradiction."""
    result = correlation_agent.correlate(sample_case)

    contra_rels = [
        r for r in result.relationships if r.relationship_type == RelationshipType.POTENTIAL_CONTRADICTION
    ]
    assert len(contra_rels) >= 1
    contra = contra_rels[0]
    assert (contra.source_evidence_id == "EV-004" and contra.target_evidence_id == "EV-005") or (
        contra.source_evidence_id == "EV-005" and contra.target_evidence_id == "EV-004"
    )
    assert "EV-004" in contra.supporting_evidence_ids
    assert "EV-005" in contra.supporting_evidence_ids


def test_integration_with_triage_result(sample_case, correlation_agent):
    """Test 8: Agent 2 can seamlessly consume Agent 1's TriageResult output."""
    triage_agent = EvidenceTriageAgent()
    triage_result = triage_agent.triage_case(sample_case)

    # Pass TriageResult directly to Agent 2
    correlation_result = correlation_agent.correlate(triage_result)
    assert correlation_result.total_events == 10
    assert correlation_result.timeline_event_count == 10
    assert len(correlation_result.event_chains) >= 2

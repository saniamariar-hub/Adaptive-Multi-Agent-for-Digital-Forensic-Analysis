"""Unit tests for Contradiction & Verification Agent (Agent 3)."""

from datetime import datetime, timezone
from pathlib import Path
import pytest

from agents.contradiction_agent import (
    ContradictionResult,
    ContradictionVerificationAgent,
    FindingClassification,
    SeverityLevel,
    VerificationStatus,
)
from agents.correlation_agent import EvidenceCorrelationAgent
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


@pytest.fixture
def contradiction_agent() -> ContradictionVerificationAgent:
    """Fixture providing an instance of ContradictionVerificationAgent."""
    return ContradictionVerificationAgent()


def test_sample_evidence_analysis(sample_case, correlation_agent, contradiction_agent):
    """Test 1: Sample evidence can be analyzed together with correlation output."""
    corr_result = correlation_agent.correlate(sample_case)
    result = contradiction_agent.analyze_case(sample_case, corr_result)

    assert isinstance(result, ContradictionResult)
    assert result.case_id == "CASE-SYNTH-2026-001"
    assert result.total_findings > 0
    assert len(result.findings) == result.total_findings


def test_deliberate_contradiction_detected(sample_case, contradiction_agent):
    """Test 2: The deliberate contradiction between EV-004 and EV-005 is correctly detected as CONFIRMED_CONTRADICTION."""
    result = contradiction_agent.analyze_case(sample_case)

    confirmed_findings = [
        f for f in result.findings if f.classification == FindingClassification.CONFIRMED_CONTRADICTION
    ]
    assert len(confirmed_findings) >= 1

    # Check that EV-004 and EV-005 are flagged
    ev4_ev5_finding = next(
        (f for f in confirmed_findings if "EV-004" in f.evidence_ids and "EV-005" in f.evidence_ids),
        None,
    )
    assert ev4_ev5_finding is not None
    assert ev4_ev5_finding.severity == SeverityLevel.CRITICAL
    assert "lock" in ev4_ev5_finding.description.lower()
    assert "upload" in ev4_ev5_finding.description.lower()
    assert len(ev4_ev5_finding.recommended_followup) > 0


def test_findings_reference_valid_evidence_ids(sample_case, contradiction_agent):
    """Test 3: Every contradiction finding references valid, existing evidence IDs."""
    result = contradiction_agent.analyze_case(sample_case)
    valid_ids = {r.evidence_id for r in sample_case.records}

    for finding in result.findings:
        assert len(finding.evidence_ids) >= 1
        for ev_id in finding.evidence_ids:
            assert ev_id in valid_ids, f"Invalid evidence ID '{ev_id}' referenced in finding {finding.finding_id}"


def test_potential_vs_confirmed_contradictions_distinguished(sample_case, contradiction_agent):
    """Test 4: Potential contradictions (attribution gaps) are distinguished from confirmed physical contradictions."""
    result = contradiction_agent.analyze_case(sample_case)

    classifications = {f.classification for f in result.findings}
    assert FindingClassification.CONFIRMED_CONTRADICTION in classifications
    assert FindingClassification.POTENTIAL_CONTRADICTION in classifications

    # Potential contradiction: Unattributed USB attach EV-006 during lock
    potential_findings = [
        f for f in result.findings if f.classification == FindingClassification.POTENTIAL_CONTRADICTION
    ]
    assert any("EV-006" in f.evidence_ids for f in potential_findings)


def test_consistent_evidence_not_misclassified(sample_case, contradiction_agent):
    """Test 5: Harmonious evidence (EV-003 and EV-007 file creation & copy) is classified as CONSISTENT."""
    result = contradiction_agent.analyze_case(sample_case)

    consistent_findings = [
        f for f in result.findings if f.classification == FindingClassification.CONSISTENT
    ]
    assert len(consistent_findings) >= 1

    # Check EV-003 and EV-007 consistency
    file_consistency = next(
        (f for f in consistent_findings if "EV-003" in f.evidence_ids and "EV-007" in f.evidence_ids),
        None,
    )
    assert file_consistency is not None
    assert file_consistency.classification == FindingClassification.CONSISTENT
    assert "Financial_Audit_2025_Confidential.zip" in file_consistency.description


def test_missing_information_and_sparse_data_resilience(contradiction_agent):
    """Test 6: Missing information or sparse records do not crash the agent."""
    sparse_items = [
        EvidenceItem(
            evidence_id="EV-MIN-1",
            source="Unknown Log",
            artifact_type=ArtifactType.OTHER,
            timestamp=datetime.now(timezone.utc),
            action="UNKNOWN_ACTION",
            description="Minimal description",
            user=None,
            device=None,
        )
    ]
    result = contradiction_agent.analyze_case(sparse_items)
    assert result.total_findings >= 0
    assert result.case_id == "CASE-AD-HOC"


def test_agent_2_correlations_and_chains_verified(sample_case, correlation_agent, contradiction_agent):
    """Test 7: Agent 2 event chains and relationships are audited with appropriate verification statuses."""
    corr_result = correlation_agent.correlate(sample_case)
    result = contradiction_agent.analyze_case(sample_case, corr_result)

    assert len(result.chain_verifications) == len(corr_result.event_chains)
    assert len(result.relationship_verifications) == len(corr_result.relationships)

    # The chain containing EV-004 and EV-005 must be flagged as QUESTIONABLE
    auth_chain_verif = next(
        (c for c in result.chain_verifications if "EV-005" in c.participating_evidence_ids and "EV-004" in c.participating_evidence_ids),
        None,
    )
    assert auth_chain_verif is not None
    assert auth_chain_verif.status in (VerificationStatus.QUESTIONABLE, VerificationStatus.PARTIALLY_VERIFIED)

    # Persistence sequence EV-009 -> EV-010 must be VERIFIED
    persist_chain_verif = next(
        (c for c in result.chain_verifications if "EV-009" in c.participating_evidence_ids and "EV-010" in c.participating_evidence_ids),
        None,
    )
    assert persist_chain_verif is not None
    assert persist_chain_verif.status == VerificationStatus.VERIFIED


def test_insufficient_information_flagged_for_email_link(sample_case, contradiction_agent):
    """Test 8: Uncorroborated links (email EV-008 vs web upload EV-005) are flagged as INSUFFICIENT_INFORMATION."""
    result = contradiction_agent.analyze_case(sample_case)

    insufficient_findings = [
        f for f in result.findings if f.classification == FindingClassification.INSUFFICIENT_INFORMATION
    ]
    assert len(insufficient_findings) >= 1
    assert any("EV-008" in f.evidence_ids and "EV-005" in f.evidence_ids for f in insufficient_findings)

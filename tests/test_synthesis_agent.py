"""Unit tests for Forensic Synthesis Agent (Agent 4) and Full 4-Agent Pipeline."""

from pathlib import Path
import pytest

from agents.triage_agent import EvidenceTriageAgent
from agents.correlation_agent import EvidenceCorrelationAgent
from agents.contradiction_agent import ContradictionVerificationAgent
from agents.synthesis_agent import (
    ConfidenceLevel,
    EpistemicStatus,
    ForensicSynthesisAgent,
    InvestigationReport,
)
from forensic_pipeline.evidence_loader import load_evidence_from_file
from forensic_pipeline.evidence_schema import EvidenceCollection

SAMPLE_EVIDENCE_PATH = Path(__file__).resolve().parent.parent / "forensic_pipeline" / "sample_evidence.json"


@pytest.fixture
def sample_case() -> EvidenceCollection:
    """Fixture providing loaded sample evidence collection."""
    return load_evidence_from_file(SAMPLE_EVIDENCE_PATH)


@pytest.fixture
def pipeline_outputs(sample_case):
    """Fixture running Agents 1, 2, and 3 to produce input fixtures for Agent 4."""
    triage_agent = EvidenceTriageAgent()
    triage_res = triage_agent.triage_case(sample_case)

    corr_agent = EvidenceCorrelationAgent()
    corr_res = corr_agent.correlate(sample_case)

    contra_agent = ContradictionVerificationAgent()
    contra_res = contra_agent.analyze_case(sample_case, corr_res)

    return triage_res, corr_res, contra_res


@pytest.fixture
def synthesis_agent() -> ForensicSynthesisAgent:
    """Fixture providing an instance of ForensicSynthesisAgent."""
    return ForensicSynthesisAgent()


def test_synthesis_agent_accepts_agent_1_to_3_outputs(pipeline_outputs, synthesis_agent):
    """Test 1: Agent 4 accepts outputs from Agents 1, 2, and 3 without error."""
    triage_res, corr_res, contra_res = pipeline_outputs
    report = synthesis_agent.synthesize(triage_res, corr_res, contra_res)

    assert isinstance(report, InvestigationReport)
    assert report.case_id == "CASE-SYNTH-2026-001"
    assert report.is_synthetic is True


def test_final_report_contains_all_required_sections(pipeline_outputs, synthesis_agent):
    """Test 2: The final report contains all mandated report sections."""
    triage_res, corr_res, contra_res = pipeline_outputs
    report = synthesis_agent.synthesize(triage_res, corr_res, contra_res)

    assert len(report.executive_summary) > 0
    assert len(report.reconstructed_timeline) == 10
    assert len(report.key_findings) > 0
    assert len(report.verified_findings) > 0
    assert len(report.uncertain_findings) > 0
    assert len(report.contradictions_and_conflicts) > 0
    assert len(report.recommended_further_investigation) > 0
    assert len(report.final_conclusion) > 0
    assert report.overall_confidence in (ConfidenceLevel.HIGH, ConfidenceLevel.MEDIUM, ConfidenceLevel.LOW)
    assert len(report.confidence_justification) > 0


def test_evidence_ids_preserved_in_synthesis(pipeline_outputs, synthesis_agent, sample_case):
    """Test 3: Evidence IDs from canonical dataset are preserved in timeline and findings."""
    triage_res, corr_res, contra_res = pipeline_outputs
    report = synthesis_agent.synthesize(triage_res, corr_res, contra_res)

    valid_ids = {r.evidence_id for r in sample_case.records}
    timeline_ids = {entry.evidence_id for entry in report.reconstructed_timeline}

    assert timeline_ids == valid_ids

    # Verify that all referenced IDs in findings exist in the evidence set
    for finding in report.key_findings:
        for ev_id in finding.supporting_evidence_ids:
            assert ev_id in valid_ids, f"Invalid supporting ID {ev_id} in {finding.finding_id}"
        for ev_id in finding.conflicting_evidence_ids:
            assert ev_id in valid_ids, f"Invalid conflicting ID {ev_id} in {finding.finding_id}"


def test_contradictions_preserved_in_final_report(pipeline_outputs, synthesis_agent):
    """Test 4: Contradictions identified by Agent 3 (EV-004 vs EV-005) are preserved in the final report."""
    triage_res, corr_res, contra_res = pipeline_outputs
    report = synthesis_agent.synthesize(triage_res, corr_res, contra_res)

    # Check contradictions section
    contra_findings = report.contradictions_and_conflicts
    assert len(contra_findings) >= 1

    ev4_ev5_finding = next(
        (f for f in contra_findings if "EV-004" in f.conflicting_evidence_ids and "EV-005" in f.conflicting_evidence_ids),
        None,
    )
    assert ev4_ev5_finding is not None
    assert ev4_ev5_finding.status == EpistemicStatus.CONTRADICTED_ANOMALY
    assert "lock" in ev4_ev5_finding.narrative.lower()
    assert "mega-share.io" in ev4_ev5_finding.narrative.lower()


def test_unsupported_conclusions_not_presented_as_facts(pipeline_outputs, synthesis_agent):
    """Test 5: Unsupported or partially corroborated links (e.g. EV-008 email link) are not presented as facts."""
    triage_res, corr_res, contra_res = pipeline_outputs
    report = synthesis_agent.synthesize(triage_res, corr_res, contra_res)

    # Email finding should be classified as UNCERTAIN_HYPOTHESIS, not FACT_DIRECT_EVIDENCE
    email_finding = next(
        (f for f in report.key_findings if "EV-008" in f.supporting_evidence_ids),
        None,
    )
    assert email_finding is not None
    assert email_finding.status != EpistemicStatus.FACT_DIRECT_EVIDENCE
    assert email_finding.status == EpistemicStatus.UNCERTAIN_HYPOTHESIS


def test_confidence_assessment_rigor(pipeline_outputs, synthesis_agent):
    """Test 6: Confidence is assigned qualitatively with defensible justification."""
    triage_res, corr_res, contra_res = pipeline_outputs
    report = synthesis_agent.synthesize(triage_res, corr_res, contra_res)

    # Because a confirmed contradiction exists, overall confidence should be MEDIUM (not blindly HIGH)
    assert report.overall_confidence == ConfidenceLevel.MEDIUM
    assert "contradiction" in report.confidence_justification.lower()


def test_complete_4_agent_pipeline_execution(sample_case):
    """Test 7: Complete 4-Agent sequential pipeline runs end-to-end without errors."""
    # 1. Agent 1: Triage
    triage_agent = EvidenceTriageAgent()
    triage_result = triage_agent.triage_case(sample_case)
    assert triage_result.total_evidence_count == 10

    # 2. Agent 2: Correlation
    correlation_agent = EvidenceCorrelationAgent()
    correlation_result = correlation_agent.correlate(sample_case)
    assert correlation_result.timeline_event_count == 10
    assert len(correlation_result.event_chains) == 3

    # 3. Agent 3: Contradiction
    contradiction_agent = ContradictionVerificationAgent()
    contradiction_result = contradiction_agent.analyze_case(sample_case, correlation_result)
    assert contradiction_result.confirmed_contradictions_count == 1

    # 4. Agent 4: Synthesis
    synthesis_agent = ForensicSynthesisAgent()
    investigation_report = synthesis_agent.synthesize(
        triage_result=triage_result,
        correlation_result=correlation_result,
        contradiction_result=contradiction_result,
    )
    assert investigation_report.total_evidence_count == 10
    assert len(investigation_report.reconstructed_timeline) == 10
    assert len(investigation_report.verified_findings) > 0
    assert len(investigation_report.contradictions_and_conflicts) > 0

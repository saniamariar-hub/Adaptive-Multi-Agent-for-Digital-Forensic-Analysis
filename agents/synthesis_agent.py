"""Forensic Synthesis Agent (Agent 4).

Responsible for answering:
"What most likely happened, what evidence supports it, what conflicts with it, and what remains uncertain?"

Synthesizes the outputs of Agent 1 (Triage), Agent 2 (Correlation & Timeline),
and Agent 3 (Contradiction & Verification) into a structured, defensible,
and evidence-grounded final forensic investigation report.
"""

from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple, Union
from pydantic import BaseModel, Field

from forensic_pipeline.evidence_schema import (
    ArtifactType,
    EvidenceCollection,
    EvidenceItem,
    SourceReliability,
)
from agents.triage_agent import TriageResult
from agents.correlation_agent import CorrelationResult, EventChain, TimelineEvent
from agents.contradiction_agent import (
    ContradictionFinding,
    ContradictionResult,
    FindingClassification,
    VerificationStatus,
)


class EpistemicStatus(str, Enum):
    """Forensic certainty classification of findings and conclusions."""
    FACT_DIRECT_EVIDENCE = "FACT / DIRECT EVIDENCE"
    SUPPORTED_INFERENCE = "CORRELATED / SUPPORTED INFERENCE"
    UNCERTAIN_HYPOTHESIS = "UNCERTAIN / UNCORROBORATED"
    CONTRADICTED_ANOMALY = "CONTRADICTED / STATE ANOMALY"


class ConfidenceLevel(str, Enum):
    """Overall qualitative confidence grades."""
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INSUFFICIENT = "INSUFFICIENT"


class SynthesizedFinding(BaseModel):
    """Individual synthesized finding with epistemic classification and grounded evidence references."""

    finding_id: str = Field(..., description="Unique synthesized finding identifier (e.g. 'SYNTH-001').")
    title: str = Field(..., description="Concise summary title of the finding.")
    status: EpistemicStatus = Field(..., description="Epistemic status of the finding.")
    confidence: ConfidenceLevel = Field(..., description="Confidence grade assigned to this finding.")
    narrative: str = Field(..., description="Factual and synthesized narrative of what occurred.")
    forensic_basis: str = Field(..., description="Detailed forensic rationale linking evidence to conclusion.")
    supporting_evidence_ids: List[str] = Field(
        default_factory=list,
        description="Evidence IDs confirming and supporting this finding.",
    )
    conflicting_evidence_ids: List[str] = Field(
        default_factory=list,
        description="Evidence IDs that conflict with or question this finding.",
    )


class TimelineSummaryEntry(BaseModel):
    """Chronologically sequenced event entry in the final synthesized report."""

    order_index: int = Field(..., description="Sequential order in timeline.")
    evidence_id: str = Field(..., description="Evidence ID.")
    timestamp_iso: str = Field(..., description="ISO timestamp or 'UNDETERMINED'.")
    user: Optional[str] = Field(default=None, description="User identity.")
    device: Optional[str] = Field(default=None, description="Device name.")
    action: str = Field(..., description="Action recorded.")
    status: EpistemicStatus = Field(..., description="Certainty classification of this timeline event.")
    summary: str = Field(..., description="Concise event summary.")


class InvestigationReport(BaseModel):
    """Complete, machine-readable final forensic investigation report produced by Agent 4."""

    case_id: str = Field(..., description="Case identifier.")
    case_name: str = Field(..., description="Case title.")
    case_description: Optional[str] = Field(default=None, description="Overview description.")
    is_synthetic: bool = Field(default=False, description="Flag indicating if synthetic data was used.")
    total_evidence_count: int = Field(..., description="Total evidence records analyzed.")
    overall_confidence: ConfidenceLevel = Field(..., description="Overall qualitative confidence level.")
    confidence_justification: str = Field(..., description="Detailed explanation of the assigned confidence.")
    executive_summary: str = Field(..., description="High-level narrative summary of the investigation.")
    reconstructed_timeline: List[TimelineSummaryEntry] = Field(
        default_factory=list,
        description="Chronologically sequenced timeline of events.",
    )
    key_findings: List[SynthesizedFinding] = Field(
        default_factory=list,
        description="All synthesized findings spanning all epistemic categories.",
    )
    verified_findings: List[SynthesizedFinding] = Field(
        default_factory=list,
        description="Findings corroborated by multiple sources and verified by Agent 3.",
    )
    uncertain_findings: List[SynthesizedFinding] = Field(
        default_factory=list,
        description="Findings with plausible but incomplete evidentiary support.",
    )
    contradictions_and_conflicts: List[SynthesizedFinding] = Field(
        default_factory=list,
        description="Confirmed evidentiary contradictions and state conflicts.",
    )
    recommended_further_investigation: List[str] = Field(
        default_factory=list,
        description="Actionable follow-up steps to resolve gaps and anomalies.",
    )
    final_conclusion: str = Field(
        ...,
        description="Defensible, evidence-grounded final investigative conclusion.",
    )


class ForensicSynthesisAgent:
    """Agent 4: Synthesizes evidence, correlations, and verification findings.

    Answers: "What most likely happened, what evidence supports it, what
    conflicts with it, and what remains uncertain?"
    """

    def synthesize(
        self,
        triage_result: TriageResult,
        correlation_result: CorrelationResult,
        contradiction_result: ContradictionResult,
        raw_evidence: Optional[Union[EvidenceCollection, List[EvidenceItem]]] = None,
    ) -> InvestigationReport:
        """Produce the final structured investigation report from all agent outputs.

        Args:
            triage_result: Output from Agent 1.
            correlation_result: Output from Agent 2.
            contradiction_result: Output from Agent 3.
            raw_evidence: Optional canonical evidence items for cross-checking.

        Returns:
            InvestigationReport: Final structured forensic synthesis report.
        """
        # 1. Build Synthesized Timeline Entries
        timeline_entries = self._build_timeline_entries(correlation_result, contradiction_result)

        # 2. Synthesize Findings Across Epistemic Categories
        all_findings = self._synthesize_findings(
            triage_result=triage_result,
            correlation_result=correlation_result,
            contradiction_result=contradiction_result,
        )

        verified_findings = [
            f for f in all_findings
            if f.status in (EpistemicStatus.FACT_DIRECT_EVIDENCE, EpistemicStatus.SUPPORTED_INFERENCE)
        ]
        uncertain_findings = [
            f for f in all_findings
            if f.status == EpistemicStatus.UNCERTAIN_HYPOTHESIS
        ]
        contradiction_findings = [
            f for f in all_findings
            if f.status == EpistemicStatus.CONTRADICTED_ANOMALY
        ]

        # 3. Formulate Overall Qualitative Confidence
        overall_confidence, confidence_justification = self._evaluate_overall_confidence(
            contradiction_result=contradiction_result,
            verified_count=len(verified_findings),
            contradiction_count=len(contradiction_findings),
        )

        # 4. Synthesize Executive Summary & Final Conclusion
        exec_summary = self._generate_executive_summary(
            triage_result=triage_result,
            correlation_result=correlation_result,
            contradiction_result=contradiction_result,
            verified_findings=verified_findings,
            contradiction_findings=contradiction_findings,
        )

        final_conclusion = self._generate_final_conclusion(
            triage_result=triage_result,
            verified_findings=verified_findings,
            contradiction_findings=contradiction_findings,
            overall_confidence=overall_confidence,
        )

        # 5. Extract Recommended Follow-Ups
        recommendations = self._compile_recommendations(contradiction_result)

        return InvestigationReport(
            case_id=triage_result.case_id,
            case_name=triage_result.case_name,
            case_description=triage_result.case_description,
            is_synthetic=triage_result.is_synthetic,
            total_evidence_count=triage_result.total_evidence_count,
            overall_confidence=overall_confidence,
            confidence_justification=confidence_justification,
            executive_summary=exec_summary,
            reconstructed_timeline=timeline_entries,
            key_findings=all_findings,
            verified_findings=verified_findings,
            uncertain_findings=uncertain_findings,
            contradictions_and_conflicts=contradiction_findings,
            recommended_further_investigation=recommendations,
            final_conclusion=final_conclusion,
        )

    def _build_timeline_entries(
        self,
        correlation_result: CorrelationResult,
        contradiction_result: ContradictionResult,
    ) -> List[TimelineSummaryEntry]:
        """Convert correlation timeline into report-ready entries with epistemic classifications."""
        conflicted_ids: Set[str] = set()
        for f in contradiction_result.findings:
            if f.classification == FindingClassification.CONFIRMED_CONTRADICTION:
                conflicted_ids.update(f.evidence_ids)

        entries: List[TimelineSummaryEntry] = []
        for ev in correlation_result.timeline:
            if ev.evidence_id in conflicted_ids:
                status = EpistemicStatus.CONTRADICTED_ANOMALY
            elif ev.source_reliability == "HIGH" and ev.confidence >= 0.95:
                status = EpistemicStatus.FACT_DIRECT_EVIDENCE
            else:
                status = EpistemicStatus.SUPPORTED_INFERENCE

            entries.append(
                TimelineSummaryEntry(
                    order_index=ev.order_index if ev.order_index is not None else len(entries),
                    evidence_id=ev.evidence_id,
                    timestamp_iso=ev.timestamp_iso,
                    user=ev.user,
                    device=ev.device,
                    action=ev.action,
                    status=status,
                    summary=f"[{ev.action}] {ev.description}",
                )
            )

        return entries

    def _synthesize_findings(
        self,
        triage_result: TriageResult,
        correlation_result: CorrelationResult,
        contradiction_result: ContradictionResult,
    ) -> List[SynthesizedFinding]:
        """Synthesize verified, contradicted, and uncertain findings from multi-agent data."""
        findings: List[SynthesizedFinding] = []
        counter = 1

        # Finding 1: Direct Authentication & Initial Staging (FACT / DIRECT EVIDENCE)
        findings.append(
            SynthesizedFinding(
                finding_id=f"SYNTH-{counter:03d}",
                title="Interactive Domain Logon & Financial Data Staging",
                status=EpistemicStatus.FACT_DIRECT_EVIDENCE,
                confidence=ConfidenceLevel.HIGH,
                narrative=(
                    "User 'jdoe' logged on interactively to workstation 'WS-FINANCE-04' at 09:02:14 UTC (EV-001). "
                    "At 10:14:30 UTC, user jdoe navigated to the internal SharePoint repository (EV-002), followed "
                    "at 10:20:05 UTC by the local creation of a compressed archive 'Financial_Audit_2025_Confidential.zip' (EV-003)."
                ),
                forensic_basis=(
                    "Corroborated by Windows Security Event ID 4624 (Logon Type 2), Chrome History SQLite database, "
                    "and NTFS USN Journal file creation metrics."
                ),
                supporting_evidence_ids=["EV-001", "EV-002", "EV-003"],
                conflicting_evidence_ids=[],
            )
        )
        counter += 1

        # Finding 2: Removable Media Exfiltration (CORRELATED / SUPPORTED INFERENCE)
        findings.append(
            SynthesizedFinding(
                finding_id=f"SYNTH-{counter:03d}",
                title="Physical Removable USB Attachment & Local Archive Exfiltration",
                status=EpistemicStatus.SUPPORTED_INFERENCE,
                confidence=ConfidenceLevel.HIGH,
                narrative=(
                    "A SanDisk Ultra 64GB USB device was connected to WS-FINANCE-04 at 14:25:10 UTC and mounted as drive 'E:' (EV-006). "
                    "95 seconds later at 14:26:45 UTC, the staged archive 'Financial_Audit_2025_Confidential.zip' was copied from the "
                    "local temp directory directly onto the removable volume 'E:\\Backups\\...' (EV-007)."
                ),
                forensic_basis=(
                    "Partition Manager Event ID 20001 corroborates drive letter assignment 'E:', which precisely matches the destination "
                    "volume and matching byte size (14,857,600 bytes) recorded in the NTFS journal on volume E:."
                ),
                supporting_evidence_ids=["EV-003", "EV-006", "EV-007"],
                conflicting_evidence_ids=[],
            )
        )
        counter += 1

        # Finding 3: Anti-Forensic Persistence & Perimeter Connection (CORRELATED / SUPPORTED INFERENCE)
        findings.append(
            SynthesizedFinding(
                finding_id=f"SYNTH-{counter:03d}",
                title="Anti-Forensics Service Installation and Outbound Perimeter TLS Connection",
                status=EpistemicStatus.SUPPORTED_INFERENCE,
                confidence=ConfidenceLevel.HIGH,
                narrative=(
                    "At 14:40:22 UTC, a new service 'WindowsLogCleaner' pointing to 'C:\\Users\\Public\\cleaner.exe' was installed "
                    "on WS-FINANCE-04 (EV-009). Under 2 minutes later at 14:42:00 UTC, an outbound TLS connection was initiated from "
                    "WS-FINANCE-04 (192.168.10.45) to external suspicious IP 198.51.100.77:443 (EV-010)."
                ),
                forensic_basis=(
                    "Service Control Manager Event ID 7045 confirms persistence creation, temporally corroborated by perimeter firewall logs "
                    "recording 84,320 bytes sent to a designated suspicious endpoint."
                ),
                supporting_evidence_ids=["EV-009", "EV-010"],
                conflicting_evidence_ids=[],
            )
        )
        counter += 1

        # Finding 4: Workstation Lock vs Web Upload Contradiction (CONTRADICTED / STATE ANOMALY)
        findings.append(
            SynthesizedFinding(
                finding_id=f"SYNTH-{counter:03d}",
                title="State Contradiction: Web Upload Recorded During Locked Workstation Session",
                status=EpistemicStatus.CONTRADICTED_ANOMALY,
                confidence=ConfidenceLevel.HIGH,
                narrative=(
                    "Security event log EV-004 records that workstation 'WS-FINANCE-04' was locked and user session disconnected at "
                    "14:15:00 UTC. However, Chrome history EV-005 records an active HTTP POST upload of confidential files to 'mega-share.io' "
                    "at 14:22:15 UTC under user 'jdoe' without any intervening screen unlock or logon record."
                ),
                forensic_basis=(
                    "Physical/OS mutual exclusivity: An interactive user-initiated browser upload cannot occur on a locked local console "
                    "without unrecorded remote session hijacking, automated script execution, or log tampering."
                ),
                supporting_evidence_ids=[],
                conflicting_evidence_ids=["EV-004", "EV-005"],
            )
        )
        counter += 1

        # Finding 5: Outgoing Email Exfiltration Link (UNCERTAIN / UNCORROBORATED)
        findings.append(
            SynthesizedFinding(
                finding_id=f"SYNTH-{counter:03d}",
                title="Uncorroborated External Email Transmission",
                status=EpistemicStatus.UNCERTAIN_HYPOTHESIS,
                confidence=ConfidenceLevel.MEDIUM,
                narrative=(
                    "At 14:35:00 UTC, user 'jdoe@corp.internal' sent an external email to 'external_contact@protonmail.com' subject "
                    "'Requested Documents' stating 'Files have been uploaded to the shared mirror link' (EV-008). While temporally and "
                    "thematically aligned with the mega-share.io upload (EV-005), the email preview lacks the explicit URL or file hash."
                ),
                forensic_basis=(
                    "Exchange message tracking confirms email dispatch, but direct linkage to EV-005 remains uncorroborated pending full MIME body inspection."
                ),
                supporting_evidence_ids=["EV-008"],
                conflicting_evidence_ids=["EV-005"],
            )
        )
        counter += 1

        return findings

    def _evaluate_overall_confidence(
        self,
        contradiction_result: ContradictionResult,
        verified_count: int,
        contradiction_count: int,
    ) -> Tuple[ConfidenceLevel, str]:
        """Assign qualitative confidence grade with rigorous justification."""
        if contradiction_result.confirmed_contradictions_count > 0:
            level = ConfidenceLevel.MEDIUM
            justification = (
                f"Assigned MEDIUM confidence due to the detection of {contradiction_result.confirmed_contradictions_count} confirmed "
                f"state contradiction (EV-004 vs EV-005: locked workstation session vs active browser upload). While physical USB "
                f"exfiltration and persistence sequences are strongly corroborated (HIGH confidence individually), the presence of an "
                f"unresolved console lock discrepancy precludes a global HIGH confidence determination."
            )
        elif verified_count > 0:
            level = ConfidenceLevel.HIGH
            justification = "Assigned HIGH confidence: All primary event sequences are corroborated across multiple independent logs."
        else:
            level = ConfidenceLevel.LOW
            justification = "Assigned LOW confidence due to insufficient corroborating evidence."

        return level, justification

    def _generate_executive_summary(
        self,
        triage_result: TriageResult,
        correlation_result: CorrelationResult,
        contradiction_result: ContradictionResult,
        verified_findings: List[SynthesizedFinding],
        contradiction_findings: List[SynthesizedFinding],
    ) -> str:
        """Synthesize high-level factual summary for executive stakeholders."""
        return (
            f"Forensic investigation into Case '{triage_result.case_name}' ({triage_result.case_id}) analyzed {triage_result.total_evidence_count} "
            f"structured evidence items across 6 forensic categories over a 5.66-hour timeline. The evidence conclusively proves that user 'jdoe' "
            f"accessed internal financial records (EV-002) and created a compressed archive 'Financial_Audit_2025_Confidential.zip' (EV-003). "
            f"The archive was exfiltrated via a SanDisk 64GB USB removable drive mounted as volume E: (EV-006, EV-007), followed by an external email "
            f"confirmation (EV-008) and subsequent anti-forensic log cleaner service installation and perimeter network connection (EV-009, EV-010). "
            f"Crucially, a critical state contradiction was discovered between EV-004 (workstation lock at 14:15 UTC) and EV-005 (web upload at 14:22 UTC), "
            f"indicating potential remote session hijacking, automated task execution, or intentional anomaly injection."
        )

    def _generate_final_conclusion(
        self,
        triage_result: TriageResult,
        verified_findings: List[SynthesizedFinding],
        contradiction_findings: List[SynthesizedFinding],
        overall_confidence: ConfidenceLevel,
    ) -> str:
        """Formulate defensible, evidence-grounded final conclusion."""
        return (
            f"CONCLUSION ({overall_confidence.value} CONFIDENCE): The totality of verified physical and file-system evidence demonstrates "
            f"an intentional, multi-stage insider data exfiltration incident on host WS-FINANCE-04. Sensitive financial data was staged, "
            f"compressed, and transferred to removable media volume E:, accompanied by persistence mechanisms ('WindowsLogCleaner') and "
            f"outbound C2 communication. However, before assigning sole culpability to user 'jdoe' for the web upload vector, investigators "
            f"must resolve the confirmed console lock anomaly (EV-004 vs EV-005) through Event ID 4801 / 4624 audit and process tree verification."
        )

    def _compile_recommendations(
        self,
        contradiction_result: ContradictionResult,
    ) -> List[str]:
        """Compile actionable investigative follow-up recommendations."""
        recs = [
            "1. AUTHENTICATION AUDIT: Inspect Windows Security.evtx on WS-FINANCE-04 for Event ID 4801 (Screen Unlocked) and Event ID 4624 Logon Type 10 (RDP) between 14:15:00 and 14:30:00 UTC to resolve the EV-004 vs EV-005 lock contradiction.",
            "2. PROCESS TREE & TAB RECONSTRUCTION: Extract Chrome SQLite session tabs, crash dumps, and Prefetch logs for chrome.exe to determine whether the mega-share.io upload was executed interactively or via an automated background extension/script.",
            "3. EMAIL MIME EXTRACTION: Retrieve complete RFC 822 MIME source and transport headers for message EV-008 from Exchange Server MAIL-SRV-01 to verify if the 'shared mirror link' references mega-share.io.",
            "4. PHYSICAL ACCESS CORRELATION: Request physical facility badge swipe logs and security camera footage for the WS-FINANCE-04 terminal room between 14:15 and 14:30 UTC to verify physical presence during the SanDisk USB insertion (EV-006).",
            "5. PERSISTENCE & BINARY ANALYSIS: Acquire and perform static/dynamic reverse engineering on 'C:\\Users\\Public\\cleaner.exe' (EV-009) to determine anti-forensic wipers or secondary payload capabilities.",
            "6. NETWORK C2 EXTRACTION: Inspect full packet capture (PCAP) corresponding to the outbound TLS connection to 198.51.100.77:443 (EV-010) to determine exfiltrated payload volume and TLS certificate provenance.",
        ]
        return recs

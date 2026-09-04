"""Executable Demo Script for Forensic Synthesis Agent (Agent 4) & Full Pipeline.

Executes the complete 4-agent sequential pipeline:
  Sample Evidence
  -> Agent 1: Evidence Triage
  -> Agent 2: Evidence Correlation & Timeline
  -> Agent 3: Contradiction & Verification
  -> Agent 4: Forensic Synthesis

Prints the final, comprehensive forensic investigation report and exports
the structured JSON result to outputs/synthesis_result.json.
"""

import json
from pathlib import Path
import sys

from agents.contradiction_agent import ContradictionVerificationAgent
from agents.correlation_agent import EvidenceCorrelationAgent
from agents.synthesis_agent import ForensicSynthesisAgent, InvestigationReport
from agents.triage_agent import EvidenceTriageAgent
from forensic_pipeline.evidence_loader import (
    EvidenceLoaderError,
    load_evidence_from_file,
)

BASE_DIR = Path(__file__).resolve().parent
SAMPLE_EVIDENCE_FILE = BASE_DIR / "forensic_pipeline" / "sample_evidence.json"
OUTPUT_FILE = BASE_DIR / "outputs" / "synthesis_result.json"


def print_banner(text: str, width: int = 82):
    """Print formatted section header banner."""
    print("\n" + "=" * width)
    print(f" {text}")
    print("=" * width)


def print_investigation_report(report: InvestigationReport):
    """Render a comprehensive, human-readable final forensic investigation report."""
    print_banner("FINAL DIGITAL FORENSICS INVESTIGATION REPORT (AGENT 4 SYNTHESIS)")
    print(f"Case ID            : {report.case_id}")
    print(f"Case Title         : {report.case_name}")
    print(f"Dataset Nature     : {'SYNTHETIC TEST BENCHMARK' if report.is_synthetic else 'LIVE INCIDENT EVIDENCE'}")
    print(f"Evidence Analyzed  : {report.total_evidence_count} structured artifact records")
    print(f"Global Confidence  : [{report.overall_confidence.value}]")
    print(f"Confidence Rationale: {report.confidence_justification}")

    print_banner("1. EXECUTIVE SUMMARY")
    print(f"  {report.executive_summary}")

    print_banner("2. RECONSTRUCTED FORENSIC TIMELINE")
    for entry in report.reconstructed_timeline:
        user_str = f"User: {entry.user}" if entry.user else "User: <None>"
        dev_str = f"Device: {entry.device}" if entry.device else "Device: <None>"
        print(f"  [{entry.order_index:02d}] {entry.timestamp_iso} | {entry.evidence_id} | {user_str} | {dev_str}")
        print(f"       Status : [{entry.status.value}]")
        print(f"       Action : {entry.action}")
        print(f"       Summary: {entry.summary}")
        print()

    print_banner("3. KEY SYNTHESIZED FINDINGS BY EPISTEMIC STATUS")
    for finding in report.key_findings:
        sup_str = f"Supporting: {', '.join(finding.supporting_evidence_ids)}" if finding.supporting_evidence_ids else ""
        conf_str = f"Conflicting: {', '.join(finding.conflicting_evidence_ids)}" if finding.conflicting_evidence_ids else ""
        ev_refs = " | ".join(filter(None, [sup_str, conf_str]))
        print(f"  * [{finding.finding_id}] {finding.title}")
        print(f"    Epistemic Status : [{finding.status.value}]")
        print(f"    Confidence Level : [{finding.confidence.value}]")
        if ev_refs:
            print(f"    Evidence Ref(s)  : {ev_refs}")
        print(f"    Synthesized Fact : {finding.narrative}")
        print(f"    Forensic Grounding: {finding.forensic_basis}")
        print()

    print_banner("4. CONTRADICTIONS, STATE CONFLICTS & DISCREPANCIES")
    if report.contradictions_and_conflicts:
        for finding in report.contradictions_and_conflicts:
            print(f"  [!] {finding.finding_id}: {finding.title}")
            print(f"      Conflicting Evidence: {', '.join(finding.conflicting_evidence_ids)}")
            print(f"      Conflict Analysis   : {finding.narrative}")
            print(f"      Forensic Grounding  : {finding.forensic_basis}")
            print()
    else:
        print("  No unresolved contradictions identified.")

    print_banner("5. RECOMMENDED FURTHER INVESTIGATION (ACTIONABLE GAPS)")
    for rec in report.recommended_further_investigation:
        print(f"  * {rec}")
        print()

    print_banner("6. FINAL INVESTIGATIVE CONCLUSION")
    print(f"  {report.final_conclusion}")

    print("\n" + "=" * 82 + "\n")


def main():
    """Execute complete 4-agent sequential forensic pipeline."""
    print("[*] Starting Adaptive Multi-Agent Digital Forensics Pipeline...")

    # 1. Ingest Canonical Evidence
    try:
        print(f"[*] Ingesting structured evidence from: {SAMPLE_EVIDENCE_FILE}")
        evidence_collection = load_evidence_from_file(SAMPLE_EVIDENCE_FILE)
        print(f"[+] Loaded and validated {len(evidence_collection.records)} forensic evidence records.")
    except EvidenceLoaderError as exc:
        print(f"[!] Error loading evidence dataset: {exc}", file=sys.stderr)
        sys.exit(1)

    # 2. Execute Agent 1 (Evidence Triage)
    print("\n[-->] [Agent 1/4] Executing Evidence Triage Agent...")
    triage_agent = EvidenceTriageAgent()
    triage_result = triage_agent.triage_case(evidence_collection)
    print(f"[+] Agent 1 Complete: {triage_result.total_evidence_count} records triaged across {len(triage_result.category_counts)} categories.")

    # 3. Execute Agent 2 (Correlation & Timeline)
    print("\n[-->] [Agent 2/4] Executing Evidence Correlation & Timeline Agent...")
    correlation_agent = EvidenceCorrelationAgent()
    correlation_result = correlation_agent.correlate(evidence_collection)
    print(f"[+] Agent 2 Complete: Reconstructed {correlation_result.timeline_event_count} sequenced events, {len(correlation_result.relationships)} links, {len(correlation_result.event_chains)} chains.")

    # 4. Execute Agent 3 (Contradiction & Verification)
    print("\n[-->] [Agent 3/4] Executing Contradiction & Verification Agent...")
    contradiction_agent = ContradictionVerificationAgent()
    contradiction_result = contradiction_agent.analyze_case(
        evidence_input=evidence_collection,
        correlation_result=correlation_result,
    )
    print(f"[+] Agent 3 Complete: {contradiction_result.total_findings} findings evaluated ({contradiction_result.confirmed_contradictions_count} confirmed contradiction, {contradiction_result.potential_contradictions_count} potential anomaly).")

    # 5. Execute Agent 4 (Forensic Synthesis)
    print("\n[-->] [Agent 4/4] Executing Forensic Synthesis Agent...")
    synthesis_agent = ForensicSynthesisAgent()
    investigation_report = synthesis_agent.synthesize(
        triage_result=triage_result,
        correlation_result=correlation_result,
        contradiction_result=contradiction_result,
        raw_evidence=evidence_collection,
    )
    print(f"[+] Agent 4 Complete: Synthesized final report with {len(investigation_report.key_findings)} grounded findings.")

    # 6. Render Terminal Report
    print_investigation_report(investigation_report)

    # 7. Export JSON Artifact
    try:
        OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)
        with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
            f.write(investigation_report.model_dump_json(indent=2))
        print(f"[+] Final structured report exported to: {OUTPUT_FILE}")
    except Exception as exc:
        print(f"[!] Warning: Could not write output file: {exc}", file=sys.stderr)


if __name__ == "__main__":
    main()

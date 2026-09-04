"""Executable Demo Script for Contradiction & Verification Agent (Agent 3).

Loads sample evidence, runs Agent 2 (Correlation) for hypothesis input,
executes Agent 3 (Contradiction & Verification), prints a detailed forensic
audit report, and exports the JSON result to outputs/contradiction_result.json.
"""

import json
from pathlib import Path
import sys

from agents.contradiction_agent import ContradictionResult, ContradictionVerificationAgent
from agents.correlation_agent import EvidenceCorrelationAgent
from forensic_pipeline.evidence_loader import (
    EvidenceLoaderError,
    load_evidence_from_file,
)

BASE_DIR = Path(__file__).resolve().parent
SAMPLE_EVIDENCE_FILE = BASE_DIR / "forensic_pipeline" / "sample_evidence.json"
OUTPUT_FILE = BASE_DIR / "outputs" / "contradiction_result.json"


def print_banner(text: str, width: int = 80):
    """Print formatted section header banner."""
    print("\n" + "=" * width)
    print(f" {text}")
    print("=" * width)


def print_contradiction_report(result: ContradictionResult):
    """Render a clean, human-readable contradiction and verification report."""
    print_banner("FORENSIC CONTRADICTION & VERIFICATION REPORT (AGENT 3)")
    print(f"Case ID                 : {result.case_id}")
    print(f"Case Name               : {result.case_name}")
    print(f"Total Findings          : {result.total_findings}")
    print(f"Confirmed Contradictions: {result.confirmed_contradictions_count} [CRITICAL/MUTUALLY EXCLUSIVE]")
    print(f"Potential Contradictions: {result.potential_contradictions_count} [ATTRIBUTION/ANOMALY GAPS]")
    print(f"Consistent Corroborations: {result.consistent_findings_count} [VERIFIED CONCORDANT]")
    print(f"Insufficient Info       : {result.insufficient_info_count} [UNCORROBORATED HYPOTHESES]")
    print(f"Chain Audits Conducted  : {len(result.chain_verifications)}")

    print_banner("1. DETAILED CONSISTENCY & CONTRADICTION FINDINGS")
    for finding in result.findings:
        badge = f"[{finding.classification.value}] [{finding.severity.value}]"
        print(f"  * {finding.finding_id}: {finding.title}")
        print(f"    Status       : {badge}")
        print(f"    Evidence IDs : {', '.join(finding.evidence_ids)} ({', '.join(finding.artifact_types)})")
        print(f"    Description  : {finding.description}")
        print(f"    Forensic Logic: {finding.reasoning}")
        print(f"    Confidence   : {finding.confidence:.2f}")
        print(f"    Recommended Follow-Up:")
        for line in finding.recommended_followup.strip().split("\n"):
            print(f"      -> {line}")
        print()

    print_banner("2. AUDIT & VERIFICATION OF PROPOSED EVENT CHAINS (AGENT 2)")
    for chain_verif in result.chain_verifications:
        status_badge = f"[{chain_verif.status.value}]"
        print(f"  >>> {chain_verif.chain_id} - {chain_verif.chain_name}")
        print(f"      Verification Status : {status_badge}")
        print(f"      Sequence Items      : {' -> '.join(chain_verif.participating_evidence_ids)}")
        if chain_verif.supporting_evidence_ids:
            print(f"      Supporting Evidence : {', '.join(chain_verif.supporting_evidence_ids)}")
        if chain_verif.conflicting_evidence_ids:
            print(f"      Conflicting Evidence: {', '.join(chain_verif.conflicting_evidence_ids)} [!] ANOMALY")
        print(f"      Audit Justification : {chain_verif.justification}")
        print(f"      Confidence          : {chain_verif.confidence:.2f}")
        print()

    print_banner("3. AUDIT OF PAIRWISE RELATIONSHIPS (AGENT 2)")
    for rel_verif in result.relationship_verifications:
        print(f"  * {rel_verif.relationship_id} ({rel_verif.source_evidence_id} <-> {rel_verif.target_evidence_id}): "
              f"[{rel_verif.status.value}] - {rel_verif.relationship_type}")
        print(f"    Basis: {rel_verif.evidence_basis}")
        print()

    print_banner("4. UNRESOLVED FORENSIC ISSUES & ACTIONABLE QUESTIONS")
    for issue in result.unresolved_issues:
        print(f"  ? {issue}")
        print()

    print_banner("5. OVERALL DATASET RELIABILITY ASSESSMENT")
    print(f"  {result.overall_reliability_assessment}")

    print_banner("6. EXECUTIVE SUMMARY")
    for bullet in result.executive_summary:
        print(f"  - {bullet}")

    print("\n" + "=" * 80 + "\n")


def main():
    """Main execution flow for contradiction verification runner."""
    print("[*] Initializing Forensic Contradiction & Verification Pipeline...")

    # 1. Load and Validate Evidence
    try:
        print(f"[*] Loading evidence file: {SAMPLE_EVIDENCE_FILE}")
        evidence_collection = load_evidence_from_file(SAMPLE_EVIDENCE_FILE)
        print(f"[+] Evidence validated successfully ({len(evidence_collection.records)} records loaded).")
    except EvidenceLoaderError as exc:
        print(f"[!] Error loading evidence dataset: {exc}", file=sys.stderr)
        sys.exit(1)

    # 2. Run Agent 2 (Evidence Correlation) to provide hypothesis context
    print("[*] Running Agent 2 (Correlation) for hypothesis scaffolding...")
    correlation_agent = EvidenceCorrelationAgent()
    correlation_result = correlation_agent.correlate(evidence_collection)
    print(f"[+] Scaffolding complete ({len(correlation_result.event_chains)} event chains, {len(correlation_result.relationships)} links).")

    # 3. Run Agent 3 (Contradiction & Verification)
    print("[*] Executing Agent 3 (ContradictionVerificationAgent)...")
    contradiction_agent = ContradictionVerificationAgent()
    contradiction_result = contradiction_agent.analyze_case(
        evidence_input=evidence_collection,
        correlation_result=correlation_result,
    )
    print("[+] Contradiction & verification analysis completed successfully.")

    # 4. Print Report
    print_contradiction_report(contradiction_result)

    # 5. Save Output JSON
    try:
        OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)
        with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
            f.write(contradiction_result.model_dump_json(indent=2))
        print(f"[+] Structured contradiction result exported to: {OUTPUT_FILE}")
    except Exception as exc:
        print(f"[!] Warning: Could not write output file: {exc}", file=sys.stderr)


if __name__ == "__main__":
    main()

"""Executable Demo Script for Evidence Correlation & Timeline Agent (Agent 2).

Loads sample evidence, performs temporal sequencing and entity correlation,
prints a structured forensic timeline and event chain report, and exports
the JSON result to outputs/correlation_result.json.
"""

import json
from pathlib import Path
import sys

from agents.correlation_agent import CorrelationResult, EvidenceCorrelationAgent
from forensic_pipeline.evidence_loader import (
    EvidenceLoaderError,
    load_evidence_from_file,
)

BASE_DIR = Path(__file__).resolve().parent
SAMPLE_EVIDENCE_FILE = BASE_DIR / "forensic_pipeline" / "sample_evidence.json"
OUTPUT_FILE = BASE_DIR / "outputs" / "correlation_result.json"


def print_banner(text: str, width: int = 80):
    """Print formatted section header banner."""
    print("\n" + "=" * width)
    print(f" {text}")
    print("=" * width)


def print_correlation_report(result: CorrelationResult):
    """Render a clean, human-readable forensic timeline & correlation report."""
    print_banner("FORENSIC EVIDENCE CORRELATION & TIMELINE REPORT (AGENT 2)")
    print(f"Case ID           : {result.case_id}")
    print(f"Case Name         : {result.case_name}")
    print(f"Total Events      : {result.total_events}")
    print(f"Sequenced Events  : {result.timeline_event_count}")
    print(f"Undetermined Events: {result.undetermined_timing_count}")
    print(f"Confirmed Links   : {len(result.relationships)}")
    print(f"Event Chains      : {len(result.event_chains)}")

    print_banner("1. CHRONOLOGICAL FORENSIC TIMELINE")
    for event in result.timeline:
        user_info = f"User: {event.user}" if event.user else "User: <None>"
        dev_info = f"Device: {event.device}" if event.device else "Device: <None>"
        print(f"  [{event.order_index:02d}] {event.timestamp_iso} | {event.evidence_id} | {user_info} | {dev_info}")
        print(f"       Action     : {event.action}")
        print(f"       Artifact   : {event.artifact_type} ({event.source})")
        print(f"       Description: {event.description}")
        if event.resource_path:
            print(f"       Resource   : {event.resource_path}")
        print()

    if result.undetermined_timing_events:
        print_banner("UNDETERMINED TIMING EVENTS")
        for event in result.undetermined_timing_events:
            print(f"  [?] {event.evidence_id} | Action: {event.action} | Source: {event.source}")
            print(f"      Description: {event.description}")
            print()

    print_banner("2. DIRECT EVENT RELATIONSHIPS & GROUNDED LINKS")
    for rel in result.relationships:
        print(f"  * [{rel.relationship_id}] {rel.source_evidence_id} <---> {rel.target_evidence_id}")
        print(f"    Type      : {rel.relationship_type.value}")
        print(f"    Basis     : {rel.basis}")
        print(f"    Confidence: {rel.confidence:.2f}")
        print(f"    Evidence  : {', '.join(rel.supporting_evidence_ids)}")
        print()

    print_banner("3. RECONSTRUCTED MULTI-STEP EVENT CHAINS")
    for chain in result.event_chains:
        start_str = chain.start_time.isoformat() if chain.start_time else "N/A"
        end_str = chain.end_time.isoformat() if chain.end_time else "N/A"
        print(f"  >>> [{chain.chain_id}] {chain.name}")
        print(f"      Type       : {chain.chain_type.value}")
        print(f"      Timespan   : {start_str}  --->  {end_str}")
        print(f"      Sequence   : {' -> '.join(chain.sequence_evidence_ids)}")
        print(f"      Narrative  : {chain.description}")
        print(f"      Rationale  : {chain.rationale}")
        print(f"      Confidence : {chain.confidence:.2f}")
        print()

    print_banner("4. UNRESOLVED / INSUFFICIENTLY SUPPORTED RELATIONSHIPS")
    if result.unresolved_relationships:
        for unres in result.unresolved_relationships:
            print(f"  ? Potential Link  : {unres.potential_link}")
            print(f"    Involved Items  : {', '.join(unres.evidence_ids)}")
            print(f"    Why Inconclusive: {unres.reason_insufficient}")
            print()
    else:
        print("  No unresolved relationship candidates flagged.")

    print_banner("5. TIMELINE & CORRELATION EXECUTIVE SUMMARY")
    for line in result.overall_timeline_summary:
        print(f"  - {line}")

    print("\n" + "=" * 80 + "\n")


def main():
    """Main execution flow for correlation runner script."""
    print("[*] Initializing Forensic Evidence Correlation Pipeline...")

    # 1. Load and Validate Evidence
    try:
        print(f"[*] Loading evidence file: {SAMPLE_EVIDENCE_FILE}")
        evidence_collection = load_evidence_from_file(SAMPLE_EVIDENCE_FILE)
        print(f"[+] Evidence validated successfully ({len(evidence_collection.records)} records loaded).")
    except EvidenceLoaderError as exc:
        print(f"[!] Error loading evidence dataset: {exc}", file=sys.stderr)
        sys.exit(1)

    # 2. Run Evidence Correlation Agent
    print("[*] Executing Agent 2 (EvidenceCorrelationAgent)...")
    agent = EvidenceCorrelationAgent()
    correlation_result = agent.correlate(evidence_collection)
    print("[+] Correlation analysis completed successfully.")

    # 3. Print Report
    print_correlation_report(correlation_result)

    # 4. Save Output JSON
    try:
        OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)
        with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
            f.write(correlation_result.model_dump_json(indent=2))
        print(f"[+] Structured correlation result exported to: {OUTPUT_FILE}")
    except Exception as exc:
        print(f"[!] Warning: Could not write output file: {exc}", file=sys.stderr)


if __name__ == "__main__":
    main()

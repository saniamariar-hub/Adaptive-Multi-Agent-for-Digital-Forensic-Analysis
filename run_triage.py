"""Executable Demo Script for Evidence Triage Agent (Agent 1).

Loads sample evidence, performs structured triage analysis, prints a formatted
forensic report to the terminal, and exports the JSON result to outputs/.
"""

import json
from pathlib import Path
import sys

from agents.triage_agent import EvidenceTriageAgent, TriageResult
from forensic_pipeline.evidence_loader import (
    EvidenceLoaderError,
    load_evidence_from_file,
)

BASE_DIR = Path(__file__).resolve().parent
SAMPLE_EVIDENCE_FILE = BASE_DIR / "forensic_pipeline" / "sample_evidence.json"
OUTPUT_FILE = BASE_DIR / "outputs" / "triage_result.json"


def print_banner(text: str, width: int = 78):
    """Print formatted section header banner."""
    print("\n" + "=" * width)
    print(f" {text}")
    print("=" * width)


def print_triage_report(result: TriageResult):
    """Render a clean, human-readable forensic triage report."""
    print_banner(f"FORENSIC EVIDENCE TRIAGE REPORT (AGENT 1)")
    print(f"Case ID      : {result.case_id}")
    print(f"Case Name    : {result.case_name}")
    if result.case_description:
        print(f"Overview     : {result.case_description}")
    print(f"Synthetic    : {'YES (Test Dataset)' if result.is_synthetic else 'NO (Live Case)'}")
    print(f"Total Records: {result.total_evidence_count}")
    if result.earliest_timestamp and result.latest_timestamp:
        print(f"Time Range   : {result.earliest_timestamp.isoformat()} -> {result.latest_timestamp.isoformat()}")
    print(f"Identified Users   : {', '.join(result.users_involved) if result.users_involved else 'None'}")
    print(f"Identified Devices : {', '.join(result.devices_involved) if result.devices_involved else 'None'}")

    print_banner("1. EVIDENCE CATEGORY BREAKDOWN")
    for category, count in result.category_counts.items():
        pct = (count / result.total_evidence_count) * 100
        print(f"  * {category:<32} : {count:>2} item(s) ({pct:>5.1f}%)")

    print_banner("2. DETAILED EVIDENCE BY CATEGORY")
    for category, items in result.categorized_evidence.items():
        print(f"\n--- [ {category.upper()} ] ({len(items)} records) ---")
        for item in items:
            notable_flag = " [!] NOTABLE" if item.is_notable else ""
            user_str = f"User: {item.user}" if item.user else "User: <None>"
            dev_str = f"Device: {item.device}" if item.device else "Device: <None>"
            print(f"  * [{item.evidence_id}] {item.timestamp.isoformat()} | {user_str} | {dev_str}{notable_flag}")
            print(f"    Action       : {item.action}")
            print(f"    Source       : {item.source}")
            print(f"    Description  : {item.description}")
            if item.resource_path:
                print(f"    Resource     : {item.resource_path}")
            print(f"    Significance : {item.significance}")
            print(f"    Confidence   : {item.confidence:.2f} | Reliability: {item.source_reliability}")
            print()

    print_banner("3. HIGH-PRIORITY / NOTABLE EVIDENCE")
    if result.notable_evidence:
        for item in result.notable_evidence:
            print(f"  [!] {item.evidence_id} ({item.timestamp.isoformat()} | {item.category.value}):")
            print(f"      Action      : {item.action}")
            print(f"      Significance: {item.significance}")
            print()
    else:
        print("  No elevated-priority items flagged.")

    print_banner("4. MISSING OR UNKNOWN CONTEXT")
    if result.missing_or_unknown_info:
        for rec in result.missing_or_unknown_info:
            print(f"  ? {rec.evidence_id}: Missing [{', '.join(rec.missing_fields)}]")
            print(f"    Investigative Note: {rec.note}")
            print()
    else:
        print("  All evidence records contain complete primary attribute context.")

    print_banner("5. OVERALL TRIAGE OBSERVATIONS")
    for obs in result.overall_observations:
        print(f"  - {obs}")

    print("\n" + "=" * 78 + "\n")


def main():
    """Main execution flow for triage test script."""
    print("[*] Initializing Forensic Evidence Triage Pipeline...")

    # 1. Load and Validate Evidence
    try:
        print(f"[*] Loading evidence file: {SAMPLE_EVIDENCE_FILE}")
        evidence_collection = load_evidence_from_file(SAMPLE_EVIDENCE_FILE)
        print(f"[+] Evidence validated successfully ({len(evidence_collection.records)} records loaded).")
    except EvidenceLoaderError as exc:
        print(f"[!] Error loading evidence dataset: {exc}", file=sys.stderr)
        sys.exit(1)

    # 2. Run Evidence Triage Agent
    print("[*] Executing Agent 1 (EvidenceTriageAgent)...")
    agent = EvidenceTriageAgent()
    triage_result = agent.triage_case(evidence_collection)
    print("[+] Triage completed successfully.")

    # 3. Print Report
    print_triage_report(triage_result)

    # 4. Save Output JSON
    try:
        OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)
        with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
            # Pydantic v2 dump to json string
            f.write(triage_result.model_dump_json(indent=2))
        print(f"[+] Structured triage result exported to: {OUTPUT_FILE}")
    except Exception as exc:
        print(f"[!] Warning: Could not write output file: {exc}", file=sys.stderr)


if __name__ == "__main__":
    main()

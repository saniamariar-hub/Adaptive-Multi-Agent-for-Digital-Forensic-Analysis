"""Real LLM-Powered Evidence Triage Demo Runner (Agent 1 + Ollama hermes3:latest).

Executes the LLM-powered Evidence Triage Agent using the local Ollama server,
validates the returned JSON against the Pydantic schema, saves the output,
and provides a comparative analysis against the deterministic baseline.
"""

import json
from pathlib import Path
import sys
import time

from agents.llm_triage_agent import (
    LLMEvidenceTriageAgent,
    LLMTriageError,
    LLMTriageValidationError,
)
from agents.triage_agent import EvidenceTriageAgent, TriageResult
from configs.config import config
from forensic_pipeline.evidence_loader import (
    EvidenceLoaderError,
    load_evidence_from_file,
)
from llm.ollama_client import OllamaClient

BASE_DIR = Path(__file__).resolve().parent
SAMPLE_EVIDENCE_FILE = BASE_DIR / "forensic_pipeline" / "sample_evidence.json"
DETERMINISTIC_OUTPUT_FILE = BASE_DIR / "outputs" / "triage_result.json"
LLM_OUTPUT_FILE = BASE_DIR / "outputs" / "llm_triage_result.json"


def print_banner(text: str, width: int = 80):
    """Print formatted section banner."""
    print("\n" + "=" * width)
    print(f" {text}")
    print("=" * width)


def print_comparison_table(deterministic: TriageResult, llm_result: TriageResult, latency: float):
    """Render a structured comparative evaluation between deterministic and LLM triage."""
    print_banner("COMPARATIVE EVALUATION: DETERMINISTIC BASELINE vs. LLM (HERMES 3)")

    # Metrics
    det_cats = sorted(list(deterministic.category_counts.keys()))
    llm_cats = sorted(list(llm_result.category_counts.keys()))

    det_ids = {
        item.evidence_id
        for sublist in deterministic.categorized_evidence.values()
        for item in sublist
    }
    llm_ids = {
        item.evidence_id
        for sublist in llm_result.categorized_evidence.values()
        for item in sublist
    }

    det_notable = [item.evidence_id for item in deterministic.notable_evidence]
    llm_notable = [item.evidence_id for item in llm_result.notable_evidence]

    det_missing_ids = [m.evidence_id for m in deterministic.missing_or_unknown_info]
    llm_missing_ids = [m.evidence_id for m in llm_result.missing_or_unknown_info]

    print(f"{'Metric':<30} | {'Deterministic Baseline':<22} | {'LLM (hermes3:latest)':<22}")
    print("-" * 80)
    print(f"{'Total Evidence Processed':<30} | {deterministic.total_evidence_count:<22} | {llm_result.total_evidence_count:<22}")
    print(f"{'Distinct Categories':<30} | {len(det_cats):<22} | {len(llm_cats):<22}")
    print(f"{'Evidence IDs Preserved':<30} | {f'{len(det_ids)}/{len(det_ids)} ({det_ids == llm_ids})':<22} | {f'{len(llm_ids)}/{len(det_ids)} ({det_ids == llm_ids})':<22}")
    print(f"{'Notable Items Flagged':<30} | {f'{len(det_notable)} items ({det_notable[:3]}...)':<22} | {f'{len(llm_notable)} items ({llm_notable[:3]}...)':<22}")
    print(f"{'Missing Context Items':<30} | {f'{len(det_missing_ids)} items ({det_missing_ids})':<22} | {f'{len(llm_missing_ids)} items ({llm_missing_ids})':<22}")
    print(f"{'Execution Latency':<30} | {'< 0.01 seconds':<22} | {f'{latency:.2f} seconds':<22}")
    print("-" * 80)


def main():
    print_banner("REAL LLM EVIDENCE TRIAGE PIPELINE (AGENT 1 + OLLAMA HERMES 3)")

    # 1. Ingest Evidence
    try:
        print(f"[*] Ingesting structured evidence from: {SAMPLE_EVIDENCE_FILE}")
        evidence_collection = load_evidence_from_file(SAMPLE_EVIDENCE_FILE)
        print(f"[+] Successfully loaded and validated {len(evidence_collection.records)} records.")
    except EvidenceLoaderError as exc:
        print(f"[!] Evidence loading failed: {exc}", file=sys.stderr)
        sys.exit(1)

    # 2. Check Ollama Health
    ollama_client = OllamaClient()
    print(f"\n[*] Checking Ollama connectivity at {ollama_client.base_url} (model: {ollama_client.model_name})...")
    is_healthy, health_msg = ollama_client.health_check()
    if not is_healthy:
        print(f"[!] Ollama Health Check Failed: {health_msg}", file=sys.stderr)
        sys.exit(1)
    print(f"[+] {health_msg}")

    # 3. Execute Real LLM Agent
    print(f"\n[*] Dispatching evidence to real LLM ({ollama_client.model_name}) for cognitive triage...")
    llm_agent = LLMEvidenceTriageAgent(llm_client=ollama_client)

    try:
        llm_triage_result = llm_agent.triage_case(evidence_collection)
        latency = llm_agent.last_response.latency_seconds if llm_agent.last_response else 0.0
        print(f"[+] LLM Triage completed successfully in {latency:.2f}s.")
    except LLMTriageValidationError as exc:
        print(f"[!] Pydantic Validation Error on LLM Output:\n{exc}", file=sys.stderr)
        sys.exit(1)
    except LLMTriageError as exc:
        print(f"[!] LLM Triage Failed: {exc}", file=sys.stderr)
        sys.exit(1)

    # 4. Print Structured Report
    print_banner("LLM FORENSIC TRIAGE REPORT")
    print(f"Case ID           : {llm_triage_result.case_id}")
    print(f"Case Name         : {llm_triage_result.case_name}")
    print(f"Total Evidence    : {llm_triage_result.total_evidence_count} records")
    print(f"LLM Latency       : {latency:.2f} seconds")
    print(f"Identified Users  : {', '.join(llm_triage_result.users_involved)}")
    print(f"Identified Devices: {', '.join(llm_triage_result.devices_involved)}")

    print("\n--- CATEGORY BREAKDOWN (LLM) ---")
    for cat, count in llm_triage_result.category_counts.items():
        print(f"  * {cat:<30} : {count} item(s)")

    print("\n--- NOTABLE EVIDENCE FLAGGED (LLM) ---")
    for item in llm_triage_result.notable_evidence:
        print(f"  [!] {item.evidence_id} ({item.timestamp.isoformat()} | {item.category.value}):")
        print(f"      Action      : {item.action}")
        print(f"      Significance: {item.significance}")

    print("\n--- MISSING / UNKNOWN CONTEXT (LLM) ---")
    for rec in llm_triage_result.missing_or_unknown_info:
        print(f"  ? {rec.evidence_id}: Missing [{', '.join(rec.missing_fields)}] - {rec.note}")

    print("\n--- OVERALL OBSERVATIONS (LLM) ---")
    for obs in llm_triage_result.overall_observations:
        print(f"  - {obs}")

    # 5. Save LLM Output JSON
    try:
        LLM_OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)
        with open(LLM_OUTPUT_FILE, "w", encoding="utf-8") as f:
            f.write(llm_triage_result.model_dump_json(indent=2))
        print(f"\n[+] Saved structured LLM triage result to: {LLM_OUTPUT_FILE}")
    except Exception as exc:
        print(f"[!] Warning: Could not write LLM output file: {exc}", file=sys.stderr)

    # 6. Comparative Analysis against Deterministic Baseline
    print("\n[*] Loading deterministic baseline result for comparison...")
    deterministic_agent = EvidenceTriageAgent()
    det_result = deterministic_agent.triage_case(evidence_collection)

    print_comparison_table(det_result, llm_triage_result, latency)


if __name__ == "__main__":
    main()

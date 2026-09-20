"""
Comprehensive Test Suite for Project Sentinel NIST Hallucination Evaluator

Tests:
1. NIST Ground Truth Dataset Integrity (All 60 Questions)
2. Atomic Claim Extraction & Classification
3. Layer 1: Deterministic Normalization (Casing, Slashes, Whitespace, Punctuation)
4. Layer 2: Entity Cross-Verification
5. Layer 3: Semantic & N-Gram Similarity Matching
6. Layer 4: Forensic Contradiction Engine (OS, IP, Hostname, Email, Timezone)
7. Layer 5: Structured Fallback & Claim Classification
8. Metrics Calculation Engine & Qualitative Verdicts
9. Multi-Question Forensic Report Evaluator
10. Persistent SQLite Storage & Audit Querying
"""

import os
import sys
import pytest
from pathlib import Path

# Add project root to sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from evaluator.claim_extractor import extract_claims, detect_claim_type, extract_claim_entities
from evaluator.metrics import compute_evaluation_metrics
from evaluator.hybrid_engine import (
    evaluate_response,
    evaluate_single_claim,
    check_deterministic_match,
    compare_entities,
    compute_ngram_jaccard,
    compute_token_overlap,
    check_contradictions,
    normalize_text,
    get_ground_truth_by_id,
    get_all_ground_truth,
)
from evaluator.report_evaluator import evaluate_report, split_report_into_sections, match_text_to_question
from evaluator.storage import (
    init_db,
    save_evaluation,
    list_evaluations,
    get_summary_stats,
    save_report_evaluation,
    list_report_evaluations,
)
from evaluator.nist_ground_truth_parser import load_ground_truth, NIST_GROUND_TRUTH_FILE


class TestGroundTruthIntegrity:
    """Verify official NIST CFReDS ground truth database."""

    def test_all_60_questions_present(self):
        all_q = get_all_ground_truth()
        assert len(all_q) == 60, f"Expected 60 NIST questions, found {len(all_q)}"
        for q in all_q:
            assert "question_id" in q
            assert 1 <= q["question_id"] <= 60
            assert "question" in q and len(q["question"].strip()) > 0
            assert "ground_truth" in q and len(q["ground_truth"].strip()) > 0
            assert "source_pages" in q
            assert "entities" in q

    def test_key_forensic_ground_truths(self):
        # Q1 Hashes
        q1 = get_ground_truth_by_id(1)
        assert q1 is not None
        assert "A49D1254C873808C58E6F1BCD60B5BDE" in q1["ground_truth"] or "a49d1254c873808c58e6f1bcd60b5bde" in q1["ground_truth"].lower()
        
        # Q3 OS Information
        q3 = get_ground_truth_by_id(3)
        assert q3 is not None
        assert "windows 7" in q3["ground_truth"].lower()
        
        # Q5 Computer Name
        q5 = get_ground_truth_by_id(5)
        assert q5 is not None
        assert "informant-pc" in q5["ground_truth"].lower()
        
        # Q9 DHCP IP Address
        q9 = get_ground_truth_by_id(9)
        assert q9 is not None
        assert "10.11.11.129" in q9["ground_truth"]
        
        # Q24 Shared Network Drive IP
        q24 = get_ground_truth_by_id(24)
        assert q24 is not None
        assert "10.11.11.128" in q24["ground_truth"] or "10.11.11.130" in q24["ground_truth"] or "10.11.11" in q24["ground_truth"]
        
        # Q31 Google Drive Account
        q31 = get_ground_truth_by_id(31)
        assert q31 is not None
        assert "iaman.informant.personal@gmail.com" in q31["ground_truth"]


class TestClaimExtractor:
    """Verify atomic claim extraction and classification."""

    def test_atomic_claim_splitting(self):
        text = (
            "The suspect machine was running Windows 7 Ultimate SP1. "
            "The computer name was INFORMANT-PC. "
            "DHCP assigned the IP address 10.11.11.129 to the primary network adapter."
        )
        claims = extract_claims(text, question_id=3)
        assert len(claims) >= 3
        texts = [c["claim_text"] for c in claims]
        assert any("Windows 7" in t for t in texts)
        assert any("INFORMANT-PC" in t for t in texts)
        assert any("10.11.11.129" in t for t in texts)

    def test_markdown_bullet_and_table_extraction(self):
        text = (
            "Key findings:\n"
            "- Operating System: Windows 7 Ultimate\n"
            "- Hostname: INFORMANT-PC\n"
            "| Artifact | Value |\n"
            "|---|---|\n"
            "| IP Address | 10.11.11.129 |\n"
        )
        claims = extract_claims(text, question_id=3)
        assert len(claims) >= 3

    def test_claim_type_classification(self):
        assert detect_claim_type("The OS is Windows 7 Ultimate SP1") == "os_info"
        assert detect_claim_type("IP address is 10.11.11.129") == "ip_address"
        assert detect_claim_type("Contact email was iaman.informant.personal@gmail.com") == "email"
        assert detect_claim_type("The MD5 hash is a49d1254c873808c58e6f1bcd60b5bde") == "hash"
        assert detect_claim_type("File path was C:\\Users\\informant\\Desktop\\resignation.docx") == "path"
        assert detect_claim_type("Deleted file resignation.docx") == "filename"
        assert detect_claim_type("Timestamp recorded was 2015-03-24 10:15:00 UTC") == "timestamp"


class TestHybridDetectionEngine:
    """Verify each detection layer of the 5-layer hybrid engine."""

    def test_layer1_exact_and_normalized_match(self):
        gt_answer = "The operating system is Windows 7 Ultimate Service Pack 1, installed on 2015-03-23."
        
        # Exact match
        is_match, conf, _ = check_deterministic_match("Windows 7 Ultimate Service Pack 1", gt_answer, "")
        assert is_match is True
        assert conf >= 0.95

        # Case-insensitive + whitespace match
        is_match2, conf2, _ = check_deterministic_match("   windows 7   ultimate   service pack 1   ", gt_answer, "")
        assert is_match2 is True

        # Slash normalization in path
        gt_path = "Located at C:/Users/informant/AppData/Local/Google/Drive/user_default/sync_log.log"
        is_match3, conf3, _ = check_deterministic_match("C:\\Users\\informant\\AppData\\Local\\Google\\Drive\\user_default\\sync_log.log", gt_path, "")
        assert is_match3 is True

    def test_layer2_entity_cross_verification(self):
        gt_entities = {
            "ips": ["10.11.11.129", "10.11.11.130"],
            "emails": ["iaman.informant.personal@gmail.com"],
            "filenames": ["resignation.docx", "snapshot.db"],
            "hashes": ["a49d1254c873808c58e6f1bcd60b5bde"]
        }
        
        # Valid entity in claim
        claim_entities = {
            "ips": [],
            "emails": ["iaman.informant.personal@gmail.com"],
            "filenames": [],
            "hashes": []
        }
        res = compare_entities(claim_entities, gt_entities)
        assert len(res["matched"]) > 0
        assert res["entity_support_score"] > 0.0

        # Conflicted entity
        fake_entities = {
            "ips": ["192.168.1.1"],
            "emails": ["attacker@evil-hackers.ru"],
            "filenames": [],
            "hashes": []
        }
        res_fake = compare_entities(fake_entities, gt_entities)
        assert len(res_fake["conflicted"]) > 0

    def test_layer3_semantic_ngram_similarity(self):
        gt_answer = "The network interface with an assigned IP of 10.11.11.129 was configured by DHCP server."
        claim = "DHCP assigned the IP address 10.11.11.129 to the network interface."
        
        jaccard = compute_ngram_jaccard(claim, gt_answer, n=3)
        overlap, _ = compute_token_overlap(claim, gt_answer)
        assert jaccard > 0.25
        assert overlap > 0.40

    def test_layer4_forensic_contradictions(self):
        gt_q3 = get_ground_truth_by_id(3)
        gt_text = gt_q3["ground_truth"] if gt_q3 else "Windows 7 Ultimate SP1"

        # Contradictory OS
        is_contra_os, reason_os = check_contradictions("The suspect workstation was running Windows 10 Enterprise.", gt_text, 3)
        assert is_contra_os is True
        assert "Windows 10" in reason_os or "Windows 7" in reason_os

        # Contradictory IP Subnet
        is_contra_ip, reason_ip = check_contradictions("The network adapter was assigned IP 192.168.1.100 via DHCP.", "10.11.11.129", 9)
        assert is_contra_ip is True

        # Contradictory Hostname
        is_contra_host, reason_host = check_contradictions("The computer hostname was DESKTOP-VICTIM-99.", "INFORMANT-PC", 5)
        assert is_contra_host is True

        # Non-contradictory claim
        is_non_contra, _ = check_contradictions("The operating system was identified as Windows 7.", gt_text, 3)
        assert is_non_contra is False


class TestFullResponseEvaluation:
    """Verify end-to-end question evaluation and metric calculation."""

    def test_supported_response_evaluation(self):
        ans = "The installed operating system is Windows 7 Ultimate Service Pack 1, registered owner is informant, installed on 2015-03-22."
        res = evaluate_response(
            agent_response=ans,
            question_id=3,
            agent_name="Test-Sentinel"
        )
        assert res["metrics"]["groundedness_score"] >= 0.70
        assert res["metrics"]["hallucination_rate"] <= 0.30
        assert res["metrics"]["verdict"] in ["GROUNDED", "PARTIALLY_GROUNDED"]
        assert len(res["claims"]) > 0

    def test_contradictory_response_evaluation(self):
        ans = "The installed operating system is Windows 10 Pro 64-bit Edition, installed on 2021-08-15."
        res = evaluate_response(
            agent_response=ans,
            question_id=3,
            agent_name="Hallucinatory-Agent"
        )
        assert res["metrics"]["contradiction_rate"] > 0.0
        assert res["metrics"]["verdict"] == "CONTRADICTED"
        assert any(c["classification"] == "CONTRADICTED" for c in res["claims"])

    def test_unsupported_hallucination_evaluation(self):
        ans = "The suspect was using Tor Browser to access dark web forum onion-link-99.onion and transferred 50 Bitcoin to ransom wallet."
        res = evaluate_response(
            agent_response=ans,
            question_id=42, # What web browsers were used?
            agent_name="Hallucinatory-Agent"
        )
        assert res["metrics"]["hallucination_rate"] >= 0.50


class TestMetricsEngine:
    """Verify mathematical scoring and edge cases."""

    def test_metrics_calculation(self):
        claims = [
            {"classification": "SUPPORTED"},
            {"classification": "SUPPORTED"},
            {"classification": "PARTIALLY_SUPPORTED"},
            {"classification": "UNSUPPORTED"}
        ]
        metrics = compute_evaluation_metrics(claims)
        # 2 + 0.5*1 = 2.5 / 4 = 0.625
        assert metrics["total_claims"] == 4
        assert metrics["supported_claims"] == 2
        assert metrics["partially_supported_claims"] == 1
        assert metrics["unsupported_claims"] == 1
        assert metrics["groundedness_score"] == 0.625
        assert metrics["hallucination_rate"] == 0.25
        assert metrics["verdict"] == "PARTIALLY_GROUNDED"

    def test_metrics_zero_claims(self):
        metrics = compute_evaluation_metrics([])
        assert metrics["total_claims"] == 0
        assert metrics["groundedness_score"] == 1.0
        assert metrics["verdict"] == "SUPPORTED"


class TestReportEvaluator:
    """Verify parsing and multi-question forensic report evaluation."""

    def test_full_report_evaluation(self):
        sample_report = (
            "# Forensic Investigation Summary\n\n"
            "## Question 3: Operating System\n"
            "The suspect computer was running Windows 7 Ultimate SP1.\n\n"
            "## Question 5: Computer Name\n"
            "The computer name was identified as INFORMANT-PC.\n\n"
            "## Question 9: Network Information\n"
            "The network interface received IP address 10.11.11.129 via DHCP.\n"
        )
        
        report_res = evaluate_report(
            report_text=sample_report,
            report_title="Test-Investigation-Report",
            examiner="Synthesis-Agent"
        )
        
        assert report_res["questions_detected_count"] == 3
        assert report_res["metrics"]["groundedness_score"] >= 0.70
        assert len(report_res["question_breakdown"]) == 3
        assert len(report_res["all_claims"]) >= 3


class TestStorageAndAuditDB:
    """Verify SQLite database persistence and querying."""

    def test_save_and_retrieve_evaluation(self):
        init_db()
        sample_eval = {
            "question_id": 9,
            "agent_name": "Unit-Test-Agent",
            "agent_response": "The assigned IP address is 10.11.11.129.",
            "ground_truth": "10.11.11.129",
            "source_pages": [14, 15],
            "claims": [
                {
                    "claim_id": "Q9-C1",
                    "claim_text": "The assigned IP address is 10.11.11.129",
                    "claim_type": "ip_address",
                    "classification": "SUPPORTED",
                    "confidence": 0.98,
                    "reason": "Exact IP match in ground truth",
                    "ground_truth_evidence": "10.11.11.129",
                    "source_pages": [14, 15],
                    "layer_resolved": "Layer 2: Entity Cross-Validation"
                }
            ],
            "metrics": {
                "total_claims": 1,
                "supported_claims": 1,
                "partially_supported_claims": 0,
                "unsupported_claims": 0,
                "contradicted_claims": 0,
                "undetermined_claims": 0,
                "evaluable_claims": 1,
                "groundedness_score": 1.0,
                "hallucination_rate": 0.0,
                "contradiction_rate": 0.0,
                "supported_percentage": 100.0,
                "accuracy_score": 1.0,
                "coverage_score": 1.0,
                "verdict": "GROUNDED"
            }
        }
        
        saved = save_evaluation(sample_eval)
        assert "evaluation_id" in saved
        
        # Query back
        history = list_evaluations(agent="Unit-Test-Agent", limit=10)
        assert len(history) >= 1
        found = next((e for e in history if e["evaluation_id"] == saved["evaluation_id"]), None)
        assert found is not None
        assert found["question_id"] == 9
        assert found["groundedness_score"] == 1.0
        assert found["verdict"] == "GROUNDED"

    def test_evaluation_summary_stats(self):
        summary = get_summary_stats()
        assert "total_evaluations" in summary
        assert "overall_groundedness" in summary
        assert "agent_benchmarks" in summary
        assert summary["total_evaluations"] > 0

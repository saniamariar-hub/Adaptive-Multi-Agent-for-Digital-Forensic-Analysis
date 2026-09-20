"""
Hallucination Evaluator Package for NIST CFReDS Digital Forensics Case.
"""
from evaluator.hybrid_engine import evaluate_response, evaluate_single_claim, get_all_ground_truth, get_ground_truth_by_id
from evaluator.claim_extractor import extract_claims
from evaluator.metrics import compute_evaluation_metrics

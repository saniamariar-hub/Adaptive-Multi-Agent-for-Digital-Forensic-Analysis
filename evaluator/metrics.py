"""
evaluator/metrics.py
────────────────────
Calculates formal claim-level and question-level evaluation metrics
benchmarked against the NIST CFReDS Ground Truth dataset.
"""

from typing import List, Dict, Any

def compute_evaluation_metrics(claim_results: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Computes groundedness, hallucination, and contradiction metrics across evaluated claims.
    
    Formulas:
    - total_claims: Total count of evaluated atomic claims.
    - evaluable_claims: Total claims excluding UNDETERMINED.
    - groundedness_score = (supported + 0.5 * partially_supported) / max(1, evaluable_claims)
    - hallucination_rate = (unsupported + contradicted) / max(1, evaluable_claims)
    - contradiction_rate = contradicted / max(1, evaluable_claims)
    - supported_percentage = supported / max(1, total_claims) * 100
    - accuracy_score = (supported + 0.5 * partially_supported) / max(1, supported + partially_supported + unsupported + contradicted)
    """
    total = len(claim_results)
    if total == 0:
        return {
            "total_claims": 0,
            "supported_claims": 0,
            "partially_supported_claims": 0,
            "unsupported_claims": 0,
            "contradicted_claims": 0,
            "undetermined_claims": 0,
            "evaluable_claims": 0,
            "groundedness_score": 1.0,
            "hallucination_rate": 0.0,
            "contradiction_rate": 0.0,
            "supported_percentage": 100.0,
            "accuracy_score": 1.0,
            "coverage_score": 1.0,
            "verdict": "SUPPORTED"
        }

    supported = sum(1 for c in claim_results if c.get("classification") == "SUPPORTED")
    partially_supported = sum(1 for c in claim_results if c.get("classification") == "PARTIALLY_SUPPORTED")
    unsupported = sum(1 for c in claim_results if c.get("classification") == "UNSUPPORTED")
    contradicted = sum(1 for c in claim_results if c.get("classification") == "CONTRADICTED")
    undetermined = sum(1 for c in claim_results if c.get("classification") == "UNDETERMINED")

    evaluable = supported + partially_supported + unsupported + contradicted
    effective_denom = evaluable if evaluable > 0 else total

    groundedness = (supported + 0.5 * partially_supported) / effective_denom
    hallucination_rate = (unsupported + contradicted) / effective_denom
    contradiction_rate = contradicted / effective_denom
    accuracy = (supported + 0.5 * partially_supported) / effective_denom
    coverage = supported / total
    supported_pct = (supported / total) * 100.0

    # Determine qualitative verdict
    if contradicted > 0:
        verdict = "CONTRADICTED"
    elif hallucination_rate > 0.4:
        verdict = "HALLUCINATED"
    elif groundedness >= 0.8:
        verdict = "GROUNDED"
    elif groundedness >= 0.5:
        verdict = "PARTIALLY_GROUNDED"
    else:
        verdict = "UNVERIFIED"

    return {
        "total_claims": total,
        "supported_claims": supported,
        "partially_supported_claims": partially_supported,
        "unsupported_claims": unsupported,
        "contradicted_claims": contradicted,
        "undetermined_claims": undetermined,
        "evaluable_claims": evaluable,
        "groundedness_score": round(groundedness, 4),
        "hallucination_rate": round(hallucination_rate, 4),
        "contradiction_rate": round(contradiction_rate, 4),
        "supported_percentage": round(supported_pct, 2),
        "accuracy_score": round(accuracy, 4),
        "coverage_score": round(coverage, 4),
        "verdict": verdict
    }


calculate_evaluation_metrics = compute_evaluation_metrics

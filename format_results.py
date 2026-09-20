"""
format_results.py

Converts run_investigation.py's results.json into a readable Markdown report.
Supports automated hallucination evaluation scoring and claim breakdown against
the NIST CFReDS Ground Truth database.

Usage:
    python format_results.py results.json --out results.md
    python format_results.py results.json --out results.md --evaluate
"""

import argparse
import json
import os
import sys


def main():
    parser = argparse.ArgumentParser(description="Convert investigation results to formatted markdown with NIST evaluation.")
    parser.add_argument("results_json", help="Path to results.json file")
    parser.add_argument("--out", default="results.md", help="Output markdown path")
    parser.add_argument("--evaluate", action="store_true", help="Run automated NIST hallucination evaluation if not already evaluated")
    args = parser.parse_args()

    if not os.path.exists(args.results_json):
        print(f"[ERROR] File not found: {args.results_json}")
        sys.exit(1)

    with open(args.results_json, "r", encoding="utf-8") as f:
        results = json.load(f)

    eval_engine = None
    save_eval = None
    if args.evaluate:
        try:
            from evaluator.hybrid_engine import evaluate_response
            from evaluator.storage import save_evaluation
            eval_engine = evaluate_response
            save_eval = save_evaluation
            print("[INFO] Hallucination evaluator initialized for formatting.")
        except Exception as e:
            print(f"[WARNING] Could not load evaluation engine: {e}")

    lines = [
        "# Forensic Agent Investigation & Hallucination Audit Report",
        "",
        "> Benchmark: **NIST CFReDS Data Leakage Case (60 Questions)**",
        "> Evaluator: **Project Sentinel Hybrid 5-Layer Hallucination Engine**",
        "",
        "---",
        ""
    ]

    total_groundedness = 0.0
    evaluated_count = 0

    for item in results:
        q_num = item.get("question_number", 0)
        q_text = item.get("question", "")
        ans_text = item.get("answer", "")
        
        evaluation = item.get("evaluation")
        if not evaluation and eval_engine:
            try:
                evaluation = eval_engine(
                    question_id=q_num,
                    question_text=q_text,
                    agent_response=ans_text,
                    agent_name="Investigation Agent"
                )
                if save_eval:
                    save_eval(evaluation)
                item["evaluation"] = evaluation
            except Exception as e:
                print(f"[WARNING] Eval error for Q{q_num}: {e}")

        lines.append(f"## Q{q_num}. {q_text}")
        lines.append("")

        if evaluation:
            evaluated_count += 1
            groundedness = evaluation.get("groundedness_score", 0.0)
            total_groundedness += groundedness
            verdict = evaluation.get("verdict", "UNKNOWN")
            halluc_rate = evaluation.get("hallucination_rate", 0.0)
            accuracy = evaluation.get("accuracy_score", 0.0)
            ground_truth = evaluation.get("ground_truth_answer", "")

            badge = "🟢" if verdict == "SUPPORTED" else ("🟡" if verdict == "PARTIALLY_SUPPORTED" else "🔴")
            lines.append(f"### {badge} Evaluation: **{verdict}**")
            lines.append(f"- **Groundedness Score:** `{groundedness:.1f}%`")
            lines.append(f"- **Hallucination Rate:** `{halluc_rate:.1f}%`")
            lines.append(f"- **Accuracy Score:** `{accuracy:.1f}%`")
            lines.append("")

            if ground_truth:
                lines.append("**NIST Official Ground Truth:**")
                lines.append(f"> {ground_truth.strip()}")
                lines.append("")

        lines.append("**Agent Answer:**")
        lines.append("")
        lines.append(ans_text.strip() if ans_text else "_No response provided._")
        lines.append("")

        if evaluation and evaluation.get("claims"):
            lines.append("**Atomic Claim Verification Breakdown:**")
            lines.append("")
            lines.append("| Claim # | Extracted Claim | Type | Status | Detection Layer | Rationale / Matched Evidence |")
            lines.append("|---|---|---|---|---|---|")
            for idx, c in enumerate(evaluation["claims"], 1):
                c_text = c.get("text", "").replace("|", "\\|")
                c_type = c.get("claim_type", "general_fact")
                c_stat = c.get("status", "UNSUPPORTED")
                c_layer = c.get("matched_layer", "-")
                c_ev = (c.get("matched_fact") or c.get("rationale") or "-").replace("|", "\\|").replace("\n", " ")
                
                stat_icon = "✅" if c_stat == "SUPPORTED" else ("❌" if c_stat == "CONTRADICTORY" else "⚠️")
                lines.append(f"| {idx} | {c_text} | `{c_type}` | {stat_icon} {c_stat} | `{c_layer}` | {c_ev} |")
            lines.append("")

        lines.append("---")
        lines.append("")

    if evaluated_count > 0:
        avg_groundedness = total_groundedness / evaluated_count
        summary_header = [
            "# Executive Summary",
            "",
            f"- **Total Questions Evaluated:** `{evaluated_count}`",
            f"- **Mean Groundedness Score:** `{avg_groundedness:.1f}%`",
            "",
            "---",
            ""
        ]
        lines = summary_header + lines

    with open(args.out, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))

    print(f"Wrote formatted report to {args.out} ({len(results)} questions processed, {evaluated_count} evaluated).")


if __name__ == "__main__":
    main()

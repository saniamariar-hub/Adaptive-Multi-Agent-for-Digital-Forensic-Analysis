"""
evaluator/api.py
────────────────
REST API handlers and router for the Hallucination Evaluation module.
"""

import json
from typing import Dict, Any, Tuple
from evaluator.hybrid_engine import get_all_ground_truth, get_ground_truth_by_id, evaluate_response
from evaluator.report_evaluator import evaluate_report
from evaluator.storage import save_evaluation, get_evaluation, list_evaluations, get_summary_stats, save_report_evaluation

KNOWN_AGENTS = [
    {"id": "sentinel", "name": "Sentinel (Gemini)", "type": "AI_AGENTIC", "description": "Multi-model cascade AI agent with live Autopsy tool access"},
    {"id": "dispatcher", "name": "Forensic Dispatcher", "type": "DETERMINISTIC_RULES", "description": "Keyword & rule-based evidence dispatcher"},
    {"id": "triage", "name": "Triage Agent", "type": "PIPELINE_AGENT", "description": "Artifact extraction and initial evidence triage"},
    {"id": "correlation", "name": "Correlation Agent", "type": "PIPELINE_AGENT", "description": "Cross-artifact timeline and entity correlation"},
    {"id": "contradiction", "name": "Contradiction Agent", "type": "PIPELINE_AGENT", "description": "Evidentiary conflict and anomaly detector"},
    {"id": "synthesis", "name": "Synthesis Agent", "type": "PIPELINE_AGENT", "description": "Investigative report and timeline synthesizer"}
]


def handle_get_questions() -> Tuple[Dict[str, Any], int]:
    questions = get_all_ground_truth()
    summary_list = []
    for q in questions:
        summary_list.append({
            "question_id": q["question_id"],
            "question": q["question"],
            "source_pages": q.get("source_pages", []),
            "keywords": q.get("keywords", [])
        })
    return {"total": len(summary_list), "questions": summary_list}, 200


def handle_get_ground_truth(question_id: int) -> Tuple[Dict[str, Any], int]:
    gt = get_ground_truth_by_id(question_id)
    if not gt:
        return {"error": f"Question #{question_id} not found"}, 404
    return gt, 200


def handle_evaluate(data: Dict[str, Any]) -> Tuple[Dict[str, Any], int]:
    try:
        qid = int(data.get("question_id", 1))
        response_text = str(data.get("response_text", "")).strip()
        agent_name = str(data.get("agent_name", "Forensic Agent")).strip()

        if not response_text:
            return {"error": "response_text cannot be empty"}, 400

        eval_res = evaluate_response(response_text, question_id=qid, agent_name=agent_name)
        saved = save_evaluation(eval_res)
        return saved, 200
    except Exception as e:
        return {"error": str(e)}, 500


def handle_evaluate_report(data: Dict[str, Any]) -> Tuple[Dict[str, Any], int]:
    try:
        report_text = str(data.get("report_text", "")).strip()
        report_title = str(data.get("report_title", "Forensic Investigation Report")).strip()
        examiner = str(data.get("examiner", "Forensic Agent")).strip()

        if not report_text:
            return {"error": "report_text cannot be empty"}, 400

        rep_eval = evaluate_report(report_text, report_title=report_title, examiner=examiner)
        saved = save_report_evaluation(rep_eval)
        return saved, 200
    except Exception as e:
        return {"error": str(e)}, 500


def handle_get_results(params: Dict[str, str]) -> Tuple[Dict[str, Any], int]:
    limit = int(params.get("limit", 100))
    offset = int(params.get("offset", 0))
    agent = params.get("agent")
    qid_str = params.get("question_id")
    qid = int(qid_str) if qid_str and qid_str.isdigit() else None

    results = list_evaluations(limit=limit, offset=offset, agent=agent, question_id=qid)
    return {"total": len(results), "evaluations": results}, 200


def handle_get_result_by_id(eval_id: str) -> Tuple[Dict[str, Any], int]:
    res = get_evaluation(eval_id)
    if not res:
        return {"error": f"Evaluation {eval_id} not found"}, 404
    return res, 200


def handle_get_summary() -> Tuple[Dict[str, Any], int]:
    stats = get_summary_stats()
    return stats, 200


def handle_get_agents() -> Tuple[Dict[str, Any], int]:
    return {"agents": KNOWN_AGENTS}, 200


def handle_run_agent(data: Dict[str, Any]) -> Tuple[Dict[str, Any], int]:
    try:
        qid = int(data.get("question_id", 1))
        agent_id = str(data.get("agent_id", "sentinel")).lower()
        gt = get_ground_truth_by_id(qid)
        if not gt:
            return {"error": f"Question #{qid} not found"}, 404

        question_text = gt["question"]
        agent_response_text = ""
        agent_name = "Forensic Agent"

        # Execute agent
        if agent_id in ("sentinel", "gemini"):
            agent_name = "Sentinel (Gemini)"
            import forensic_agent
            if forensic_agent.GEMINI_API_KEY:
                chat_res = forensic_agent.answer(question_text)
                agent_response_text = chat_res.get("response", "")
            else:
                import forensic_dispatcher
                chat_res = forensic_dispatcher.dispatch_chat_query(question_text)
                agent_response_text = chat_res.get("response", "")
        elif agent_id in ("dispatcher", "rules"):
            agent_name = "Forensic Dispatcher"
            import forensic_dispatcher
            chat_res = forensic_dispatcher.dispatch_chat_query(question_text)
            agent_response_text = chat_res.get("response", "")
        else:
            # Check for existing outputs (triage, synthesis, correlation, contradiction)
            out_map = {
                "triage": BASE_DIR / "outputs" / "triage_result.json",
                "correlation": BASE_DIR / "outputs" / "correlation_result.json",
                "contradiction": BASE_DIR / "outputs" / "contradiction_result.json",
                "synthesis": BASE_DIR / "outputs" / "synthesis_result.json",
            }
            p = out_map.get(agent_id)
            if p and p.exists():
                with open(p, "r", encoding="utf-8") as f:
                    out_data = json.load(f)
                    agent_name = agent_id.capitalize() + " Agent"
                    # Render concise summary
                    obs = out_data.get("overall_observations", [])
                    exec_sum = out_data.get("executive_summary", "")
                    if exec_sum:
                        agent_response_text = f"**Executive Summary:** {exec_sum}\n\n" + "\n".join(f"- {o}" for o in obs[:5])
                    elif obs:
                        agent_response_text = "\n".join(f"- {o}" for o in obs)
                    else:
                        agent_response_text = f"Analyzed {out_data.get('total_evidence_count', 0)} evidence items in case {out_data.get('case_id')}."
            else:
                import forensic_dispatcher
                chat_res = forensic_dispatcher.dispatch_chat_query(question_text)
                agent_response_text = chat_res.get("response", "")
                agent_name = "Forensic Dispatcher"

        # Now evaluate the response
        eval_res = evaluate_response(agent_response_text, question_id=qid, agent_name=agent_name)
        saved = save_evaluation(eval_res)
        return saved, 200
    except Exception as e:
        return {"error": str(e)}, 500

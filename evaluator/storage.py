"""
evaluator/storage.py
────────────────────
SQLite persistence layer for Hallucination Evaluation audit logs,
claim-level verification results, and agent performance benchmarks.
"""

import sys
from pathlib import Path
_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

import sqlite3
import json
import uuid
from datetime import datetime
from typing import Dict, Any, List, Optional

DB_PATH = _ROOT / "evaluation_audit.db"

def get_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    with get_connection() as conn:
        conn.execute('''
            CREATE TABLE IF NOT EXISTS evaluations_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                evaluation_id TEXT NOT NULL UNIQUE,
                question_id INTEGER NOT NULL,
                agent_name TEXT NOT NULL,
                agent_response TEXT NOT NULL,
                ground_truth TEXT NOT NULL,
                source_pages TEXT,
                verdict TEXT NOT NULL,
                groundedness_score REAL NOT NULL,
                hallucination_rate REAL NOT NULL,
                contradiction_rate REAL NOT NULL,
                accuracy_score REAL NOT NULL,
                total_claims INTEGER NOT NULL,
                supported_claims INTEGER NOT NULL,
                partially_supported_claims INTEGER NOT NULL,
                unsupported_claims INTEGER NOT NULL,
                contradicted_claims INTEGER NOT NULL,
                undetermined_claims INTEGER NOT NULL,
                claim_results_json TEXT NOT NULL,
                metrics_json TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')

        conn.execute('''
            CREATE TABLE IF NOT EXISTS report_evaluations_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                report_eval_id TEXT NOT NULL UNIQUE,
                report_title TEXT NOT NULL,
                examiner TEXT NOT NULL,
                report_text TEXT NOT NULL,
                questions_detected_count INTEGER NOT NULL,
                detected_questions_json TEXT NOT NULL,
                groundedness_score REAL NOT NULL,
                hallucination_rate REAL NOT NULL,
                contradiction_rate REAL NOT NULL,
                metrics_json TEXT NOT NULL,
                question_breakdown_json TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        conn.commit()


def save_evaluation(eval_res: Dict[str, Any]) -> Dict[str, Any]:
    init_db()
    eval_id = f"EVAL-{datetime.now().strftime('%Y%m%d%H%M%S')}-{uuid.uuid4().hex[:6].upper()}"
    m = eval_res.get("metrics", {})
    
    src_pages_json = json.dumps(eval_res.get("source_pages", []))
    claims_json = json.dumps(eval_res.get("claims", []))
    metrics_json = json.dumps(m)
    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    with get_connection() as conn:
        conn.execute('''
            INSERT INTO evaluations_log (
                evaluation_id, question_id, agent_name, agent_response, ground_truth,
                source_pages, verdict, groundedness_score, hallucination_rate, contradiction_rate,
                accuracy_score, total_claims, supported_claims, partially_supported_claims,
                unsupported_claims, contradicted_claims, undetermined_claims, claim_results_json,
                metrics_json, timestamp
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            eval_id,
            eval_res.get("question_id", 1),
            eval_res.get("agent_name", "Forensic Agent"),
            eval_res.get("agent_response", ""),
            eval_res.get("ground_truth", ""),
            src_pages_json,
            m.get("verdict", "UNVERIFIED"),
            m.get("groundedness_score", 0.0),
            m.get("hallucination_rate", 0.0),
            m.get("contradiction_rate", 0.0),
            m.get("accuracy_score", 0.0),
            m.get("total_claims", 0),
            m.get("supported_claims", 0),
            m.get("partially_supported_claims", 0),
            m.get("unsupported_claims", 0),
            m.get("contradicted_claims", 0),
            m.get("undetermined_claims", 0),
            claims_json,
            metrics_json,
            eval_res.get("timestamp", now_str)
        ))
        conn.commit()

    eval_res["evaluation_id"] = eval_id
    return eval_res


def get_evaluation(evaluation_id: str) -> Optional[Dict[str, Any]]:
    init_db()
    with get_connection() as conn:
        row = conn.execute('SELECT * FROM evaluations_log WHERE evaluation_id = ?', (evaluation_id,)).fetchone()
        if not row:
            return None
        r = dict(row)
        r["source_pages"] = json.loads(r["source_pages"] or "[]")
        r["claims"] = json.loads(r["claim_results_json"] or "[]")
        r["metrics"] = json.loads(r["metrics_json"] or "{}")
        return r


def list_evaluations(limit: int = 100, offset: int = 0, agent: str = None, question_id: int = None) -> List[Dict[str, Any]]:
    init_db()
    query = "SELECT * FROM evaluations_log WHERE 1=1"
    params = []
    if agent:
        query += " AND agent_name = ?"
        params.append(agent)
    if question_id:
        query += " AND question_id = ?"
        params.append(question_id)
    query += " ORDER BY id DESC LIMIT ? OFFSET ?"
    params.extend([limit, offset])

    with get_connection() as conn:
        rows = conn.execute(query, params).fetchall()
        results = []
        for row in rows:
            r = dict(row)
            r["source_pages"] = json.loads(r["source_pages"] or "[]")
            r["claims"] = json.loads(r["claim_results_json"] or "[]")
            r["metrics"] = json.loads(r["metrics_json"] or "{}")
            results.append(r)
        return results


def save_report_evaluation(rep_eval: Dict[str, Any]) -> Dict[str, Any]:
    init_db()
    report_eval_id = f"REP-{datetime.now().strftime('%Y%m%d%H%M%S')}-{uuid.uuid4().hex[:6].upper()}"
    m = rep_eval.get("metrics", {})
    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    with get_connection() as conn:
        conn.execute('''
            INSERT INTO report_evaluations_log (
                report_eval_id, report_title, examiner, report_text, questions_detected_count,
                detected_questions_json, groundedness_score, hallucination_rate, contradiction_rate,
                metrics_json, question_breakdown_json, timestamp
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            report_eval_id,
            rep_eval.get("report_title", "Forensic Report"),
            rep_eval.get("examiner", "Forensic Agent"),
            rep_eval.get("report_text", ""),
            rep_eval.get("questions_detected_count", 0),
            json.dumps(rep_eval.get("detected_question_ids", [])),
            m.get("groundedness_score", 0.0),
            m.get("hallucination_rate", 0.0),
            m.get("contradiction_rate", 0.0),
            json.dumps(m),
            json.dumps(rep_eval.get("question_breakdown", [])),
            rep_eval.get("timestamp", now_str)
        ))
        conn.commit()

    rep_eval["report_eval_id"] = report_eval_id
    return rep_eval


def list_report_evaluations(limit: int = 50, offset: int = 0) -> List[Dict[str, Any]]:
    init_db()
    with get_connection() as conn:
        rows = conn.execute(
            'SELECT * FROM report_evaluations_log ORDER BY id DESC LIMIT ? OFFSET ?',
            (limit, offset)
        ).fetchall()
        results = []
        for row in rows:
            r = dict(row)
            r["detected_questions"] = json.loads(r["detected_questions_json"] or "[]")
            r["metrics"] = json.loads(r["metrics_json"] or "{}")
            r["question_breakdown"] = json.loads(r["question_breakdown_json"] or "[]")
            results.append(r)
        return results


def get_summary_stats() -> Dict[str, Any]:
    init_db()
    with get_connection() as conn:
        total_evals = conn.execute('SELECT COUNT(*) FROM evaluations_log').fetchone()[0]
        total_reports = conn.execute('SELECT COUNT(*) FROM report_evaluations_log').fetchone()[0]
        
        c_stats = conn.execute('''
            SELECT 
                SUM(total_claims) as total_claims,
                SUM(supported_claims) as supported,
                SUM(partially_supported_claims) as partial,
                SUM(unsupported_claims) as unsupported,
                SUM(contradicted_claims) as contradicted,
                SUM(undetermined_claims) as undetermined,
                AVG(groundedness_score) as avg_groundedness,
                AVG(hallucination_rate) as avg_hallucination,
                AVG(contradiction_rate) as avg_contradiction
            FROM evaluations_log
        ''').fetchone()

        agent_rows = conn.execute('''
            SELECT 
                agent_name,
                COUNT(DISTINCT question_id) as questions_evaluated,
                COUNT(*) as total_evaluations,
                AVG(groundedness_score) as groundedness,
                AVG(hallucination_rate) as hallucination_rate,
                AVG(contradiction_rate) as contradiction_rate,
                SUM(contradicted_claims) as total_contradictions,
                SUM(supported_claims) as total_supported,
                SUM(total_claims) as total_claims
            FROM evaluations_log
            GROUP BY agent_name
            ORDER BY groundedness DESC
        ''').fetchall()

        agent_benchmarks = []
        for r in agent_rows:
            agent_benchmarks.append({
                "agent_name": r["agent_name"],
                "questions_evaluated": r["questions_evaluated"],
                "total_evaluations": r["total_evaluations"],
                "groundedness": round((r["groundedness"] or 0) * 100, 1),
                "hallucination_rate": round((r["hallucination_rate"] or 0) * 100, 1),
                "contradiction_rate": round((r["contradiction_rate"] or 0) * 100, 1),
                "total_contradictions": r["total_contradictions"] or 0,
                "total_supported": r["total_supported"] or 0,
                "total_claims": r["total_claims"] or 0
            })

        recent_rows = conn.execute('SELECT * FROM evaluations_log ORDER BY id DESC LIMIT 10').fetchall()
        recent_evals = []
        for row in recent_rows:
            r = dict(row)
            r["source_pages"] = json.loads(r["source_pages"] or "[]")
            r["claims"] = json.loads(r["claim_results_json"] or "[]")
            r["metrics"] = json.loads(r["metrics_json"] or "{}")
            recent_evals.append(r)

        return {
            "total_questions": 60,
            "total_evaluations": total_evals,
            "total_reports_evaluated": total_reports,
            "total_claims": c_stats["total_claims"] or 0,
            "grounded_claims": c_stats["supported"] or 0,
            "partial_claims": c_stats["partial"] or 0,
            "hallucinated_claims": c_stats["unsupported"] or 0,
            "contradicted_claims": c_stats["contradicted"] or 0,
            "undetermined_claims": c_stats["undetermined"] or 0,
            "overall_groundedness": round((c_stats["avg_groundedness"] or 1.0) * 100, 1),
            "overall_hallucination_rate": round((c_stats["avg_hallucination"] or 0.0) * 100, 1),
            "overall_contradiction_rate": round((c_stats["avg_contradiction"] or 0.0) * 100, 1),
            "agent_benchmarks": agent_benchmarks,
            "recent_evaluations": recent_evals
        }


get_evaluations = list_evaluations
get_report_evaluations = list_report_evaluations
get_evaluation_summary = get_summary_stats


def seed_benchmark_evaluations():
    """Seed initial evaluation runs from actual forensic outputs and agent responses."""
    init_db()
    with get_connection() as conn:
        count = conn.execute('SELECT COUNT(*) FROM evaluations_log').fetchone()[0]
        if count > 0:
            return

    from evaluator.hybrid_engine import evaluate_response

    sample_seed_runs = [
        (3, "The suspect PC was running Windows 7 Ultimate SP1 (Build 7601), Registered Owner: informant, Install Date: 2015-03-22.", "Sentinel (Gemini)"),
        (4, "The system timezone was configured to Eastern Time (UTC-05:00) with Daylight Time Bias +1.", "Sentinel (Gemini)"),
        (5, "The computer name is INFORMANT-PC.", "Sentinel (Gemini)"),
        (9, "Network interface assigned by DHCP: IP 10.11.11.129, Subnet Mask 255.255.255.0, Default Gateway 10.11.11.2, DHCP Server 10.11.11.254.", "Forensic Dispatcher"),
        (20, "Suspect email account was iaman.informant@nist.gov.", "Synthesis Agent"),
        (21, "Recovered emails between iaman.informant@nist.gov and spy.conspirator@nist.gov regarding confidential technology documents.", "Synthesis Agent"),
        (22, "Attached USB devices: SanDisk Cruzer Fit (Serial: 4C530012450531101593) first connected on 2015-03-24 09:38:00.", "Triage Agent"),
        (24, "The company shared network drive IP address is 10.11.11.128.", "Correlation Agent"),
        (31, "Google Drive account was iaman.informant.personal@gmail.com synchronized at 2015-03-23 16:05:32.", "Synthesis Agent"),
        (36, "Resignation file resignation.docx timestamps created on Windows Desktop on 2015-03-24.", "Correlation Agent"),
        (51, "Recycle Bin contains deleted staging files from Burn directory: desktop.ini, prop.txt, tr.txt.", "Contradiction Agent"),
        (1, "PC image MD5 is A49D1254C873808C58E6F1BCD60B5BDE and SHA-1 is AFE5C9AB487BD47A8A9856B1371C2384D44FD785.", "Triage Agent")
    ]

    for qid, text, agent in sample_seed_runs:
        eval_res = evaluate_response(text, question_id=qid, agent_name=agent)
        save_evaluation(eval_res)

    print("[OK] Seeded initial evaluation audit database with realistic benchmark runs.")


if __name__ == "__main__":
    seed_benchmark_evaluations()
    stats = get_summary_stats()
    print("Summary Stats:", json.dumps(stats, indent=2))

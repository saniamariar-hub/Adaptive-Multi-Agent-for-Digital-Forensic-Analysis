"""
evaluator/report_evaluator.py
─────────────────────────────
Evaluates complete, multi-question digital forensics reports against the
60 NIST CFReDS Ground Truth questions.
Detects addressed questions, extracts and maps atomic claims, runs hybrid evaluation,
and produces aggregated report-level hallucination metrics.
"""

import re
import datetime
from typing import Dict, Any, List, Tuple
from evaluator.hybrid_engine import get_all_ground_truth, get_ground_truth_by_id, evaluate_single_claim
from evaluator.claim_extractor import extract_claims
from evaluator.metrics import compute_evaluation_metrics


def match_text_to_question(section_title: str, section_content: str, all_questions: List[Dict[str, Any]]) -> Tuple[int, float]:
    """
    Identifies which NIST question ID best corresponds to a section of text or report.
    Returns (question_id, match_confidence).
    """
    combined = (section_title + " " + section_content).lower()

    # 1. Check for explicit question numbers: "Q3", "Question 3", "Q03", "3.", etc.
    q_num_match = re.search(r'\b(?:question|q)\s*[:#\.\-]?\s*(\d{1,2})\b', section_title, re.IGNORECASE)
    if q_num_match:
        qid = int(q_num_match.group(1))
        if 1 <= qid <= 60:
            return qid, 1.0

    # 2. Check topic-based heuristics for common sections
    if any(k in section_title.lower() for k in ("os info", "operating system", "windows version", "install date", "os analysis")):
        return 3, 0.95
    if any(k in section_title.lower() for k in ("timezone", "time zone")):
        return 4, 0.95
    if any(k in section_title.lower() for k in ("computer name", "hostname")):
        return 5, 0.95
    if any(k in section_title.lower() for k in ("user account", "os account", "user profile")):
        return 6, 0.95
    if any(k in section_title.lower() for k in ("shutdown date", "shutdown time", "last recorded shutdown")):
        return 8, 0.95
    if any(k in section_title.lower() for k in ("dhcp", "network interface", "network configuration", "ip address")):
        if "shared network drive" in combined or "company network drive" in combined:
            return 24, 0.90
        return 9, 0.95
    if any(k in section_title.lower() for k in ("image hash", "md5", "sha-1", "hash values")):
        return 1, 0.95
    if any(k in section_title.lower() for k in ("partition", "disk geometry", "disk volume")):
        return 2, 0.95
    if any(k in section_title.lower() for k in ("email", "e-mail", "outlook", "ost file")):
        return 21, 0.90
    if any(k in section_title.lower() for k in ("usb", "external storage", "attached device")):
        return 22, 0.95
    if any(k in section_title.lower() for k in ("google drive", "cloud service", "cloud sync", "cloud exfiltration")):
        if "deleted" in combined:
            return 30, 0.90
        return 31, 0.90
    if any(k in section_title.lower() for k in ("cd-r", "burning", "cd burn")):
        return 32, 0.90
    if any(k in section_title.lower() for k in ("resignation", "resignation file")):
        return 36, 0.95
    if any(k in section_title.lower() for k in ("recycle bin", "deleted files")):
        return 51, 0.95
    if any(k in section_title.lower() for k in ("timeline", "chronology", "sequence of events")):
        return 58, 0.90

    # 3. Fuzzy match against questions
    best_qid = 1
    best_score = -1.0
    stop = {'what', 'when', 'where', 'which', 'who', 'how', 'the', 'and', 'for', 'are', 'was', 'were', 'from', 'this', 'that', 'with', 'about', 'only', 'also', 'list', 'identify', 'explain', 'data', 'file', 'section'}
    title_words = set(w for w in re.findall(r'[a-zA-Z0-9_\-]+', section_title.lower()) if len(w) > 2 and w not in stop)
    content_words = set(w for w in re.findall(r'[a-zA-Z0-9_\-]+', section_content.lower()) if len(w) > 3 and w not in stop)

    for q in all_questions:
        qid = q["question_id"]
        q_keywords = set(w.lower() for w in q.get("keywords", []))
        q_text_words = set(w for w in re.findall(r'[a-zA-Z0-9_\-]+', q["question"].lower()) if len(w) > 2 and w not in stop)

        title_overlap = len(title_words.intersection(q_keywords.union(q_text_words))) if title_words else 0
        content_overlap = len(content_words.intersection(q_keywords.union(q_text_words))) if content_words else 0

        score = title_overlap * 4.0 + content_overlap * 1.0
        if score > best_score:
            best_score = score
            best_qid = qid

    confidence = min(0.95, max(0.40, best_score / 6.0)) if best_score > 0 else 0.30
    return best_qid, confidence


def split_report_into_sections(report_text: str) -> List[Dict[str, str]]:
    """
    Splits a full report into distinct logical sections by headers, bullet blocks, or question dividers.
    """
    lines = report_text.split('\n')
    sections = []
    current_title = "Executive Summary / Overview"
    current_lines = []

    for line in lines:
        sline = line.strip()
        header_match = re.match(r'^(?:[#]{1,4}\s+|(?:\*{1,2}|_{1,2})?(?:Q\d+|Question\s+\d+|Section\s+\d+|\[.+?\])(?:\*{1,2}|_{1,2})?[:\.\s\-]+)(.*)$', sline, re.IGNORECASE)
        is_header = bool(header_match or sline.startswith('#'))

        if is_header:
            content = "\n".join(current_lines).strip()
            if content:
                sections.append({"title": current_title, "content": content})
            current_title = sline.lstrip('#').strip()
            current_lines = []
        else:
            current_lines.append(line)

    if current_lines:
        content = "\n".join(current_lines).strip()
        if content:
            sections.append({"title": current_title, "content": content})

    if not sections and report_text.strip():
        sections.append({"title": "Full Report Text", "content": report_text.strip()})

    return sections


def evaluate_report(report_text: str, report_title: str = "Forensic Investigation Report", examiner: str = "Forensic Agent") -> Dict[str, Any]:
    """
    Full Forensic Report Evaluation Pipeline.
    """
    all_questions = get_all_ground_truth()
    sections = split_report_into_sections(report_text)

    all_evaluated_claims = []
    question_breakdown = {}
    detected_question_ids = set()

    for sec in sections:
        sec_title = sec["title"]
        sec_content = sec["content"]

        qid, match_conf = match_text_to_question(sec_title, sec_content, all_questions)
        detected_question_ids.add(qid)

        gt_q = get_ground_truth_by_id(qid)
        claims = extract_claims(sec_content, question_id=qid)
        
        evaluated_sec_claims = [evaluate_single_claim(c, qid) for c in claims]
        all_evaluated_claims.extend(evaluated_sec_claims)

        if qid not in question_breakdown:
            question_breakdown[qid] = {
                "question_id": qid,
                "question": gt_q.get("question", f"NIST Q{qid}") if gt_q else f"Q{qid}",
                "section_title": sec_title,
                "claims": [],
                "source_pages": gt_q.get("source_pages", []) if gt_q else []
            }
        question_breakdown[qid]["claims"].extend(evaluated_sec_claims)

    for qid, q_data in question_breakdown.items():
        q_data["metrics"] = compute_evaluation_metrics(q_data["claims"])

    overall_metrics = compute_evaluation_metrics(all_evaluated_claims)
    overall_metrics["questions_detected"] = len(detected_question_ids)
    overall_metrics["total_nist_questions"] = 60
    overall_metrics["question_coverage_percentage"] = round((len(detected_question_ids) / 60.0) * 100, 2)

    timestamp_str = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    return {
        "report_title": report_title,
        "examiner": examiner,
        "report_text": report_text,
        "questions_detected_count": len(detected_question_ids),
        "detected_question_ids": sorted(list(detected_question_ids)),
        "metrics": overall_metrics,
        "question_breakdown": [question_breakdown[qid] for qid in sorted(question_breakdown.keys())],
        "all_claims": all_evaluated_claims,
        "timestamp": timestamp_str
    }


evaluate_forensic_report = evaluate_report

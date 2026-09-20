import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from evaluator.report_evaluator import evaluate_report

sample_report = """
# Comprehensive Case Report: NIST Data Leakage

### Section 1: PC System and OS Analysis
The suspect machine hostname was INFORMANT-PC.
The system was running Windows 7 Ultimate SP1 64-bit English.
The system timezone was configured to Eastern Time (UTC-05:00).

### Section 2: Network Configuration
The network interface received IP address 10.11.11.129 from DHCP server.
The internal corporate shared network drive was located at 10.11.11.128.

### Section 3: Cloud Exfiltration
The suspect logged into Google Drive using iaman.informant.personal@gmail.com.
File happy_holiday.jpg was deleted from Google Drive on 2015-03-23.
"""

rep_eval = evaluate_report(sample_report, report_title="Sample Multi-Section Report", examiner="Sentinel Agent")
m = rep_eval["metrics"]
print(f"Questions detected: {rep_eval['questions_detected_count']}/60 ({rep_eval['detected_question_ids']})")
print(f"Total claims: {m['total_claims']}, Supported: {m['supported_claims']}, Contradicted: {m['contradicted_claims']}")
print(f"Groundedness: {m['groundedness_score']}, Hallucination rate: {m['hallucination_rate']}")
print("Sections breakdown:")
for q in rep_eval["question_breakdown"]:
    print(f"  Q{q['question_id']}: {len(q['claims'])} claims (Score: {q['metrics']['groundedness_score']}) - {q['section_title']}")

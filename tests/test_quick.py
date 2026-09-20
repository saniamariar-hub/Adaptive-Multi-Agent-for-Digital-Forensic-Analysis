import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from evaluator.hybrid_engine import evaluate_response

cases = [
    (3, "The suspect PC was running Windows 7 Ultimate SP1.", "Supported OS"),
    (3, "The suspect PC was running Windows 10 Pro 64-bit.", "Contradicted OS"),
    (9, "The network interface was assigned IP 10.11.11.129 via DHCP.", "Supported DHCP IP"),
    (9, "The network interface was assigned IP 192.168.1.105 via DHCP.", "Contradicted DHCP IP"),
    (31, "The suspect synchronized Google Drive with iaman.informant.personal@gmail.com on 2015-03-23.", "Supported GDrive email"),
    (31, "The suspect synchronized Google Drive with fake_intruder@darknet.ru.", "Hallucinated email"),
    (1, "The PC image MD5 hash value is A49D1254C873808C58E6F1BCD60B5BDE.", "Supported MD5 hash")
]

for qid, text, desc in cases:
    res = evaluate_response(text, question_id=qid, agent_name="Test Agent")
    m = res["metrics"]
    c0 = res["claims"][0]
    print(f"Test: {desc}")
    print(f"  Classification: {c0['classification']} (conf={c0['confidence']})")
    print(f"  Layer: {c0['layer_resolved']}")
    print(f"  Reason: {c0['reason']}")
    print(f"  Groundedness: {m['groundedness_score']}, Hallucination Rate: {m['hallucination_rate']}")
    print("-" * 60)

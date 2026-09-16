"""
format_results.py

Converts run_investigation.py's results.json into a readable Markdown
report, one section per question, so you can put it in a split pane next
to NIST's official leakage-answers.pdf (or .docx) and grade question by
question.

This script does not attempt to score answers automatically -- exact
wording will legitimately differ from NIST's phrasing, so grading stays
manual. It only removes the friction of reading raw JSON while doing it.

Usage:
    python format_results.py results.json --out results.md
"""

import argparse
import json


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("results_json")
    parser.add_argument("--out", default="results.md")
    args = parser.parse_args()

    with open(args.results_json) as f:
        results = json.load(f)

    lines = ["# Agent Answers vs. NIST Ground Truth", ""]
    for item in results:
        lines.append(f"## Q{item['question_number']}. {item['question']}")
        lines.append("")
        lines.append("**Agent answer:**")
        lines.append("")
        lines.append(item["answer"])
        lines.append("")
        lines.append("**Verdict (fill in while comparing to the PDF):** ")
        lines.append("")
        lines.append("---")
        lines.append("")

    with open(args.out, "w") as f:
        f.write("\n".join(lines))

    print(f"Wrote {args.out} ({len(results)} questions)")


if __name__ == "__main__":
    main()

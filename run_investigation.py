"""
run_investigation.py

Feeds the 60 published questions from the NIST CFReDS Data Leakage Case to
a Hermes Agent instance, one at a time, restricted to the "autopsy" MCP
toolset, and writes every answer to a JSON file alongside the question
text. That output file is what you diff against NIST's official answer
key (leakage-answers.pdf / leakage-answers.docx) for cross-checking.

Requires:
    - hermes-agent installed and importable as run_agent.AIAgent
      (see the framework's own install docs; typically you clone
      https://github.com/NousResearch/hermes-agent and run this script
      from inside that directory, or `pip install` it as a package).
    - The "autopsy" MCP server registered in ~/.hermes/config.yaml as
      shown in hermes_config_snippet.yaml, pointing at your case.db.
    - OPENAI_API_KEY set in the environment or in ~/.hermes/.env.

Usage:
    python run_investigation.py --out results.json
    python run_investigation.py --out results.json --only 1 2 3
"""

import argparse
import json
import os
import sys

try:
    from run_agent import AIAgent
except ImportError:
    AIAgent = None

QUESTIONS = [
    "What are the hash values (MD5 and SHA-1) of all images? Does the acquisition and verification hash value match?",
    "Identify the partition information of the PC image.",
    "Explain the installed OS information in detail (OS name, install date, registered owner).",
    "What is the timezone setting?",
    "What is the computer name?",
    "List all accounts in the OS except the system accounts (Administrator, Guest, systemprofile, LocalService, NetworkService): account name, login count, last logon date.",
    "Who was the last user to logon into the PC?",
    "When was the last recorded shutdown date/time?",
    "Explain the information of network interface(s) with an IP address assigned by DHCP.",
    "What applications were installed by the suspect after installing the OS?",
    "List application execution logs: executable path, execution time, execution count.",
    "List all traces of system on/off and user logon/logoff, considering only the time range 09:00 to 18:00 in the timezone identified earlier.",
    "What web browsers were used?",
    "Identify directory/file paths related to the web browser history.",
    "What websites was the suspect accessing? Include timestamp and URL.",
    "List all search keywords used in web browsers, with timestamp, URL, and keyword.",
    "List all user keywords entered in the Windows Explorer search bar, with timestamp and keyword.",
    "What application was used for e-mail communication?",
    "Where is the e-mail file located?",
    "What was the e-mail account used by the suspect?",
    "List all e-mails of the suspect, identifying deleted e-mails if possible: timestamp, from, to, subject, body, attachment. Examine the OST file only.",
    "List external storage devices attached to the PC.",
    "Identify all traces related to renaming of files in Windows Desktop, considering only the date range 2015-03-23 to 2015-03-24. Note: the parent directories of renamed files were deleted and their MFT entries overwritten, so full paths may not be recoverable.",
    "What is the IP address of the company's shared network drive?",
    "List all directories that were traversed in RM#2.",
    "List all files that were opened in RM#2.",
    "List all directories that were traversed in the company's network drive.",
    "List all files that were opened in the company's network drive.",
    "Find traces related to cloud services on the PC: service name and log files.",
    "What files were deleted from Google Drive? Find the filename and modified timestamp. Look for a transaction log file of Google Drive.",
    "Identify account information for synchronizing Google Drive.",
    "What method or software was used for burning the CD-R?",
    "When did the suspect burn the CD-R? It may be one or more times.",
    "What files were copied from the PC to the CD-R? Use the PC image only, and examine file system transaction logs.",
    "What files were opened from the CD-R?",
    "Identify all timestamps related to a resignation file in Windows Desktop. The resignation file is a DOCX file in the NTFS file system.",
    "How and when did the suspect print the resignation file?",
    "Where are Thumbcache files located?",
    "Identify traces related to confidential files stored in Thumbcache. Include the 256 thumbcache file only.",
    "Where are Sticky Note files located?",
    "Identify notes stored in the Sticky Note file.",
    "Was the Windows Search and Indexing function enabled? How can you identify it, and if enabled, what is the file path of the Windows Search index database?",
    "What kinds of data were stored in the Windows Search database?",
    "Find traces of Internet Explorer usage stored in the Windows Search database, considering only the date range 2015-03-22 to 2015-03-23.",
    "List the e-mail communication stored in the Windows Search database, considering only the date range 2015-03-23 to 2015-03-24.",
    "List files and directories related to Windows Desktop stored in the Windows Search database (Windows Desktop directory: \\Users\\informant\\Desktop\\).",
    "Where are Volume Shadow Copies stored, and when were they created?",
    "Find traces related to the Google Drive service in Volume Shadow Copy. What are the differences between the current system image and its VSC?",
    "What files were deleted from Google Drive? Find deleted records of the cloud_entry table inside snapshot.db from the VSC (examine the SQLite database only; assume the text-based log was wiped). Table DDL: CREATE TABLE cloud_entry (doc_id TEXT, filename TEXT, modified INTEGER, created INTEGER, acl_role INTEGER, doc_type INTEGER, removed INTEGER, size INTEGER, checksum TEXT, shared INTEGER, resource_type TEXT, PRIMARY KEY (doc_id)).",
    "Why can't we find Outlook's e-mail data in Volume Shadow Copy?",
    "Examine Recycle Bin data in the PC.",
    "What actions were performed for anti-forensics on the PC on the last day, 2015-03-25?",
    "Recover deleted files from USB drive RM#2.",
    "What actions were performed for anti-forensics on USB drive RM#2? This can be inferred from the file recovery results.",
    "What files were copied from the PC to USB drive RM#2?",
    "Recover hidden files from the CD-R RM#3. How can proper filenames of the original files be determined prior to renaming?",
    "What actions were performed for anti-forensics on the CD-R RM#3?",
    "Create a detailed timeline of the data leakage process.",
    "List and explain the methodologies of data leakage performed by the suspect.",
    "Create a visual diagram summarizing the results.",
]

SYSTEM_PROMPT = (
    "You are a digital forensics analyst investigating the NIST CFReDS "
    "Data Leakage Case. Answer only using the autopsy MCP tools available "
    "to you. If a tool call returns no data relevant to the question, say "
    "so explicitly rather than guessing or filling gaps from general "
    "knowledge. For every factual claim, cite the source file, artifact "
    "type, or table the data came from. Tool responses that return "
    "large sets include a 'truncated' field -- if it is true, narrow "
    "your query with start_ts/end_ts or a smaller limit and call the "
    "tool again rather than answering from a partial page as if it were "
    "complete."
)


def main():
    parser = argparse.ArgumentParser(description="Run investigative questions against forensic agent and evaluate.")
    parser.add_argument("--out", default="results.json", help="Output JSON path")
    parser.add_argument("--model", default="openai/gpt-5.6-terra", help="Model name for AIAgent")
    parser.add_argument(
        "--only", nargs="*", type=int, default=None, help="1-based question numbers to run"
    )
    parser.add_argument(
        "--evaluate", action="store_true", help="Run automated NIST hallucination evaluation on each response"
    )
    parser.add_argument(
        "--agent-name", default="Sentinel Investigation Agent", help="Agent identifier for audit logging"
    )
    args = parser.parse_args()

    if AIAgent is None:
        print("[WARNING] 'run_agent.AIAgent' could not be imported (hermes-agent not installed in current environment).")
        print("          If you already have a results.json file, you can evaluate it using 'format_results.py --evaluate' or the web dashboard.")
        sys.exit(1)

    agent = AIAgent(
        model=args.model,
        enabled_toolsets=["autopsy"],
        quiet_mode=True,
    )

    eval_engine = None
    save_eval = None
    if args.evaluate:
        try:
            from evaluator.hybrid_engine import evaluate_response
            from evaluator.storage import save_evaluation
            eval_engine = evaluate_response
            save_eval = save_evaluation
            print("[INFO] Hallucination evaluation engine initialized.")
        except Exception as e:
            print(f"[WARNING] Failed to load evaluation engine: {e}")

    indices = args.only or range(1, len(QUESTIONS) + 1)
    results = []
    for i in indices:
        question = QUESTIONS[i - 1]
        result = agent.run_conversation(
            user_message=question,
            system_message=SYSTEM_PROMPT,
            task_id=f"q{i}",
        )
        answer_text = result.get("final_response", "") if isinstance(result, dict) else str(result)
        
        item = {
            "question_number": i,
            "question": question,
            "answer": answer_text,
        }

        if eval_engine:
            try:
                eval_res = eval_engine(
                    question_id=i,
                    question_text=question,
                    agent_response=answer_text,
                    agent_name=args.agent_name,
                )
                if save_eval:
                    save_eval(eval_res)
                item["evaluation"] = eval_res
                print(f"[{i}/{len(QUESTIONS)}] Q{i} Done -> Groundedness: {eval_res['groundedness_score']}% | Verdict: {eval_res['verdict']}")
            except Exception as e:
                print(f"[{i}/{len(QUESTIONS)}] Q{i} Done (Eval Error: {e})")
        else:
            print(f"[{i}/{len(QUESTIONS)}] done")

        results.append(item)

    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2, ensure_ascii=False)
    print(f"\nInvestigation complete. Saved {len(results)} responses to {args.out}")


if __name__ == "__main__":
    main()

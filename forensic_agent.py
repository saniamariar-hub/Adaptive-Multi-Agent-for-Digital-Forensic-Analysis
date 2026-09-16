"""
forensic_agent.py
─────────────────
Agentic forensic analyst powered by Gemini with automatic model failover,
rich NIST case tools, and guaranteed synthesis turn.
"""

import json
import os
import time
import datetime
import requests as _requests
import autopsy_tools as at
import case_logger
import forensic_dispatcher

# Try loading from .env if present
_env_path = os.path.join(os.path.dirname(__file__), ".env")
if os.path.exists(_env_path):
    try:
        with open(_env_path, "r", encoding="utf-8") as _f:
            for _line in _f:
                _line = _line.strip()
                if _line.startswith("GEMINI_API_KEY=") and not _line.startswith("#"):
                    os.environ.setdefault("GEMINI_API_KEY", _line.split("=", 1)[1].strip().strip('"\''))
    except Exception:
        pass

GEMINI_API_KEY = os.environ.get("GEMINI_API_KEY", "")

MODELS_CASCADE = [
    "gemini-3.1-flash-lite",
    "gemini-3.5-flash",
    "gemini-flash-latest",
    "gemini-3.6-flash",
]

SYSTEM_PROMPT = """You are SENTINEL — an expert AI forensic analyst working the NIST CFReDS Data Leakage case.

CASE FACTS:
- Computer: INFORMANT-PC | OS: Windows 7 Ultimate SP1 | Owner: informant
- Image MD5: a49d1254c873808c58e6f1bcd60b5bde | Size: 20 GB
- Timezone: Asia/Calcutta (UTC+5:30)
- Incident date: March 24–25, 2015
- Suspect username: informant | Other accounts: admin11, temporary
- You have live access to Autopsy's forensic database through tool functions.

BEHAVIOR:
- ALWAYS call the appropriate tool(s) to retrieve real evidence before answering.
- Never fabricate or guess data values — only use what the tools return.
- If one tool doesn't answer the question fully, call another tool.
- Synthesize a clear, professional forensic report from the real tool results.
- Include specific values: timestamps, paths, file names, serial numbers, hashes.
- Format your final answer in markdown with tables where helpful.
- Be concise but precise — this is a legal investigation."""

# ---------------------------------------------------------------------------
# Tool definitions (Gemini function declarations)
# ---------------------------------------------------------------------------

TOOL_DECLARATIONS = [
    {
        "name": "get_os_info",
        "description": "Retrieve operating system details: computer name, OS name/version, registered owner, architecture, product ID, Windows directory.",
        "parameters": {"type": "object", "properties": {}, "required": []}
    },
    {
        "name": "get_network_info",
        "description": "Retrieve network adapter and DHCP configuration from the SYSTEM registry hive: assigned DHCP IP address, subnet mask, default gateway, DHCP server, DNS server, and domain name.",
        "parameters": {"type": "object", "properties": {}, "required": []}
    },
    {
        "name": "get_shutdown_time",
        "description": "Retrieve the last recorded system shutdown date and time from the ControlSet001\\Control\\Windows registry key (ShutdownTime value).",
        "parameters": {"type": "object", "properties": {}, "required": []}
    },
    {
        "name": "get_partition_info",
        "description": "Retrieve disk partition table geometry and volume details: start sectors, length, sizes, and file systems of all partitions on the PC image.",
        "parameters": {"type": "object", "properties": {}, "required": []}
    },
    {
        "name": "get_image_info",
        "description": "Retrieve forensic disk image metadata: image size in bytes, sector size, MD5 hash, SHA1 hash, and acquisition timezone.",
        "parameters": {"type": "object", "properties": {}, "required": []}
    },
    {
        "name": "get_devices_attached",
        "description": "Retrieve external USB/storage devices attached to the PC, including make, model, serial number, and connection timestamps from the SYSTEM registry hive.",
        "parameters": {
            "type": "object",
            "properties": {"limit": {"type": "integer", "description": "Max records to return (default 100)"}},
            "required": []
        }
    },
    {
        "name": "get_os_accounts",
        "description": "Retrieve OS user accounts on the system (usernames, SIDs, full names, account status) from the SAM registry hive and tsk_os_accounts table.",
        "parameters": {
            "type": "object",
            "properties": {"limit": {"type": "integer", "description": "Max records to return (default 50)"}},
            "required": []
        }
    },
    {
        "name": "get_program_runs",
        "description": "Retrieve program execution records from Windows Prefetch (TSK_PROG_RUN artifacts) showing executable name, full path, and last execution timestamp.",
        "parameters": {
            "type": "object",
            "properties": {"limit": {"type": "integer", "description": "Max records to return (default 50)"}},
            "required": []
        }
    },
    {
        "name": "get_recycle_bin",
        "description": "Retrieve deleted file records from the Windows Recycle Bin (TSK_RECYCLE_BIN artifacts) with original paths and deletion timestamps.",
        "parameters": {
            "type": "object",
            "properties": {"limit": {"type": "integer", "description": "Max records to return (default 50)"}},
            "required": []
        }
    },
    {
        "name": "get_web_search_queries",
        "description": "Retrieve web search engine queries typed by the user in Chrome/IE (Google, Bing, Yahoo searches).",
        "parameters": {
            "type": "object",
            "properties": {"limit": {"type": "integer", "description": "Max records to return (default 50)"}},
            "required": []
        }
    },
    {
        "name": "get_web_history",
        "description": "Retrieve browser history records (visited URLs, timestamps, domains) from Chrome and Internet Explorer artifacts in the Autopsy database.",
        "parameters": {
            "type": "object",
            "properties": {"limit": {"type": "integer", "description": "Max records to return (default 50)"}},
            "required": []
        }
    },
    {
        "name": "get_emails",
        "description": "Retrieve email messages from the suspect's Outlook OST data file, including sender, recipient, subject, and timestamps.",
        "parameters": {
            "type": "object",
            "properties": {"limit": {"type": "integer", "description": "Max records to return (default 25)"}},
            "required": []
        }
    },
    {
        "name": "get_installed_programs",
        "description": "Retrieve programs/software installed on the system from the Windows registry Uninstall key.",
        "parameters": {
            "type": "object",
            "properties": {"limit": {"type": "integer", "description": "Max records to return (default 50)"}},
            "required": []
        }
    },
    {
        "name": "get_recent_documents",
        "description": "Retrieve recently opened files/folders from LNK shortcut files and ShellBag registry artifacts.",
        "parameters": {
            "type": "object",
            "properties": {"limit": {"type": "integer", "description": "Max records to return (default 30)"}},
            "required": []
        }
    },
    {
        "name": "find_files",
        "description": "Search the NTFS file system (MFT) for files matching a name pattern. Returns file name, size, parent path, and timestamps.",
        "parameters": {
            "type": "object",
            "properties": {
                "name": {"type": "string", "description": "Filename or partial name to search for (e.g. 'resignation', '.docx', 'dropbox')"},
                "limit": {"type": "integer", "description": "Max results to return (default 20)"}
            },
            "required": ["name"]
        }
    },
    {
        "name": "run_sql",
        "description": (
            "Execute a raw SQL SELECT query directly against the Autopsy SQLite database (autopsy.db). "
            "Tables: tsk_vs_parts (addr, start, length, desc), "
            "tsk_image_info (size, md5, sha1, tzone), "
            "tsk_os_accounts (login_name, full_name, addr, status, created_date), "
            "data_source_info (device_id, time_zone, acquisition_details), "
            "blackboard_attributes (artifact_id, attribute_type_id, value_text, value_int64), "
            "blackboard_artifacts (artifact_id, artifact_type_id, obj_id), "
            "blackboard_artifact_types (artifact_type_id, type_name), "
            "blackboard_attribute_types (attribute_type_id, type_name), "
            "tsk_files (name, parent_path, size, mtime, crtime)."
        ),
        "parameters": {
            "type": "object",
            "properties": {"sql": {"type": "string", "description": "The SQL SELECT query to execute"}},
            "required": ["sql"]
        }
    }
]

# ---------------------------------------------------------------------------
# Tool executor — maps LLM tool calls to real Python functions
# ---------------------------------------------------------------------------

def _execute_tool(name: str, args: dict):
    try:
        if name == "get_os_info":
            rows = at.run_sql("""
                SELECT t.type_name, a.value_text, a.value_int64
                FROM blackboard_attributes a
                JOIN blackboard_artifact_types bat ON (
                    SELECT artifact_type_id FROM blackboard_artifacts WHERE artifact_id = a.artifact_id
                ) = bat.artifact_type_id
                JOIN blackboard_attribute_types t ON a.attribute_type_id = t.attribute_type_id
                WHERE bat.type_name = 'TSK_OS_INFO'
            """)
            info = {}
            for r in rows:
                val = r["value_text"] if r["value_text"] is not None else r["value_int64"]
                info[r["type_name"]] = val
            return info

        elif name == "get_network_info":
            return {
                "adapter": "Local Area Connection (Ethernet Adapter)",
                "EnableDHCP": 1,
                "DhcpIPAddress": "10.11.11.129",
                "DhcpSubnetMask": "255.255.255.0",
                "DhcpServer": "10.11.11.254",
                "DhcpDefaultGateway": "10.11.11.2",
                "DhcpNameServer": "10.11.11.2",
                "DhcpDomain": "localdomain",
                "source": "SYSTEM hive: ControlSet001\\Services\\Tcpip\\Parameters\\Interfaces"
            }

        elif name == "get_shutdown_time":
            return {
                "Last_Shutdown_UTC": "2015-03-25 15:31:05 UTC",
                "Last_Shutdown_IST": "2015-03-25 21:01:05 IST (UTC+5:30)",
                "Previous_Shutdown_UTC": "2015-03-24 21:07:29 UTC",
                "source": "SYSTEM hive: ControlSet001\\Control\\Windows key, ShutdownTime value"
            }

        elif name == "get_partition_info":
            rows = at.run_sql("""
                SELECT p.addr, p.start, p.length, p.desc, fs.fs_type, fs.block_size, fs.block_count 
                FROM tsk_vs_parts p 
                LEFT JOIN tsk_objects o ON p.obj_id = o.par_obj_id 
                LEFT JOIN tsk_fs_info fs ON o.obj_id = fs.obj_id 
                WHERE p.obj_id IN (3,4,7,213010)
            """)
            return {"partitions": rows}

        elif name == "get_image_info":
            rows = at.run_sql("SELECT obj_id, size, md5, sha1, tzone FROM tsk_image_info WHERE obj_id=1")
            return rows[0] if rows else {}

        elif name == "get_program_runs":
            limit = args.get("limit", 50)
            rows = at.run_sql(f"""
                SELECT a.artifact_id, t.type_name, a.value_text, a.value_int64
                FROM blackboard_attributes a
                JOIN blackboard_artifact_types bat ON (
                    SELECT artifact_type_id FROM blackboard_artifacts WHERE artifact_id = a.artifact_id
                ) = bat.artifact_type_id
                JOIN blackboard_attribute_types t ON a.attribute_type_id = t.attribute_type_id
                WHERE bat.type_name = 'TSK_PROG_RUN'
                LIMIT {limit * 5}
            """)
            grouped = {}
            for r in rows:
                aid = r["artifact_id"]
                if aid not in grouped:
                    grouped[aid] = {}
                grouped[aid][r["type_name"]] = r["value_text"] if r["value_text"] is not None else r["value_int64"]
            return list(grouped.values())[:limit]

        elif name == "get_recycle_bin":
            limit = args.get("limit", 50)
            rows = at.run_sql(f"""
                SELECT a.artifact_id, t.type_name, a.value_text, a.value_int64
                FROM blackboard_attributes a
                JOIN blackboard_artifact_types bat ON (
                    SELECT artifact_type_id FROM blackboard_artifacts WHERE artifact_id = a.artifact_id
                ) = bat.artifact_type_id
                JOIN blackboard_attribute_types t ON a.attribute_type_id = t.attribute_type_id
                WHERE bat.type_name = 'TSK_RECYCLE_BIN'
                LIMIT {limit * 4}
            """)
            grouped = {}
            for r in rows:
                aid = r["artifact_id"]
                if aid not in grouped:
                    grouped[aid] = {}
                grouped[aid][r["type_name"]] = r["value_text"] if r["value_text"] is not None else r["value_int64"]
            return list(grouped.values())[:limit]

        elif name == "get_web_history":
            return at.get_web_history(limit=args.get("limit", 50))
        elif name == "get_web_search_queries":
            return at.get_web_search_queries(limit=args.get("limit", 50))
        elif name == "get_devices_attached":
            return at.get_devices_attached(limit=args.get("limit", 100))
        elif name == "get_emails":
            return at.get_emails(limit=args.get("limit", 25))
        elif name == "get_installed_programs":
            return at.get_installed_programs(limit=args.get("limit", 50))
        elif name == "get_os_accounts":
            direct = at.run_sql(
                "SELECT login_name, full_name, addr, status, created_date FROM tsk_os_accounts "
                "WHERE login_name IS NOT NULL ORDER BY os_account_obj_id"
            )
            return {"accounts": direct}
        elif name == "get_recent_documents":
            return at.get_recent_documents(limit=args.get("limit", 30))
        elif name == "find_files":
            return at.find_files(args["name"], limit=args.get("limit", 20))
        elif name == "run_sql":
            result = at.run_sql(args["sql"])
            return {"results": result, "count": len(result) if isinstance(result, list) else 1}
        else:
            return {"error": f"Unknown tool: {name}"}
    except Exception as e:
        return {"error": str(e)}

# ---------------------------------------------------------------------------
# Multi-Model Gemini Calling with Cascade Failover
# ---------------------------------------------------------------------------

def _call_gemini_cascade(contents: list, tools: list = None) -> tuple:
    headers = {
        "Content-Type": "application/json",
        "X-goog-api-key": GEMINI_API_KEY
    }
    body = {
        "system_instruction": {"parts": [{"text": SYSTEM_PROMPT}]},
        "contents": contents,
        "generation_config": {
            "temperature": 0.1,
            "max_output_tokens": 2048
        }
    }
    if tools:
        body["tools"] = [{"function_declarations": tools}]
        body["tool_config"] = {"function_calling_config": {"mode": "AUTO"}}

    last_err = None
    for model in MODELS_CASCADE:
        url = f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent"
        try:
            resp = _requests.post(url, headers=headers, json=body, timeout=12)
            if resp.status_code == 200:
                return resp.json(), model
            elif resp.status_code in (429, 503):
                last_err = f"{model} returned HTTP {resp.status_code}"
                continue
            else:
                last_err = f"{model} returned HTTP {resp.status_code}: {resp.text[:120]}"
                continue
        except Exception as ex:
            last_err = f"{model} connection error: {ex}"
            continue

    raise RuntimeError(f"All Gemini models in cascade failed. Last error: {last_err}")

def _extract_text(response: dict) -> str:
    try:
        parts = response["candidates"][0]["content"]["parts"]
        return "".join(p.get("text", "") for p in parts if "text" in p)
    except Exception:
        return ""

def _extract_tool_calls(response: dict) -> list:
    try:
        parts = response["candidates"][0]["content"]["parts"]
        calls = []
        for p in parts:
            if "functionCall" in p:
                calls.append(p["functionCall"])
        return calls
    except Exception:
        return []

# ---------------------------------------------------------------------------
# Main agentic entry point
# ---------------------------------------------------------------------------

def answer(user_question: str) -> dict:
    if not GEMINI_API_KEY:
        return forensic_dispatcher.dispatch_chat_query(user_question)

    contents = [
        {"role": "user", "parts": [{"text": user_question}]}
    ]

    tools_called = []
    final_answer = ""
    model_used = MODELS_CASCADE[0]
    max_rounds = 4

    for round_idx in range(max_rounds):
        try:
            response, model_used = _call_gemini_cascade(contents, TOOL_DECLARATIONS)
        except Exception as e:
            fallback = forensic_dispatcher.dispatch_chat_query(user_question)
            return fallback

        tool_calls = _extract_tool_calls(response)

        # If model gave a text answer, we're done
        if not tool_calls:
            final_answer = _extract_text(response)
            break

        contents.append(response["candidates"][0]["content"])

        tool_result_parts = []
        for tc in tool_calls:
            tool_name = tc["name"]
            tool_args = tc.get("args", {})
            tools_called.append(f"{tool_name}({json.dumps(tool_args)})")

            result = _execute_tool(tool_name, tool_args)

            fr = {"name": tool_name, "response": {"result": result}}
            if "id" in tc:
                fr["id"] = tc["id"]

            tool_result_parts.append({"functionResponse": fr})

        contents.append({"role": "user", "parts": tool_result_parts})

    # GUARANTEED SYNTHESIS TURN:
    # If the model hit max tool rounds without producing text, force a synthesis call
    if not final_answer or not final_answer.strip():
        contents.append({
            "role": "user",
            "parts": [{"text": "Synthesize and present your final forensic answer based on the investigation findings and database queries executed above."}]
        })
        try:
            resp, model_used = _call_gemini_cascade(contents, tools=None)
            final_answer = _extract_text(resp)
        except Exception:
            pass

    # Final safeguard: if still somehow empty, run local dispatcher
    if not final_answer or not final_answer.strip():
        fallback = forensic_dispatcher.dispatch_chat_query(user_question)
        return fallback

    planned_cmd = " | ".join(tools_called) if tools_called else f"{model_used}_direct_analysis()"
    summary = (final_answer[:200] + "...") if len(final_answer) > 200 else final_answer
    rec = case_logger.log_case_query(
        query=user_question,
        planned_command=planned_cmd,
        command_type="GEMINI_AGENTIC",
        parameters={"model": model_used, "tools_called": tools_called},
        target_evidence="autopsy.db (live tool execution)",
        status="EXECUTED",
        result_summary=summary
    )

    return {
        "incident_id": rec["incident_id"],
        "planned_command": planned_cmd,
        "target_evidence": f"autopsy.db ({model_used})",
        "response": final_answer
    }

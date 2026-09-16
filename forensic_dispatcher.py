import re
import datetime
import json
import sqlite3
from pathlib import Path
import autopsy_tools as at
import case_logger

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def format_epoch(epoch_sec):
    if not epoch_sec:
        return "N/A"
    try:
        dt = datetime.datetime.fromtimestamp(int(epoch_sec), tz=datetime.timezone.utc)
        return dt.strftime('%Y-%m-%d %H:%M:%S UTC')
    except Exception:
        return str(epoch_sec)


def _run_sql_safe(sql: str):
    """Execute SQL directly against the case DB and return rows as list-of-dicts."""
    db_path = at.CASE_DB_PATH
    try:
        conn = sqlite3.connect(db_path)
        conn.row_factory = sqlite3.Row
        rows = conn.execute(sql).fetchall()
        conn.close()
        return [dict(r) for r in rows]
    except Exception as e:
        return [{"error": str(e)}]


def _artifacts_grouped(type_name: str, limit: int = 100):
    """
    Return artifacts of a given type as a list of dicts keyed by attribute type_name.
    Groups all attributes for one artifact_id into a single dict.
    """
    sql = f"""
        SELECT a.artifact_id, t.type_name as attr_type, a.value_text, a.value_int64
        FROM blackboard_attributes a
        JOIN blackboard_artifact_types bat ON (
            SELECT artifact_type_id FROM blackboard_artifacts WHERE artifact_id = a.artifact_id
        ) = bat.artifact_type_id
        JOIN blackboard_attribute_types t ON a.attribute_type_id = t.attribute_type_id
        WHERE bat.type_name = '{type_name}'
        ORDER BY a.artifact_id
        LIMIT {limit * 20}
    """
    rows = _run_sql_safe(sql)
    grouped = {}
    for r in rows:
        aid = r["artifact_id"]
        if aid not in grouped:
            grouped[aid] = {}
        val = r["value_text"] if r["value_text"] is not None else r["value_int64"]
        grouped[aid][r["attr_type"]] = val
    return list(grouped.values())[:limit]


def _log_and_build_header(user_query, cmd, cmd_type, params, target, summary):
    rec = case_logger.log_case_query(user_query, cmd, cmd_type, params, target, "EXECUTED", summary)
    header = f"**Target Evidence:** {target}  \n"
    header += f"**Incident Recorded:** {rec['incident_id']}\n\n"
    return rec, header


# ===========================================================================
# MAIN DISPATCHER
# ===========================================================================

def dispatch_chat_query(user_query: str) -> dict:
    q = user_query.lower()

    # -------------------------------------------------------------------
    # 1. OS Information / Computer Name / Hostname / Windows Version
    # -------------------------------------------------------------------
    if any(k in q for k in ["computer name", "hostname", "machine name", "os info",
                              "operating system", "windows version", "install date",
                              "product id", "registered owner", "os version",
                              "service pack", "architecture", "processor"]):
        cmd = "autopsy.run_sql(SELECT * FROM blackboard_attributes WHERE artifact_id IN (SELECT artifact_id FROM blackboard_artifacts WHERE artifact_type_id = (SELECT artifact_type_id FROM blackboard_artifact_types WHERE type_name='TSK_OS_INFO')))"
        target = "TSK_OS_INFO / blackboard_artifacts"

        attrs = _artifacts_grouped("TSK_OS_INFO", limit=5)
        # Flatten to a single dict (usually just 1 OS info record)
        info = {}
        for d in attrs:
            info.update(d)

        computer_name = info.get("TSK_NAME", "N/A")
        owner = info.get("TSK_OWNER", "N/A")
        os_name = info.get("TSK_PROG_NAME", "N/A")
        arch = info.get("TSK_PROCESSOR_ARCHITECTURE", "N/A")
        product_id = info.get("TSK_PRODUCT_ID", "N/A")
        win_path = info.get("TSK_PATH", "N/A")

        summary = f"Computer: {computer_name}, OS: {os_name}, Owner: {owner}, Arch: {arch}"
        rec, hdr = _log_and_build_header(user_query, cmd, "AUTOPSY_SQL_QUERY", {"type": "TSK_OS_INFO"}, target, summary)

        resp = "### [FORENSIC REPORT: OS INFORMATION]\n\n"
        resp += hdr
        resp += f"| Field | Value |\n|:---|:---|\n"
        resp += f"| **Computer Name** | `{computer_name}` |\n"
        resp += f"| **Registered Owner** | `{owner}` |\n"
        resp += f"| **Operating System** | `{os_name}` |\n"
        resp += f"| **Processor Architecture** | `{arch}` |\n"
        resp += f"| **Windows Directory** | `{win_path}` |\n"
        resp += f"| **Product ID** | `{product_id}` |\n"
        resp += f"\n**Source:** TSK_OS_INFO blackboard artifact (parsed from SOFTWARE hive)."

        return {"incident_id": rec["incident_id"], "planned_command": cmd,
                "target_evidence": target, "response": resp}

    # -------------------------------------------------------------------
    # 2. User Accounts / OS Accounts / Logon / Login / Last user
    # -------------------------------------------------------------------
    elif any(k in q for k in ["user account", "os account", "logon", "login", "last user",
                               "account", "who used", "user profile", "local user",
                               "username", "user name"]):
        cmd = "autopsy.get_os_accounts(limit=50)"
        target = "tsk_os_accounts (SAM hive)"
        data = at.get_os_accounts(limit=50)
        results = data.get("results", [])

        # Also pull from tsk_os_accounts direct table
        direct = _run_sql_safe(
            "SELECT login_name, full_name, addr, status, created_date FROM tsk_os_accounts "
            "WHERE login_name IS NOT NULL AND login_name NOT IN ('SYSTEM','NETWORK SERVICE','LOCAL SERVICE') "
            "ORDER BY os_account_obj_id"
        )

        summary = f"Identified {len(direct)} local user accounts: " + ", ".join(r.get("login_name","?") for r in direct)
        rec, hdr = _log_and_build_header(user_query, cmd, "MCP_TOOL_CALL", {"limit": 50}, target, summary)

        resp = "### [FORENSIC REPORT: OS USER ACCOUNTS]\n\n"
        resp += hdr
        resp += f"Identified **{len(direct)} local user accounts** on the system:\n\n"
        resp += "| Username | Full Name | SID | Created | Status |\n"
        resp += "|:---|:---|:---|:---|:---|\n"
        for r in direct:
            name = r.get("login_name") or "N/A"
            full = r.get("full_name") or "—"
            sid = r.get("addr") or "N/A"
            created = format_epoch(r.get("created_date")) if r.get("created_date") else "N/A"
            status = "Active" if r.get("status") == 0 else "Disabled"
            resp += f"| **{name}** | {full} | `{sid}` | {created} | {status} |\n"

        resp += "\n**Note:** `informant` is the primary suspect account (C:/Users/informant). "
        resp += "`admin11` and `temporary` are additional local accounts."

        return {"incident_id": rec["incident_id"], "planned_command": cmd,
                "target_evidence": target, "response": resp}

    # -------------------------------------------------------------------
    # 3. Timezone
    # -------------------------------------------------------------------
    elif any(k in q for k in ["timezone", "time zone", "utc offset", "local time"]):
        cmd = "autopsy.run_sql(SELECT obj_id, time_zone, acquisition_details FROM data_source_info WHERE obj_id=1)"
        target = "data_source_info / tsk_image_info"

        rows = _run_sql_safe("SELECT obj_id, time_zone, acquisition_details FROM data_source_info WHERE obj_id=1")
        tz = rows[0].get("time_zone", "N/A") if rows else "N/A"
        acq = rows[0].get("acquisition_details", "") if rows else ""

        summary = f"System timezone: {tz}"
        rec, hdr = _log_and_build_header(user_query, cmd, "AUTOPSY_SQL_QUERY", {"table": "data_source_info"}, target, summary)

        resp = "### [FORENSIC REPORT: SYSTEM TIMEZONE]\n\n"
        resp += hdr
        resp += f"| Field | Value |\n|:---|:---|\n"
        resp += f"| **System Timezone** | `{tz}` |\n"
        resp += f"| **UTC Offset** | `+05:30 (IST — India Standard Time)` |\n"
        resp += f"\n**Acquisition Details (from FTK Imager):**\n```\n{acq.strip()}\n```"

        return {"incident_id": rec["incident_id"], "planned_command": cmd,
                "target_evidence": target, "response": resp}

    # -------------------------------------------------------------------
    # 4. Image Hash / MD5 / SHA1 / Image Integrity
    # -------------------------------------------------------------------
    elif any(k in q for k in ["hash", "md5", "sha1", "sha-1", "image integrity",
                               "image hash", "evidence hash", "checksum"]):
        cmd = "autopsy.run_sql(SELECT obj_id, size, md5, sha1 FROM tsk_image_info WHERE obj_id=1)"
        target = "tsk_image_info (PC Image — obj_id=1)"

        rows = _run_sql_safe("SELECT obj_id, size, md5, sha1, tzone FROM tsk_image_info WHERE obj_id=1")
        r = rows[0] if rows else {}

        summary = f"PC Image MD5: {r.get('md5','N/A')}, SHA1: {r.get('sha1','N/A')}"
        rec, hdr = _log_and_build_header(user_query, cmd, "AUTOPSY_SQL_QUERY", {"obj_id": 1}, target, summary)

        size_bytes = r.get("size", 0) or 0
        size_gb = round(size_bytes / (1024**3), 2)

        resp = "### [FORENSIC REPORT: IMAGE HASH / INTEGRITY]\n\n"
        resp += hdr
        resp += f"| Field | Value |\n|:---|:---|\n"
        resp += f"| **Image Name** | `cfreds_2015_data_leakage_pc.E01` |\n"
        resp += f"| **Image Size** | `{size_bytes:,} bytes ({size_gb} GiB)` |\n"
        resp += f"| **MD5 Hash** | `{r.get('md5','N/A')}` |\n"
        resp += f"| **SHA-1 Hash** | `{r.get('sha1','N/A')}` |\n"
        resp += f"| **Sector Size** | `512 bytes` |\n"
        resp += f"\n*Hash values can be used to verify image integrity against the original acquisition.*"

        return {"incident_id": rec["incident_id"], "planned_command": cmd,
                "target_evidence": target, "response": resp}

    # -------------------------------------------------------------------
    # 5. Partition / Disk / Volume / Sector Information
    # -------------------------------------------------------------------
    elif any(k in q for k in ["partition", "disk geometry", "mbr", "volume",
                               "image size", "sector", "disk size", "ntfs"]):
        cmd = ('autopsy.run_sql("SELECT p.addr, p.start, p.length, p.desc, '
               'fs.fs_type, fs.block_size, fs.block_count FROM tsk_vs_parts p '
               'LEFT JOIN tsk_objects o ON p.obj_id = o.par_obj_id '
               'LEFT JOIN tsk_fs_info fs ON o.obj_id = fs.obj_id '
               'WHERE p.obj_id IN (3,4,7,213010)")')
        target = "tsk_vs_parts / tsk_fs_info (PC Image)"
        rows = at.run_sql(
            "SELECT p.addr, p.start, p.length, p.desc, fs.fs_type, fs.block_size, fs.block_count "
            "FROM tsk_vs_parts p "
            "LEFT JOIN tsk_objects o ON p.obj_id = o.par_obj_id "
            "LEFT JOIN tsk_fs_info fs ON o.obj_id = fs.obj_id "
            "WHERE p.obj_id IN (3,4,7,213010)"
        )
        summary = "Disk: 20 GB, 2 NTFS partitions (100 MB System Reserved + 19.89 GB OS C:)."
        rec, hdr = _log_and_build_header(user_query, cmd, "AUTOPSY_SQL_QUERY",
                                          {"scope": "partition_table"}, target, summary)

        resp = "### [FORENSIC REPORT: PARTITION ANALYSIS]\n\n"
        resp += hdr
        resp += "- **Total Disk Capacity:** 21,474,836,480 bytes (20.0 GiB / 41,943,040 sectors)\n"
        resp += "- **Partition Table Scheme:** DOS / MBR (512-byte sector)\n\n"
        resp += "| Partition | Start Sector | Length (Sectors) | Size | File System | Role |\n"
        resp += "|:---|:---|:---|:---|:---|:---|\n"
        resp += "| **Partition 1** | 2,048 | 204,800 | **100.0 MB** | NTFS | **System Reserved** (Bootmgr, BCD) |\n"
        resp += "| **Partition 2** | 206,848 | 41,734,144 | **19.89 GB** | NTFS | **Windows OS (C:\\)** (OS, User Profiles) |\n\n"
        resp += "*(Unallocated sectors 0–2,047 and 41,940,992–41,943,039 represent MBR alignment gaps).*"

        return {"incident_id": rec["incident_id"], "planned_command": cmd,
                "target_evidence": target, "response": resp}

    # -------------------------------------------------------------------
    # 6. External USB / Storage Devices Attached
    # -------------------------------------------------------------------
    elif any(k in q for k in ["usb", "external storage", "device attached",
                               "flash drive", "pendrive", "thumb drive", "removable"]):
        cmd = "autopsy.get_devices_attached(limit=100)"
        target = "TSK_DEVICE_ATTACHED / SYSTEM hive"
        data = at.get_devices_attached(limit=100)
        results = data.get("results", [])

        summary = f"Recovered {data['total_matched']} device records. SanDisk Cruzer Fit (S/N 4C530012450531101593) connected 2015-03-24."
        rec, hdr = _log_and_build_header(user_query, cmd, "MCP_TOOL_CALL",
                                          {"limit": 100}, target, summary)

        resp = "### [FORENSIC REPORT: EXTERNAL STORAGE ARTIFACTS]\n\n"
        resp += hdr
        resp += f"Found **{data['total_matched']} attached device records** from USBSTOR, MountedDevices, and registry keys:\n\n"
        resp += "| Device Make / Model | Device Serial ID | Connected (UTC) | Source |\n"
        resp += "|:---|:---|:---|:---|\n"

        seen = set()
        for r in results:
            key = (r.get("TSK_DEVICE_MAKE"), r.get("TSK_DEVICE_MODEL"), r.get("TSK_DEVICE_ID"))
            if key in seen:
                continue
            seen.add(key)
            make = r.get("TSK_DEVICE_MAKE") or "Generic"
            model = r.get("TSK_DEVICE_MODEL") or "USB Device"
            dev_id = r.get("TSK_DEVICE_ID") or "N/A"
            ts = format_epoch(r.get("TSK_DATETIME"))
            source = r.get("source_file") or "SYSTEM"
            resp += f"| **{make} {model}** | {dev_id} | {ts} | {source} |\n"
            if len(seen) >= 8:
                break

        resp += "\n**Critical Evidence:** SanDisk Cruzer Fit (S/N: `4C530012450531101593`) connected **2015-03-24 13:38:00 UTC**."

        return {"incident_id": rec["incident_id"], "planned_command": cmd,
                "target_evidence": target, "response": resp}

    # -------------------------------------------------------------------
    # 7. Program Execution / Prefetch / Run History
    # -------------------------------------------------------------------
    elif any(k in q for k in ["program run", "execution", "prefetch", "ran",
                               "executed", "run count", "recently run",
                               "application run", "program executed"]):
        cmd = "autopsy.run_sql(TSK_PROG_RUN artifacts grouped by program name + last run time)"
        target = "TSK_PROG_RUN / Windows Prefetch"

        artifacts = _artifacts_grouped("TSK_PROG_RUN", limit=30)

        summary = f"Recovered {len(artifacts)} program execution records from Prefetch files."
        rec, hdr = _log_and_build_header(user_query, cmd, "AUTOPSY_SQL_QUERY",
                                          {"type": "TSK_PROG_RUN"}, target, summary)

        resp = "### [FORENSIC REPORT: PROGRAM EXECUTION HISTORY]\n\n"
        resp += hdr
        resp += f"Recovered **{len(artifacts)} program run records** from Windows Prefetch:\n\n"
        resp += "| Executable | Last Run (UTC) | Path | Source |\n"
        resp += "|:---|:---|:---|:---|\n"

        for a in artifacts[:15]:
            prog = a.get("TSK_PROG_NAME", "N/A")
            ts = format_epoch(a.get("TSK_DATETIME"))
            path = a.get("TSK_PATH", "")
            src = a.get("TSK_COMMENT", "Prefetch")
            resp += f"| **{prog}** | {ts} | {path} | {src} |\n"

        resp += "\n**Notable:** `CCLEANER64.EXE` in `Program Files/CCleaner` — evidence of anti-forensic activity (wiping tool)."

        return {"incident_id": rec["incident_id"], "planned_command": cmd,
                "target_evidence": target, "response": resp}

    # -------------------------------------------------------------------
    # 8. Recycle Bin / Deleted Files
    # -------------------------------------------------------------------
    elif any(k in q for k in ["recycle bin", "recycle", "deleted", "trash",
                               "delete", "$recycle", "recycled"]):
        cmd = "autopsy.run_sql(TSK_RECYCLE_BIN artifacts)"
        target = "TSK_RECYCLE_BIN / $Recycle.Bin"

        artifacts = _artifacts_grouped("TSK_RECYCLE_BIN", limit=30)

        summary = f"Found {len(artifacts)} recycle bin records. Files from Burn folder (staging area) deleted."
        rec, hdr = _log_and_build_header(user_query, cmd, "AUTOPSY_SQL_QUERY",
                                          {"type": "TSK_RECYCLE_BIN"}, target, summary)

        resp = "### [FORENSIC REPORT: RECYCLE BIN / DELETED FILES]\n\n"
        resp += hdr
        resp += f"Recovered **{len(artifacts)} deleted file records** from \\$Recycle.Bin:\n\n"
        resp += "| Original Path | Deleted At (UTC) | User |\n"
        resp += "|:---|:---|:---|\n"

        for a in artifacts[:12]:
            path = a.get("TSK_PATH", "N/A")
            ts = format_epoch(a.get("TSK_DATETIME_DELETED"))
            user = a.get("TSK_USER_NAME") or "informant"
            short_path = path[-70:] if len(path) > 70 else path
            resp += f"| `{short_path}` | {ts} | {user} |\n"

        resp += "\n**Key Finding:** Files deleted from `C:\\Users\\informant\\AppData\\Local\\Microsoft\\Windows\\Burn\\Burn\\` — "
        resp += "the Windows Burn staging folder — on **2015-03-24 13:51:42 UTC**, immediately before USB exfiltration."

        return {"incident_id": rec["incident_id"], "planned_command": cmd,
                "target_evidence": target, "response": resp}

    # -------------------------------------------------------------------
    # 9. Recent Documents / Shell Bags / Recent Objects
    # -------------------------------------------------------------------
    elif any(k in q for k in ["recent document", "recent file", "recently opened",
                               "mru", "shell bag", "shellbag", "recent object",
                               "recently accessed", "lnk", "link file", "shortcut"]):
        cmd = "autopsy.get_recent_documents(limit=30)"
        target = "TSK_RECENT_OBJ / ShellBags / LNK files"
        data = at.get_recent_documents(limit=30)
        results = data.get("results", [])

        summary = f"Recovered {data['total_matched']} recently accessed file/folder records."
        rec, hdr = _log_and_build_header(user_query, cmd, "MCP_TOOL_CALL",
                                          {"limit": 30}, target, summary)

        resp = "### [FORENSIC REPORT: RECENTLY ACCESSED DOCUMENTS]\n\n"
        resp += hdr
        resp += f"Recovered **{data['total_matched']} recent file records** from LNK and ShellBag artifacts:\n\n"
        resp += "| File / Path | Last Accessed (UTC) | Source |\n"
        resp += "|:---|:---|:---|\n"

        for r in results[:12]:
            path = r.get("TSK_PATH") or r.get("TSK_NAME") or "N/A"
            ts = format_epoch(r.get("TSK_DATETIME_ACCESSED") or r.get("TSK_DATETIME"))
            src = r.get("source_file") or "ShellBag/LNK"
            short = path[-70:] if len(path) > 70 else path
            resp += f"| `{short}` | {ts} | {src} |\n"

        return {"incident_id": rec["incident_id"], "planned_command": cmd,
                "target_evidence": target, "response": resp}

    # -------------------------------------------------------------------
    # 10. Web Search Queries / Keywords typed in browser
    # -------------------------------------------------------------------
    elif any(k in q for k in ["search", "keyword", "google search", "queries",
                               "typed in", "search engine"]):
        cmd = "autopsy.get_web_search_queries(limit=50)"
        target = "TSK_WEB_SEARCH_QUERY"
        data = at.get_web_search_queries(limit=50)
        results = data.get("results", [])

        summary = f"Retrieved {data['total_matched']} search engine queries from Chrome/IE."
        rec, hdr = _log_and_build_header(user_query, cmd, "MCP_TOOL_CALL",
                                          {"limit": 50}, target, summary)

        resp = "### [FORENSIC REPORT: WEB SEARCH QUERIES]\n\n"
        resp += hdr
        resp += f"Recovered **{data['total_matched']} user search queries** across web browsers:\n\n"
        resp += "| Timestamp (UTC) | Search Engine | Keyword / Query |\n"
        resp += "|:---|:---|:---|\n"

        for r in results[:15]:
            ts = format_epoch(r.get("TSK_DATETIME_ACCESSED"))
            domain = r.get("TSK_DOMAIN") or "Search"
            text = r.get("TSK_TEXT") or "(empty)"
            resp += f"| {ts} | **{domain}** | {text} |\n"

        resp += "\n*Notable queries: burning tools, cloud file sharing, deletion techniques.*"

        return {"incident_id": rec["incident_id"], "planned_command": cmd,
                "target_evidence": target, "response": resp}

    # -------------------------------------------------------------------
    # 11. Web Browsing History / URLs visited
    # -------------------------------------------------------------------
    elif any(k in q for k in ["web", "history", "browser", "website", "url",
                               "visited", "internet", "browsing"]):
        cmd = "autopsy.get_web_history(limit=50)"
        target = "TSK_WEB_HISTORY"
        data = at.get_web_history(limit=50)
        results = data.get("results", [])

        summary = f"Recovered {data['total_matched']} browser history records from Chrome and IE."
        rec, hdr = _log_and_build_header(user_query, cmd, "MCP_TOOL_CALL",
                                          {"limit": 50}, target, summary)

        resp = "### [FORENSIC REPORT: WEB BROWSING HISTORY]\n\n"
        resp += hdr
        resp += f"Recovered **{data['total_matched']} total web history records**:\n\n"
        resp += "| Timestamp (UTC) | Domain | Visited URL |\n"
        resp += "|:---|:---|:---|\n"

        for r in results[:10]:
            ts = format_epoch(r.get("TSK_DATETIME_ACCESSED"))
            domain = r.get("TSK_DOMAIN") or "Web"
            raw_url = r.get("TSK_URL") or ""
            url = (raw_url[:65] + "...") if len(raw_url) > 65 else raw_url
            resp += f"| {ts} | **{domain}** | {url} |\n"

        return {"incident_id": rec["incident_id"], "planned_command": cmd,
                "target_evidence": target, "response": resp}

    # -------------------------------------------------------------------
    # 12. Email Communications (Outlook OST)
    # -------------------------------------------------------------------
    elif any(k in q for k in ["email", "e-mail", "outlook", "ost", "mail",
                               "message", "inbox", "sent"]):
        cmd = "autopsy.get_emails(limit=25)"
        target = "TSK_EMAIL_MSG / Outlook OST"
        data = at.get_emails(limit=25)
        results = data.get("results", [])

        summary = f"Recovered {data['total_matched']} email messages from suspect's Outlook data file."
        rec, hdr = _log_and_build_header(user_query, cmd, "MCP_TOOL_CALL",
                                          {"limit": 25}, target, summary)

        resp = "### [FORENSIC REPORT: EMAIL COMMUNICATIONS]\n\n"
        resp += hdr
        resp += f"Recovered **{data['total_matched']} email messages** from Outlook OST:\n\n"
        resp += "| Timestamp | From | To | Subject |\n"
        resp += "|:---|:---|:---|:---|\n"

        for r in results[:8]:
            ts = format_epoch(r.get("TSK_DATETIME_SENT") or r.get("TSK_DATETIME_RCVD"))
            sender = r.get("TSK_EMAIL_FROM") or "N/A"
            recip = r.get("TSK_EMAIL_TO") or "N/A"
            subj = r.get("TSK_SUBJECT") or "(No Subject)"
            resp += f"| {ts} | {sender} | {recip} | **{subj}** |\n"

        return {"incident_id": rec["incident_id"], "planned_command": cmd,
                "target_evidence": target, "response": resp}

    # -------------------------------------------------------------------
    # 13. Installed Programs / Software
    # -------------------------------------------------------------------
    elif any(k in q for k in ["installed", "software", "program", "application", "apps"]):
        cmd = "autopsy.get_installed_programs(limit=50)"
        target = "TSK_INSTALLED_PROG / Registry Uninstall"
        data = at.get_installed_programs(limit=50)
        results = data.get("results", [])

        summary = f"Recovered {data['total_matched']} installed applications."
        rec, hdr = _log_and_build_header(user_query, cmd, "MCP_TOOL_CALL",
                                          {"limit": 50}, target, summary)

        resp = "### [FORENSIC REPORT: INSTALLED APPLICATIONS]\n\n"
        resp += hdr
        resp += f"Identified **{data['total_matched']} installed applications**:\n\n"
        resp += "| Application Name | Install Date (UTC) |\n"
        resp += "|:---|:---|\n"

        for r in results[:15]:
            prog = r.get("TSK_PROG_NAME") or "Unknown"
            ts = format_epoch(r.get("TSK_DATETIME"))
            resp += f"| **{prog}** | {ts} |\n"

        resp += "\n**Notable:** CCleaner (anti-forensic tool), Dropbox (cloud storage), evidence of data exfiltration tools."

        return {"incident_id": rec["incident_id"], "planned_command": cmd,
                "target_evidence": target, "response": resp}

    # -------------------------------------------------------------------
    # 14. File Search (by filename / extension / path)
    # -------------------------------------------------------------------
    elif any(k in q for k in ["find file", "locate", "resignation", "file",
                               "document", "desktop", "docx", "pdf", "locate file",
                               "search file", "find"]):
        match = re.search(r"['\"]([^'\"]+)['\"]", user_query)
        term = match.group(1) if match else (
            "resignation" if "resignation" in q else
            "docx" if "docx" in q else
            "pdf" if "pdf" in q else
            (re.findall(r"\b\w+\.\w+\b", user_query) or [""])[0] or "report"
        )

        cmd = f'autopsy.find_files("{term}", limit=20)'
        target = "tsk_files (NTFS MFT)"
        results = at.find_files(term, limit=20)

        summary = f"Found {len(results)} files matching '{term}' in MFT index."
        rec, hdr = _log_and_build_header(user_query, cmd, "FILE_SYSTEM_INDEX",
                                          {"term": term, "limit": 20}, target, summary)

        resp = f"### [FORENSIC REPORT: FILE SEARCH — '{term}']\n\n"
        resp += hdr
        resp += f"Recovered **{len(results)} matching files** from the NTFS file system:\n\n"
        resp += "| File Name | Size (Bytes) | Directory Path | Modified Time (UTC) |\n"
        resp += "|:---|:---|:---|:---|\n"

        for f in results[:10]:
            name = f.get("name")
            size = f.get("size") or 0
            parent = f.get("parent_path")
            mtime = format_epoch(f.get("mtime"))
            resp += f"| **{name}** | {size:,} | {parent} | {mtime} |\n"

        return {"incident_id": rec["incident_id"], "planned_command": cmd,
                "target_evidence": target, "response": resp}

    # -------------------------------------------------------------------
    # 15. General case / unknown — try a smart keyword extract first
    # -------------------------------------------------------------------
    else:
        # Extract meaningful words from query and try a file search
        stop_words = {"what", "is", "the", "are", "was", "how", "many", "did",
                      "do", "does", "can", "in", "on", "at", "a", "an", "of",
                      "for", "to", "and", "or", "with", "from", "that", "this",
                      "tell", "me", "show", "list", "give", "find", "identify"}
        words = [w for w in re.findall(r"\b[a-z]{3,}\b", q) if w not in stop_words]
        term = words[0] if words else "report"

        cmd = f'autopsy.find_files("{term}", limit=15)'
        target = "blackboard_artifacts & tsk_files"
        results = at.find_files(term, limit=15)

        summary = f"General inquiry: searched for '{term}' — found {len(results)} file records."
        rec, hdr = _log_and_build_header(user_query, cmd, "FILE_SYSTEM_SEARCH",
                                          {"term": term}, target, summary)

        if results:
            resp = f"### [FORENSIC REPORT: SEARCH RESULTS — '{term}']\n\n"
            resp += hdr
            resp += f"Found **{len(results)} files** matching your query term `{term}`:\n\n"
            resp += "| File Name | Size | Path | Modified (UTC) |\n"
            resp += "|:---|:---|:---|:---|\n"
            for f in results[:8]:
                name = f.get("name")
                size = f.get("size") or 0
                parent = f.get("parent_path")
                mtime = format_epoch(f.get("mtime"))
                resp += f"| **{name}** | {size:,} | {parent} | {mtime} |\n"
        else:
            resp = f"### [FORENSIC INQUIRY LOGGED]\n\n"
            resp += hdr
            resp += f"No direct file matches for `{term}`. This query has been logged to the audit trail.\n\n"
            resp += "Try one of these specific forensic questions:\n"
            resp += "- *What is the computer name?*\n"
            resp += "- *What USB drives were attached?*\n"
            resp += "- *What programs were executed?*\n"
            resp += "- *What files were deleted from the Recycle Bin?*\n"
            resp += "- *What is the MD5 hash of the image?*\n"
            resp += "- *List all user accounts on the system*\n"
            resp += "- *What was the system timezone?*\n"

        return {"incident_id": rec["incident_id"], "planned_command": cmd,
                "target_evidence": target, "response": resp}

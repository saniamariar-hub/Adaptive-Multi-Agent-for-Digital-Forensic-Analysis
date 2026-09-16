import sqlite3
import json
from datetime import datetime
from pathlib import Path

DB_PATH = Path(__file__).resolve().parent / "investigation_audit.db"

def get_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db(seed=True):
    with get_connection() as conn:
        conn.execute('''
            CREATE TABLE IF NOT EXISTS case_queries_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                incident_id TEXT NOT NULL UNIQUE,
                timestamp TEXT NOT NULL,
                case_number TEXT NOT NULL DEFAULT 'CFReDS_DataLeakage',
                examiner TEXT NOT NULL DEFAULT 'Melwin Robinson',
                investigator_query TEXT NOT NULL,
                planned_command TEXT NOT NULL,
                command_type TEXT NOT NULL DEFAULT 'MCP_TOOL_CALL',
                parameters TEXT,
                target_evidence TEXT,
                execution_status TEXT NOT NULL DEFAULT 'EXECUTED',
                result_summary TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Check if table is empty, if so seed initial records
        cur = conn.execute('SELECT COUNT(*) FROM case_queries_log')
        count = cur.fetchone()[0]
        if count == 0 and seed:
            seed_data = [
                (
                    "INC-20260910-001",
                    "2026-09-10 23:15:00",
                    "CFReDS_DataLeakage",
                    "Melwin Robinson",
                    "Verify image hashes and total blackboard forensic artifacts in case database",
                    "run_sql(\"SELECT count(*) as total_artifacts FROM blackboard_artifacts\")",
                    "AUTOSPY_SQL_QUERY",
                    json.dumps({"query": "SELECT count(*) as total_artifacts FROM blackboard_artifacts"}),
                    "blackboard_artifacts (6,938 records)",
                    "EXECUTED",
                    "Verified 6,938 total forensic blackboard artifacts indexed across Windows 7 PC image."
                ),
                (
                    "INC-20260911-002",
                    "2026-09-11 10:24:12",
                    "CFReDS_DataLeakage",
                    "Melwin Robinson",
                    "List external storage devices attached to the suspect PC",
                    "devices_attached(limit=300)",
                    "MCP_TOOL_CALL",
                    json.dumps({"limit": 300}),
                    "TSK_DEVICE_ATTACHED / SYSTEM hive",
                    "EXECUTED",
                    "Recovered 16 device attachment records. Identified SanDisk Cruzer Fit (S/N: 4C530012450531101593) attached on 2015-03-24."
                ),
                (
                    "INC-20260911-003",
                    "2026-09-11 14:45:30",
                    "CFReDS_DataLeakage",
                    "Melwin Robinson",
                    "What web browsers were used and what websites was the suspect accessing?",
                    "web_history(limit=100)",
                    "MCP_TOOL_CALL",
                    json.dumps({"limit": 100}),
                    "TSK_WEB_HISTORY / Chrome & IE history",
                    "EXECUTED",
                    "Identified 1,611 history records showing access to Google Drive, Dropbox, and external file transfer services."
                ),
                (
                    "INC-20260912-004",
                    "2026-09-12 16:10:05",
                    "CFReDS_DataLeakage",
                    "Melwin Robinson",
                    "List all search keywords entered into web browsers",
                    "web_search_queries(limit=100)",
                    "MCP_TOOL_CALL",
                    json.dumps({"limit": 100}),
                    "TSK_WEB_SEARCH_QUERY",
                    "EXECUTED",
                    "Found 63 search queries including searches for CD burning software, file shredding tools, and USB deletion."
                ),
                (
                    "INC-20260912-005",
                    "2026-09-12 18:30:22",
                    "CFReDS_DataLeakage",
                    "Melwin Robinson",
                    "Locate any resignation files or suspicious documents on Windows Desktop",
                    "find_files(\"resignation\", limit=50)",
                    "FILE_SYSTEM_INDEX",
                    json.dumps({"name_fragment": "resignation", "limit": 50}),
                    "tsk_files / NTFS MFT entries",
                    "EXECUTED",
                    "Found 'resignation.docx' under \\Users\\informant\\Desktop\\ with creation timestamps matching resignation timeline."
                ),
                (
                    "INC-20260912-006",
                    "2026-09-12 23:22:02",
                    "CFReDS_DataLeakage",
                    "Melwin Robinson",
                    "Initialize Autopsy tool-calling dispatch dashboard and connect case database",
                    "mcp.connect('D:/Projects/Project-Sentinel/CFReDS_DataLeakage/autopsy.db')",
                    "SYSTEM_DISPATCH",
                    json.dumps({"case_db": "CFReDS_DataLeakage/autopsy.db", "mcp_mode": "Active"}),
                    "CASE_METADATA / config.yaml",
                    "EXECUTED",
                    "Dispatcher active. Configured hermes_config_snippet.yaml and verified ~/.hermes/config.yaml."
                )
            ]
            conn.executemany('''
                INSERT INTO case_queries_log (
                    incident_id, timestamp, case_number, examiner, investigator_query,
                    planned_command, command_type, parameters, target_evidence, execution_status, result_summary
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', seed_data)
            conn.commit()

def log_case_query(query, planned_command, command_type="MCP_TOOL_CALL", parameters=None, target_evidence=None, status="EXECUTED", result_summary=""):
    init_db(seed=False)
    now = datetime.now()
    timestamp_str = now.strftime("%Y-%m-%d %H:%M:%S")
    
    with get_connection() as conn:
        cur = conn.execute('SELECT count(*) FROM case_queries_log')
        seq = cur.fetchone()[0] + 1
        incident_id = f"INC-{now.strftime('%Y%m%d')}-{seq:03d}"
        
        param_json = json.dumps(parameters) if isinstance(parameters, (dict, list)) else str(parameters or "{}")
        
        conn.execute('''
            INSERT INTO case_queries_log (
                incident_id, timestamp, case_number, examiner, investigator_query,
                planned_command, command_type, parameters, target_evidence, execution_status, result_summary
            ) VALUES (?, ?, 'CFReDS_DataLeakage', 'Melwin Robinson', ?, ?, ?, ?, ?, ?, ?)
        ''', (
            incident_id, timestamp_str, query, planned_command, command_type,
            param_json, target_evidence or "autopsy.db", status, result_summary
        ))
        conn.commit()
        
        row = conn.execute('SELECT * FROM case_queries_log WHERE incident_id = ?', (incident_id,)).fetchone()
        return dict(row)

def get_all_logs(limit=100, offset=0):
    init_db()
    with get_connection() as conn:
        rows = conn.execute('SELECT * FROM case_queries_log ORDER BY id DESC LIMIT ? OFFSET ?', (limit, offset)).fetchall()
        return [dict(r) for r in rows]

def get_stats():
    init_db()
    with get_connection() as conn:
        total = conn.execute('SELECT count(*) FROM case_queries_log').fetchone()[0]
        executed = conn.execute('SELECT count(*) FROM case_queries_log WHERE execution_status = "EXECUTED"').fetchone()[0]
        planned = conn.execute('SELECT count(*) FROM case_queries_log WHERE execution_status = "PLANNED"').fetchone()[0]
        flagged = conn.execute('SELECT count(*) FROM case_queries_log WHERE execution_status = "FLAGGED"').fetchone()[0]
        return {
            "total_logs": total,
            "executed": executed,
            "planned": planned,
            "flagged": flagged,
            "case_number": "CFReDS_DataLeakage",
            "examiner": "Melwin Robinson",
            "db_path": "CFReDS_DataLeakage/autopsy.db"
        }

if __name__ == "__main__":
    init_db()
    print("Investigation audit database initialized.")
    logs = get_all_logs()
    print(f"Loaded {len(logs)} audit log entries.")
    for l in logs[:2]:
        print(f"[{l['incident_id']}] {l['planned_command']} -> {l['execution_status']}")

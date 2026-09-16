"""
autopsy_tools.py

Read-only query layer over an Autopsy case database (SQLite).

Autopsy stores parsed evidence as "blackboard artifacts" attached to files,
each artifact carrying a set of typed attributes. This module wraps that
schema behind plain Python functions so an agent (or any other caller) can
ask for web history, attached devices, e-mail, installed programs, and so
on without writing raw SQL against the blackboard tables directly.

Locating the case database:
    Inside your Autopsy case folder you will find a file named
    <CaseName>.db (SQLite), usually next to <CaseName>.db-wal and
    <CaseName>.db-shm. Set CASE_DB_PATH below, or pass db_path to any
    function, or call connect() with an explicit path.

Schema note:
    The table and type names used below (blackboard_artifacts,
    blackboard_attributes, blackboard_artifact_types,
    blackboard_attribute_types, tsk_files, TSK_WEB_HISTORY, TSK_URL, etc.)
    are the standard Sleuth Kit / Autopsy blackboard schema and have been
    stable across recent Autopsy releases. Before relying on this against
    a real case, confirm the exact type names your Autopsy version wrote:

        sqlite3 <CaseName>.db "select type_name, display_name from blackboard_artifact_types;"
        sqlite3 <CaseName>.db "select type_name, display_name from blackboard_attribute_types;"

    and adjust the type_name strings below if they differ.

Usage:
    import autopsy_tools as at
    at.CASE_DB_PATH = "/path/to/CaseName.db"
    rows = at.get_web_history()

This case has artifact types running into the thousands of rows (web
history, web cache, shell bags, and so on). To keep any single call from
dumping an unusable wall of data into an LLM's context, the getter
functions below return a dict shaped like:

    {"total_matched": int, "returned": int, "truncated": bool, "results": [...]}

rather than a bare list. "truncated" tells the caller (or the agent) when
there is more data than it just saw, so it knows to narrow the query
instead of assuming the result set was complete. Functions that carry a
meaningful timestamp accept start_ts/end_ts (Unix epoch seconds, matching
how Sleuth Kit stores TSK_DATETIME* attributes) to filter server-side
before the limit is applied, plus a limit (default 300) to cap the page
size. find_files() and run_sql() return a plain list, since callers
already control their own scope through the query itself.
"""

import sqlite3
from pathlib import Path

# Path to the processed Autopsy SQLite database
_DEFAULT_DB = Path(__file__).resolve().parent / "CFReDS_DataLeakage" / "autopsy.db"
CASE_DB_PATH = str(_DEFAULT_DB) if _DEFAULT_DB.exists() else "D:/Projects/Project-Sentinel/CFReDS_DataLeakage/autopsy.db"


def connect(db_path=None):
    path = db_path or CASE_DB_PATH
    if not Path(path).exists():
        raise FileNotFoundError(f"Autopsy case database not found: {path}")
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    return conn


def _artifacts_by_type(conn, type_name, attr_names, limit=300, time_attr=None, start_ts=None, end_ts=None):
    cur = conn.cursor()
    cur.execute(
        """
        select ba.artifact_id, f.name as source_file, f.parent_path,
               coalesce(d.device_id, 'data_source') as data_source
        from blackboard_artifacts ba
        join blackboard_artifact_types bat on ba.artifact_type_id = bat.artifact_type_id
        join tsk_files f on ba.obj_id = f.obj_id
        join data_source_info d on ba.data_source_obj_id = d.obj_id
        where bat.type_name = ?
        """,
        (type_name,),
    )
    artifacts = cur.fetchall()

    all_records = []
    for art in artifacts:
        cur.execute(
            """
            select t.type_name, coalesce(a.value_text, a.value_int64,
                   a.value_int32, a.value_double) as value
            from blackboard_attributes a
            join blackboard_attribute_types t on a.attribute_type_id = t.attribute_type_id
            where a.artifact_id = ?
            """,
            (art["artifact_id"],),
        )
        attrs = {row["type_name"]: row["value"] for row in cur.fetchall()}
        record = {
            "source_file": art["source_file"],
            "parent_path": art["parent_path"],
            "data_source": art["data_source"],
        }
        for name in attr_names:
            record[name] = attrs.get(name)
        all_records.append(record)

    if time_attr and (start_ts is not None or end_ts is not None):
        def in_range(rec):
            value = rec.get(time_attr)
            if value is None:
                return False
            if start_ts is not None and value < start_ts:
                return False
            if end_ts is not None and value > end_ts:
                return False
            return True

        all_records = [r for r in all_records if in_range(r)]

    if time_attr:
        all_records.sort(key=lambda r: (r.get(time_attr) is None, r.get(time_attr)))

    total_matched = len(all_records)
    page = all_records[:limit]
    return {
        "total_matched": total_matched,
        "returned": len(page),
        "truncated": total_matched > len(page),
        "results": page,
    }


def get_web_history(db_path=None, start_ts=None, end_ts=None, limit=300):
    conn = connect(db_path)
    try:
        return _artifacts_by_type(
            conn,
            "TSK_WEB_HISTORY",
            ["TSK_URL", "TSK_DOMAIN", "TSK_DATETIME_ACCESSED", "TSK_REFERRER", "TSK_PROG_NAME"],
            limit=limit,
            time_attr="TSK_DATETIME_ACCESSED",
            start_ts=start_ts,
            end_ts=end_ts,
        )
    finally:
        conn.close()


def get_web_search_queries(db_path=None, start_ts=None, end_ts=None, limit=300):
    conn = connect(db_path)
    try:
        return _artifacts_by_type(
            conn,
            "TSK_WEB_SEARCH_QUERY",
            ["TSK_TEXT", "TSK_DOMAIN", "TSK_DATETIME_ACCESSED"],
            limit=limit,
            time_attr="TSK_DATETIME_ACCESSED",
            start_ts=start_ts,
            end_ts=end_ts,
        )
    finally:
        conn.close()


def get_devices_attached(db_path=None, limit=300):
    conn = connect(db_path)
    try:
        return _artifacts_by_type(
            conn,
            "TSK_DEVICE_ATTACHED",
            ["TSK_DEVICE_ID", "TSK_DEVICE_MAKE", "TSK_DEVICE_MODEL", "TSK_DATETIME"],
            limit=limit,
            time_attr="TSK_DATETIME",
        )
    finally:
        conn.close()


def get_emails(db_path=None, start_ts=None, end_ts=None, limit=300):
    conn = connect(db_path)
    try:
        return _artifacts_by_type(
            conn,
            "TSK_EMAIL_MSG",
            [
                "TSK_EMAIL_FROM",
                "TSK_EMAIL_TO",
                "TSK_SUBJECT",
                "TSK_DATETIME_SENT",
                "TSK_DATETIME_RCVD",
                "TSK_TEXT",
                "TSK_PATH",
            ],
            limit=limit,
            time_attr="TSK_DATETIME_SENT",
            start_ts=start_ts,
            end_ts=end_ts,
        )
    finally:
        conn.close()


def get_installed_programs(db_path=None, limit=300):
    conn = connect(db_path)
    try:
        return _artifacts_by_type(
            conn,
            "TSK_INSTALLED_PROG",
            ["TSK_PROG_NAME", "TSK_DATETIME"],
            limit=limit,
            time_attr="TSK_DATETIME",
        )
    finally:
        conn.close()


def get_os_accounts(db_path=None, limit=300):
    conn = connect(db_path)
    try:
        return _artifacts_by_type(
            conn,
            "TSK_OS_ACCOUNT",
            ["TSK_USER_NAME", "TSK_DATETIME_CREATED", "TSK_DATETIME_ACCESSED", "TSK_COUNT"],
            limit=limit,
        )
    finally:
        conn.close()


def get_recent_documents(db_path=None, start_ts=None, end_ts=None, limit=300):
    conn = connect(db_path)
    try:
        return _artifacts_by_type(
            conn,
            "TSK_RECENT_OBJ",
            ["TSK_PATH", "TSK_DATETIME"],
            limit=limit,
            time_attr="TSK_DATETIME",
            start_ts=start_ts,
            end_ts=end_ts,
        )
    finally:
        conn.close()


def find_files(name_fragment, db_path=None, limit=200):
    conn = connect(db_path)
    try:
        cur = conn.cursor()
        cur.execute(
            """
            select f.name, f.parent_path, f.size, f.crtime, f.mtime, f.atime, f.known
            from tsk_files f
            where f.name like ?
            limit ?
            """,
            (f"%{name_fragment}%", limit),
        )
        return [dict(row) for row in cur.fetchall()]
    finally:
        conn.close()


def run_sql(query, params=(), db_path=None):
    if not query.strip().lower().startswith("select"):
        raise ValueError("run_sql only accepts SELECT statements")
    conn = connect(db_path)
    try:
        cur = conn.cursor()
        cur.execute(query, params)
        return [dict(row) for row in cur.fetchall()]
    finally:
        conn.close()

"""
mcp_server.py

Exposes the read-only functions in autopsy_tools.py as MCP tools, so any
MCP-aware agent (Hermes Agent, Claude Desktop, etc.) can query a processed
Autopsy case without the agent ever touching SQL or the case file layout
directly.

Requires the mcp package: pip install mcp

Run standalone for a quick smoke test:
    python mcp_server.py /path/to/CaseName.db

Wire it into Hermes Agent by adding this to ~/.hermes/config.yaml:
    mcp_servers:
      autopsy:
        command: "python"
        args: ["/absolute/path/to/mcp_server.py", "/absolute/path/to/CaseName.db"]

Every tool below returns JSON-serializable data (lists of dicts) straight
from autopsy_tools.py, with no summarizing or interpretation performed
here. That is intentional: interpretation is the LLM agent's job,
retrieval is this server's job, and keeping them separate is what lets
you trust that the agent's answers trace back to real evidence.
"""

import sys

from mcp.server.fastmcp import FastMCP

import autopsy_tools as at

mcp = FastMCP("autopsy")

if len(sys.argv) > 1:
    at.CASE_DB_PATH = sys.argv[1]


@mcp.tool()
def web_history(start_ts: int = None, end_ts: int = None, limit: int = 300) -> dict:
    """Browser history entries: URL, domain, access time, referrer, browser.
    start_ts/end_ts are Unix epoch seconds; omit either to leave that side
    open. Check the "truncated" field in the response and narrow the
    time range or raise limit if you need more than the returned page."""
    return at.get_web_history(start_ts=start_ts, end_ts=end_ts, limit=limit)


@mcp.tool()
def web_search_queries(start_ts: int = None, end_ts: int = None, limit: int = 300) -> dict:
    """Search engine queries typed into web browsers, with access time."""
    return at.get_web_search_queries(start_ts=start_ts, end_ts=end_ts, limit=limit)


@mcp.tool()
def devices_attached(limit: int = 300) -> dict:
    """External storage devices (USB, etc.) that were attached to the PC."""
    return at.get_devices_attached(limit=limit)


@mcp.tool()
def emails(start_ts: int = None, end_ts: int = None, limit: int = 300) -> dict:
    """Parsed e-mail messages: from, to, subject, timestamps, body, path."""
    return at.get_emails(start_ts=start_ts, end_ts=end_ts, limit=limit)


@mcp.tool()
def installed_programs(limit: int = 300) -> dict:
    """Programs installed on the imaged system, with install timestamps."""
    return at.get_installed_programs(limit=limit)


@mcp.tool()
def os_accounts(limit: int = 300) -> dict:
    """OS user accounts, with creation/last-access timestamps and login counts."""
    return at.get_os_accounts(limit=limit)


@mcp.tool()
def recent_documents(start_ts: int = None, end_ts: int = None, limit: int = 300) -> dict:
    """Recently opened file/document shortcuts recovered from the system."""
    return at.get_recent_documents(start_ts=start_ts, end_ts=end_ts, limit=limit)


@mcp.tool()
def find_files(name_fragment: str, limit: int = 200) -> list:
    """Search tsk_files by a substring of the filename."""
    return at.find_files(name_fragment, limit=limit)


@mcp.tool()
def run_sql(query: str, params: list = []) -> list:
    """Run an arbitrary read-only SELECT against the case database, for
    anything the other tools do not already cover (e.g. querying a
    specific table like tsk_image_info or a case-specific SQLite file
    such as snapshot.db that you have attached separately)."""
    return at.run_sql(query, tuple(params))


if __name__ == "__main__":
    mcp.run()

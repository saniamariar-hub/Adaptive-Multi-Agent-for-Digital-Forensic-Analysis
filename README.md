# Adaptive Multi-Agent Digital Forensics (Project Sentinel)

An intelligent digital forensics framework designed to interface directly with Autopsy case databases, expose forensic tools via the Model Context Protocol (MCP), and perform autonomous evidentiary reasoning, cross-artifact correlation, and investigative report synthesis.

---

## 1. System Architecture

```text
    ┌─────────────────────────────────────────────────────────────┐
    │              Forensic Evidence Data Sources                 │
    │         (Autopsy SQLite DB / NTFS MFT / SYSTEM Hive)        │
    └──────────────────────────────┬──────────────────────────────┘
                                   │
                                   ▼
    ┌─────────────────────────────────────────────────────────────┐
    │       Autopsy Extraction & MCP Layer (autopsy_tools.py)      │
    │   • Devices Attached      • Web History & Search Queries    │
    │   • Prefetch Executions   • User Accounts & Passwords       │
    │   • Recycle Bin Items     • OS Info & Shutdown Timestamps   │
    │   • File System (MFT)     • Raw SQL Execution Interface     │
    └──────────────┬──────────────────────────────┬───────────────┘
                   │                              │
                   ▼                              ▼
    ┌──────────────────────────────┐ ┌────────────────────────────┐
    │      FastMCP Server          │ │   Forensic Agent Engine    │
    │      (mcp_server.py)         │ │    (forensic_agent.py)     │
    │  Exposes tools directly to   │ │  Multi-model LLM cascade   │
    │  external agents (Hermes)    │ │  with structured function  │
    └──────────────────────────────┘ │  calling & auto-failover   │
                                     └────────────┬───────────────┘
                                                  │
                                                  ▼
    ┌─────────────────────────────────────────────────────────────┐
    │          Threaded Dispatch Server (server.py:8080)          │
    │   • GET  /api/logs        • GET  /api/stats                 │
    │   • GET  /api/case-info   • POST /api/chat                  │
    └──────────────┬──────────────────────────────┬───────────────┘
                   │                              │
                   ▼                              ▼
    ┌──────────────────────────────┐ ┌────────────────────────────┐
    │ Police Investigation Board   │ │  Interactive Forensic Chat │
    │         (index.html)         │ │        (chat.html)         │
    │  Real-time incident audit    │ │  Natural-language query    │
    │  log, stats & dossier modal  │ │  answering & reporting     │
    └──────────────────────────────┘ └────────────────────────────┘
```

---

## 2. Core Modules & Repository Structure

```text
.
├── autopsy_tools.py        # Direct SQLite interface for Autopsy case databases (autopsy.db)
├── mcp_server.py           # FastMCP server exposing Autopsy tools via Model Context Protocol
├── hermes_config_snippet.yaml # Configuration snippet for connecting external Hermes agents
├── forensic_agent.py       # Autonomous LLM agent with multi-model failover & function calling
├── forensic_dispatcher.py  # Deterministic forensic query routing & SQL fallback
├── case_logger.py          # Investigation audit logging & incident ID generation (SQLite)
├── server.py               # Threaded HTTP server hosting audit API & web dashboards
├── index.html              # Police Investigation Incident Audit Dashboard UI
├── chat.html               # Real-time forensic investigator chat interface
├── run_investigation.py    # NIST CFReDS 60-question automated evaluation runner
├── format_results.py       # Formatter converting evaluation results to Markdown reports
│
├── .env.example            # Environment configuration template
├── .gitignore              # Rules excluding large disk images, caches, and case databases
└── README.md               # Project documentation
```

---

## 3. Quick Start & Web Interface

### 1. Configure Environment:
Copy the example environment file and set your API key (if using cloud LLMs):
```bash
cp .env.example .env
```

### 2. Start the Forensic Server:
```bash
python server.py
```

### 3. Open the Dashboards:
* **Police Investigation Incident Audit Board:** [http://localhost:8080/](http://localhost:8080/)
* **Interactive Forensic Chat UI:** [http://localhost:8080/chat.html](http://localhost:8080/chat.html)

---

## 4. Model Context Protocol (MCP) Integration

To expose Autopsy tools to external agents (such as Hermes or Claude):
```bash
python mcp_server.py "path/to/autopsy.db"
```

---

## 5. NIST CFReDS Evaluation Suite

To run the automated investigation against the 60 NIST Data Leakage ground-truth questions:
```bash
# Run evaluation across specific questions or all 60
python run_investigation.py --only 1 2 3 4 5 --out results.json

# Format findings into a readable Markdown report
python format_results.py results.json --out results.md
```

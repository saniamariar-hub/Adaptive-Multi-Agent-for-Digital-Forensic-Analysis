# Adaptive Multi-Agent Digital Forensics Using LLM Routing and Evidence Analysis

An intelligent digital forensics framework designed to process structured forensic evidence, route domain-specific queries via an LLM router, and perform multi-agent evidentiary reasoning, correlation, contradiction detection, and report synthesis.

---

## 1. Project Objective

The objective of this Final Year Project (FYP) is to develop an adaptive, multi-agent AI architecture that automates high-level digital forensics reasoning. By decoupling low-level forensic artifact extraction (e.g., via Autopsy / Sleuth Kit) from cognitive evidentiary reasoning, the system analyzes complex timelines, cross-correlates multi-source artifacts, flags inconsistencies, and synthesizes structured investigative reports.

---

## 2. System Architecture

```text
Forensic Evidence Sources (Autopsy / Raw Disks / EVTX / Logs)
         │
         ▼
 Structured Evidence Schema (Pydantic)
         │
         ▼
     [Hermes]  <─── (Local / Cloud LLM Foundation)
         │
         ▼
    [LLM Router]
         │
 ┌───────┴───────────────────────────────┐
 │                                       │
 ▼                                       ▼
1. Evidence Triage Agent        2. Evidence Correlation & Timeline Agent
 │                                       │
 ▼                                       ▼
3. Contradiction & Verification 4. Forensic Synthesis Agent
   Agent                                 │
                                         ▼
                             Comprehensive Investigation Report
```

### The Four Forensic Agents
1. **Evidence Triage Agent**: Evaluates evidence relevance, filters background system noise, assesses source reliability, and prioritizes suspicious artifacts.
2. **Evidence Correlation & Timeline Agent**: Cross-references temporal and causal connections across diverse artifact types (browser history, USB insertion, file modifications, network traffic).
3. **Contradiction & Verification Agent**: Detects temporal anomalies, impossible state transitions (e.g., activity on locked workstations), and conflicting evidentiary records.
4. **Forensic Synthesis Agent**: Aggregates verified agent insights to construct a cohesive, defensible forensic timeline and investigative summary report.

---

## 3. Architecture Separation: Extraction vs. AI Reasoning

To maintain forensic integrity and modularity, the architecture enforces a strict boundary:
* **Forensic Extraction Layer**: Operates deterministically using established forensic tools (Autopsy, Sleuth Kit, log parsers) to extract raw artifacts into a standardized, validated evidence schema.
* **AI Reasoning Layer**: Consumes structured evidence objects to perform multi-agent analysis, semantic anomaly detection, and natural language synthesis.

---

## 4. Current Development Stage

* **Current Stage**: **Stage 2 - Live Autopsy Case Integration & Agentic Investigation UI**
* **Active Status**:
  - Python virtual environment configured with core validation tools.
  - Standardized Pydantic forensic evidence schema implemented (`forensic_pipeline/evidence_schema.py`).
  - Modular evidence loader implemented with strict validation rules (`forensic_pipeline/evidence_loader.py`).
  - Core validation and schema test suite operational (`tests/test_evidence_loader.py`).
  - **Live Autopsy Case Database Interface** (`autopsy_tools.py`): Direct extraction of blackboard artifacts, OS info, attached devices, prefetch logs, recycle bin, web history, and raw MFT records from Autopsy case databases (`autopsy.db`).
  - **Model Context Protocol (MCP) Server** (`mcp_server.py`): FastMCP-based bridge exposing Autopsy tools directly to Hermes and AI agent runners.
  - **Agentic Forensic Analyst Engine** (`forensic_agent.py`): Multi-model LLM reasoning cascade with structured function calling and guaranteed synthesis.
  - **Police Investigation Audit Dashboard & Chat UI** (`index.html`, `chat.html`, `server.py`): High-concurrency threaded dispatch server hosting live forensic chat and an automated incident audit logger.
  - **NIST CFReDS Investigation Runner** (`run_investigation.py`, `format_results.py`): Automated evaluation suite testing all 60 NIST Data Leakage questions against forensic ground truth.

---

## 5. Directory Structure

```text
├── agents/                 # Specialized forensic agent implementations
├── router/                 # Query classification and agent routing logic
├── forensic_pipeline/      # Evidence schemas, parsers, and data loaders
│   ├── __init__.py
│   ├── evidence_schema.py  # Pydantic data models for forensic artifacts
│   ├── evidence_loader.py  # Validation and JSON parsing utilities
│   └── sample_evidence.json# Synthetic test case containing intentional contradictions
├── configs/                # System configuration and environment settings
├── evaluation/             # Benchmarks, ground-truth metrics, and evaluation scripts
├── outputs/                # Generated reports, agent traces, and run logs
├── tests/                  # Pytest test suites
├── datasets/               # Forensic datasets (CFReDS disk images, raw artifacts)
│
├── autopsy_tools.py        # Direct SQLite interface for Autopsy case databases
├── mcp_server.py           # FastMCP server exposing forensic tools to LLMs
├── hermes_config_snippet.yaml # MCP client configuration for Hermes agent
├── forensic_agent.py       # Autonomous LLM agent with function calling & cascade
├── forensic_dispatcher.py  # Deterministic forensic query routing & SQL fallback
├── case_logger.py          # Investigation audit logging & incident ID generation
├── server.py               # Threaded HTTP server hosting audit API & web interfaces
├── index.html              # Police Investigation Incident Audit Dashboard UI
├── chat.html               # Real-time forensic investigator chat interface
├── run_investigation.py    # NIST CFReDS 60-question automated evaluation runner
├── format_results.py       # Formatter converting evaluation results to Markdown
│
├── .env.example            # Environment configuration template
├── .gitignore              # Git ignore rules for virtualenvs, caches, and raw images
├── requirements.txt        # Python dependency manifest
└── README.md               # Project documentation
```

---

## 6. Running the Interactive Forensic UI

To launch the Police Investigation Audit Board and Forensic Chat Interface:

```bash
# Start the threaded forensic dispatch server
python server.py

# Access the dashboards in your browser:
# Incident Audit Log Board: http://localhost:8080/
# Interactive Forensic Chat: http://localhost:8080/chat.html
```

---

## 7. Running Tests & Evaluations

### Run Schema Tests:
```bash
python -m pytest -v
```

### Run NIST CFReDS Automated Investigation:
```bash
# Run all questions or filter by specific question numbers
python run_investigation.py --only 1 2 3 4 5 --out results.json

# Format findings into a readable Markdown report
python format_results.py results.json --out results.md
```

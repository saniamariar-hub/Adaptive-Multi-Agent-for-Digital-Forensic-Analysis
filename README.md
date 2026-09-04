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

* **Current Stage**: **Stage 1 - Foundational Data Models & Environment Setup**
* **Active Status**:
  - Python virtual environment (`.venv`) configured with core validation tools.
  - Standardized Pydantic forensic evidence schema implemented (`forensic_pipeline/evidence_schema.py`).
  - Modular evidence loader implemented with strict validation rules (`forensic_pipeline/evidence_loader.py`).
  - Synthetic forensic dataset generated with deliberate timeline contradictions (`forensic_pipeline/sample_evidence.json`).
  - Core validation and schema test suite operational (`tests/test_evidence_loader.py`).
* **Note on Evidence**: Synthetic test evidence is currently utilized for initial prototyping and unit testing. Integration with real **CFReDS** forensic disk images and **Autopsy** extracted cases will be connected in subsequent development phases.
* **Note on Agents & Hermes**: Agent reasoning logic, LLM routing, and Hermes integration are planned for upcoming phases and are not yet implemented.

---

## 5. Directory Structure

```text
FYP/
├── agents/                 # Specialized forensic agent implementations (Upcoming)
├── router/                 # Query classification and agent routing logic (Upcoming)
├── forensic_pipeline/      # Evidence schemas, parsers, and data loaders
│   ├── __init__.py
│   ├── evidence_schema.py  # Pydantic data models for forensic artifacts
│   ├── evidence_loader.py  # Validation and JSON parsing utilities
│   └── sample_evidence.json# Synthetic test case containing intentional contradictions
├── configs/                # System configuration and environment settings
│   ├── __init__.py
│   └── config.py           # Central configuration container
├── evaluation/             # Benchmarks, ground-truth metrics, and evaluation scripts
├── outputs/                # Generated reports, agent traces, and run logs
├── tests/                  # Pytest test suites
│   ├── __init__.py
│   └── test_evidence_loader.py
├── datasets/               # Forensic datasets (CFReDS disk images, raw artifacts)
├── autopsy_cases/          # Autopsy case files and exports
├── .env.example            # Environment configuration template
├── .gitignore              # Git ignore rules for virtualenvs, caches, and raw images
├── requirements.txt        # Python dependency manifest
└── README.md               # Project documentation
```

---

## 6. Running Tests

To run the schema validation test suite:

```bash
# Activate virtual environment (Windows PowerShell)
.\.venv\Scripts\Activate.ps1

# Execute pytest
python -m pytest -v
```

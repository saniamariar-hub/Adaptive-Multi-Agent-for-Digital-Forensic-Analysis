"""LLM-Powered Evidence Triage Agent (Agent 1 - LLM Extension).

Uses real LLM reasoning (via Ollama / hermes3:latest) to analyze, categorize,
and assess structured forensic evidence while strictly validating against the
standard Pydantic TriageResult schema.
"""

import json
from pathlib import Path
import re
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field, ValidationError

from agents.triage_agent import TriageResult
from forensic_pipeline.evidence_schema import EvidenceCollection
from llm.llm_client import LLMClient, LLMResponse
from llm.ollama_client import OllamaClient

PROMPT_TEMPLATE_PATH = Path(__file__).resolve().parent.parent / "configs" / "prompts" / "triage_prompt.txt"


class LLMTriageError(Exception):
    """Base exception for LLM triage processing failures."""
    pass


class LLMTriageValidationError(LLMTriageError):
    """Raised when LLM output cannot be validated against the Pydantic TriageResult schema."""
    def __init__(self, message: str, raw_text: str, raw_errors: Optional[list] = None):
        super().__init__(message)
        self.raw_text = raw_text
        self.raw_errors = raw_errors or []


class LLMTriagedItem(BaseModel):
    """Schema for an individual evidence item triaged by LLM."""
    evidence_id: str = Field(..., description="Evidence ID matching canonical record.")
    category: str = Field(..., description="Assigned forensic category.")
    significance: Optional[str] = Field(default=None, description="Investigative significance summary.")
    is_notable: bool = Field(default=False, description="Whether item has elevated investigative significance.")
    confidence: float = Field(default=1.0, description="Confidence score.")


class LLMTriageResponse(BaseModel):
    """Schema for the expected raw LLM triage response structure."""
    case_id: Optional[str] = None
    case_name: Optional[str] = None
    triaged_items: List[LLMTriagedItem] = Field(..., description="List of triaged evidence items.")
    missing_or_unknown_info: Optional[List[Dict[str, Any]]] = None
    overall_observations: Optional[List[str]] = None


class LLMEvidenceTriageAgent:
    """Agent 1 LLM Variant: Performs AI-powered forensic evidence triage using real LLM reasoning."""

    def __init__(
        self,
        llm_client: Optional[LLMClient] = None,
        prompt_template_path: Optional[Path] = None,
    ):
        self.llm_client = llm_client or OllamaClient()
        self.prompt_template_path = prompt_template_path or PROMPT_TEMPLATE_PATH
        self.last_response: Optional[LLMResponse] = None

    def triage_case(
        self,
        collection: EvidenceCollection,
        temperature: Optional[float] = None,
    ) -> TriageResult:
        """Analyze evidence collection using LLM and return validated TriageResult.

        Args:
            collection: Validated EvidenceCollection.
            temperature: Sampling temperature override.

        Returns:
            TriageResult: Validated Pydantic triage result.

        Raises:
            LLMTriageError: If LLM generation fails.
            LLMTriageValidationError: If LLM output fails schema validation.
        """
        # 1. Prepare Prompt
        prompt = self._build_prompt(collection)
        system_prompt = (
            "You are a specialized digital forensics AI assistant. "
            "You strictly output valid JSON adhering to the specified schema without conversational prose."
        )

        # 2. Call LLM (with json_mode=True)
        response = self.llm_client.generate(
            prompt=prompt,
            system_prompt=system_prompt,
            json_mode=True,
            temperature=temperature,
        )
        self.last_response = response

        if not response.success:
            raise LLMTriageError(f"LLM generation failed: {response.error_message}")

        # 3. Parse and Clean JSON
        parsed_data = self._clean_and_parse_json(response.text)

        # 4. Validate against Pydantic schema and normalize
        try:
            if not isinstance(parsed_data, dict):
                raise ValidationError.from_exception_data(
                    title="LLMTriageResponse",
                    line_errors=[{"type": "model_type", "loc": ("root",), "input": parsed_data, "msg": "Input must be a JSON object"}],
                )

            if "triaged_items" in parsed_data:
                # Validate raw LLM response schema
                LLMTriageResponse.model_validate(parsed_data)
                normalized_data = self._normalize_parsed_data(parsed_data, collection)
                triage_result = TriageResult.model_validate(normalized_data)
                return triage_result
            elif "categorized_evidence" in parsed_data:
                normalized_data = self._normalize_parsed_data(parsed_data, collection)
                triage_result = TriageResult.model_validate(normalized_data)
                return triage_result
            else:
                # Schema mismatch: missing required triage fields
                LLMTriageResponse.model_validate(parsed_data)
                normalized_data = self._normalize_parsed_data(parsed_data, collection)
                return TriageResult.model_validate(normalized_data)
        except ValidationError as exc:
            formatted_errors = []
            for err in exc.errors():
                loc = " -> ".join(str(elem) for elem in err.get("loc", []))
                msg = err.get("msg", "Validation error")
                formatted_errors.append(f"Field [{loc}]: {msg}")

            error_msg = (
                f"LLM output failed Pydantic schema validation with {len(formatted_errors)} error(s):\n"
                + "\n".join(f"  - {e}" for e in formatted_errors)
            )
            raise LLMTriageValidationError(
                message=error_msg,
                raw_text=response.text,
                raw_errors=exc.errors(),
            ) from exc

    def _build_prompt(self, collection: EvidenceCollection) -> str:
        """Render prompt template with serialized evidence records."""
        if not self.prompt_template_path.exists():
            raise FileNotFoundError(f"Prompt template not found at {self.prompt_template_path}")

        template_text = self.prompt_template_path.read_text(encoding="utf-8")

        evidence_dict_list = [item.model_dump(mode="json") for item in collection.records]
        evidence_json_str = json.dumps(evidence_dict_list, indent=2)

        prompt = template_text.format(
            case_id=collection.case_id,
            case_name=collection.case_name,
            is_synthetic=str(collection.is_synthetic).lower(),
            total_count=len(collection.records),
            evidence_json=evidence_json_str,
        )
        return prompt

    def _clean_and_parse_json(self, raw_text: str) -> Dict[str, Any]:
        """Extract and parse valid JSON from LLM output, handling markdown fences or leading whitespace."""
        text = raw_text.strip()

        # Strip markdown code blocks ```json ... ``` or ``` ... ```
        if text.startswith("```"):
            match = re.search(r"```(?:json)?\s*([\s\S]*?)\s*```", text)
            if match:
                text = match.group(1).strip()

        # Find first '{' and last '}'
        start_idx = text.find("{")
        end_idx = text.rfind("}")
        if start_idx != -1 and end_idx != -1 and end_idx > start_idx:
            text = text[start_idx : end_idx + 1]

        try:
            return json.loads(text)
        except json.JSONDecodeError as exc:
            raise LLMTriageError(
                f"Failed to decode LLM response as valid JSON: {exc}\nRaw output preview:\n{raw_text[:400]}"
            ) from exc

    def _normalize_parsed_data(self, data: Dict[str, Any], collection: EvidenceCollection) -> Dict[str, Any]:
        """Normalize and assemble complete TriageResult dictionary from LLM classifications."""
        if not isinstance(data, dict):
            return data

        # Ensure case metadata fallback
        data.setdefault("case_id", collection.case_id)
        data.setdefault("case_name", collection.case_name)
        data.setdefault("is_synthetic", collection.is_synthetic)
        data.setdefault("case_description", collection.description)

        # Build items map from canonical collection
        records_map = {item.evidence_id: item for item in collection.records}

        # Case 1: LLM returned 'triaged_items' list
        if "triaged_items" in data and isinstance(data["triaged_items"], list):
            llm_items_map = {
                t.get("evidence_id"): t for t in data["triaged_items"] if isinstance(t, dict) and "evidence_id" in t
            }

            categorized: Dict[str, List[Dict[str, Any]]] = {}
            notable_list: List[Dict[str, Any]] = []

            for ev_id, canonical_item in records_map.items():
                llm_meta = llm_items_map.get(ev_id, {})
                category_val = str(llm_meta.get("category", "Other"))
                significance_val = llm_meta.get("significance", f"Record of {canonical_item.action}.")
                is_notable_val = bool(llm_meta.get("is_notable", False))
                confidence_val = float(llm_meta.get("confidence", canonical_item.confidence))

                # Normalize category string to match TriageCategory enum
                valid_cats = [
                    "Browser/Web Activity",
                    "Email/Communication",
                    "File Activity",
                    "System Activity",
                    "USB/External Device Activity",
                    "Network Activity",
                    "Other",
                ]
                matched_cat = next((c for c in valid_cats if c.lower() in category_val.lower()), "Other")

                item_dict = {
                    "evidence_id": canonical_item.evidence_id,
                    "source": canonical_item.source,
                    "artifact_type": canonical_item.artifact_type.value,
                    "category": matched_cat,
                    "timestamp": canonical_item.timestamp.isoformat() if canonical_item.timestamp else None,
                    "timestamp_timezone": canonical_item.timestamp_timezone,
                    "user": canonical_item.user,
                    "device": canonical_item.device,
                    "action": canonical_item.action,
                    "description": canonical_item.description,
                    "resource_path": canonical_item.resource_path,
                    "significance": significance_val,
                    "confidence": confidence_val,
                    "source_reliability": canonical_item.source_reliability.value,
                    "is_notable": is_notable_val,
                    "raw_metadata": canonical_item.metadata,
                }

                categorized.setdefault(matched_cat, []).append(item_dict)
                if is_notable_val:
                    notable_list.append(item_dict)

            data["categorized_evidence"] = categorized
            data["notable_evidence"] = notable_list
            data["category_counts"] = {k: len(v) for k, v in categorized.items()}
            data["total_evidence_count"] = len(collection.records)

        # Case 2: LLM returned 'categorized_evidence' directly
        elif "categorized_evidence" in data and isinstance(data["categorized_evidence"], dict):
            cat_ev = data["categorized_evidence"]
            all_items = []
            for cat_name, items_list in cat_ev.items():
                if isinstance(items_list, list):
                    all_items.extend(items_list)

            data.setdefault("total_evidence_count", len(all_items) if all_items else len(collection.records))
            data.setdefault("category_counts", {k: len(v) for k, v in cat_ev.items() if isinstance(v, list) and len(v) > 0})

            if not data.get("notable_evidence") and all_items:
                data["notable_evidence"] = [i for i in all_items if isinstance(i, dict) and i.get("is_notable")]

        # Aggregate users, devices, timestamps from canonical collection
        users_set = {r.user for r in collection.records if r.user}
        devices_set = {r.device for r in collection.records if r.device}
        timestamps = [r.timestamp for r in collection.records if r.timestamp]

        data.setdefault("users_involved", sorted(list(users_set)))
        data.setdefault("devices_involved", sorted(list(devices_set)))
        if timestamps:
            data.setdefault("earliest_timestamp", min(timestamps).isoformat())
            data.setdefault("latest_timestamp", max(timestamps).isoformat())

        data.setdefault("missing_or_unknown_info", [])
        data.setdefault("overall_observations", [])

        return data


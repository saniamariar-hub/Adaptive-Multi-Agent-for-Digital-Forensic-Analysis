"""Evidence Triage Agent (Agent 1).

Responsible for answering: "What evidence do we actually have?"
Performs deterministic initial categorization, significance assessment,
missing information tracking, and structured summary generation.
Designed with pluggable reasoning so LLM capabilities can be integrated
without altering the input/output contract.
"""

from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple
from pydantic import BaseModel, Field

from forensic_pipeline.evidence_schema import (
    ArtifactType,
    EvidenceCollection,
    EvidenceItem,
    SourceReliability,
)


class TriageCategory(str, Enum):
    """High-level forensic evidence categories."""
    BROWSER_WEB = "Browser/Web Activity"
    EMAIL_COMMUNICATION = "Email/Communication"
    FILE_ACTIVITY = "File Activity"
    SYSTEM_ACTIVITY = "System Activity"
    USB_EXTERNAL_DEVICE = "USB/External Device Activity"
    NETWORK_ACTIVITY = "Network Activity"
    OTHER = "Other"


class TriagedEvidenceItem(BaseModel):
    """Enriched representation of an evidence item post-triage."""

    evidence_id: str = Field(..., description="Unique evidence identifier.")
    source: str = Field(..., description="Source file or log origin.")
    artifact_type: str = Field(..., description="Original forensic artifact type.")
    category: TriageCategory = Field(..., description="High-level triage category.")
    timestamp: Optional[datetime] = Field(default=None, description="Event timestamp (ISO-8601).")
    timestamp_timezone: str = Field(default="UTC", description="Timezone.")
    user: Optional[str] = Field(default=None, description="Associated user if identified.")
    device: Optional[str] = Field(default=None, description="Associated device hostname/ID.")
    action: str = Field(..., description="Event or action performed.")
    description: str = Field(..., description="Factual description from source.")
    resource_path: Optional[str] = Field(default=None, description="Resource, file path, or URL.")
    significance: str = Field(..., description="Factual relevance or investigative significance.")
    confidence: float = Field(..., ge=0.0, le=1.0, description="Confidence score.")
    source_reliability: str = Field(..., description="Reliability grade.")
    is_notable: bool = Field(
        default=False,
        description="Flag indicating elevated investigative importance for downstream correlation.",
    )
    raw_metadata: Dict[str, Any] = Field(
        default_factory=dict,
        description="Extensible raw metadata preserved from original artifact.",
    )


class MissingInfoRecord(BaseModel):
    """Record of missing or unverified attributes in an evidence item."""

    evidence_id: str = Field(..., description="Evidence ID with missing attributes.")
    missing_fields: List[str] = Field(..., description="List of empty or missing fields.")
    note: str = Field(..., description="Investigative context of why the omission matters.")


class TriageResult(BaseModel):
    """Deterministic structured output produced by Agent 1 for Agent 2 consumption."""

    case_id: str = Field(..., description="Forensic case identifier.")
    case_name: str = Field(..., description="Case title.")
    case_description: Optional[str] = Field(default=None, description="Overview of case context.")
    is_synthetic: bool = Field(default=False, description="Whether case uses synthetic test data.")
    total_evidence_count: int = Field(..., description="Total evidence records triaged.")
    category_counts: Dict[str, int] = Field(
        default_factory=dict,
        description="Distribution of evidence counts per category.",
    )
    categorized_evidence: Dict[str, List[TriagedEvidenceItem]] = Field(
        default_factory=dict,
        description="Evidence items grouped by high-level category.",
    )
    notable_evidence: List[TriagedEvidenceItem] = Field(
        default_factory=list,
        description="High-significance items flagged for immediate timeline/contradiction review.",
    )
    missing_or_unknown_info: List[MissingInfoRecord] = Field(
        default_factory=list,
        description="Items with missing users, devices, or unverified metadata.",
    )
    earliest_timestamp: Optional[datetime] = Field(
        default=None,
        description="Earliest timestamp recorded in the triaged evidence.",
    )
    latest_timestamp: Optional[datetime] = Field(
        default=None,
        description="Latest timestamp recorded in the triaged evidence.",
    )
    users_involved: List[str] = Field(
        default_factory=list,
        description="Unique user accounts identified across evidence.",
    )
    devices_involved: List[str] = Field(
        default_factory=list,
        description="Unique devices identified across evidence.",
    )
    overall_observations: List[str] = Field(
        default_factory=list,
        description="High-level factual findings and structural summary observations.",
    )


class EvidenceTriageAgent:
    """Agent 1: Evaluates, categorizes, and organizes structured forensic evidence.

    Answers: "What evidence do we actually have?"
    Modular design allows heuristic reasoning to be replaced/augmented with
    LLM reasoning in future stages.
    """

    def __init__(self, high_priority_keywords: Optional[List[str]] = None):
        self.high_priority_keywords = high_priority_keywords or [
            "upload", "exfiltration", "archive", "cleaner", "delete", "usb",
            "logon", "lock", "logoff", "suspicious", "c2", "remover", "temp"
        ]

    def triage_case(self, collection: EvidenceCollection) -> TriageResult:
        """Process an entire forensic evidence collection and return structured triage results.

        Args:
            collection: Validated EvidenceCollection from evidence_loader.

        Returns:
            TriageResult: Comprehensive structured triage report.
        """
        triaged_items: List[TriagedEvidenceItem] = []
        missing_info_records: List[MissingInfoRecord] = []
        category_map: Dict[str, List[TriagedEvidenceItem]] = {
            cat.value: [] for cat in TriageCategory
        }

        users_set: Set[str] = set()
        devices_set: Set[str] = set()
        timestamps: List[datetime] = []

        for record in collection.records:
            # 1. Classify Category
            category = self._classify_category(record)

            # 2. Assess Significance and Notability
            significance, is_notable = self._assess_significance(record)

            # 3. Track Missing Information
            missing_rec = self._identify_missing_info(record)
            if missing_rec:
                missing_info_records.append(missing_rec)

            # 4. Build Enriched Triaged Item
            triaged_item = TriagedEvidenceItem(
                evidence_id=record.evidence_id,
                source=record.source,
                artifact_type=record.artifact_type.value,
                category=category,
                timestamp=record.timestamp,
                timestamp_timezone=record.timestamp_timezone,
                user=record.user,
                device=record.device,
                action=record.action,
                description=record.description,
                resource_path=record.resource_path,
                significance=significance,
                confidence=record.confidence,
                source_reliability=record.source_reliability.value,
                is_notable=is_notable,
                raw_metadata=record.metadata,
            )

            triaged_items.append(triaged_item)
            category_map[category.value].append(triaged_item)

            # Aggregate tracking
            if record.user:
                users_set.add(record.user)
            if record.device:
                devices_set.add(record.device)
            if record.timestamp:
                timestamps.append(record.timestamp)

        # Filter empty categories from dictionary for cleaner output
        active_categorized = {k: v for k, v in category_map.items() if len(v) > 0}
        category_counts = {k: len(v) for k, v in active_categorized.items()}

        notable_items = [item for item in triaged_items if item.is_notable]

        # Calculate time boundaries
        earliest_ts = min(timestamps) if timestamps else None
        latest_ts = max(timestamps) if timestamps else None

        # Generate observations
        observations = self._generate_observations(
            collection=collection,
            triaged_items=triaged_items,
            category_counts=category_counts,
            users=sorted(list(users_set)),
            devices=sorted(list(devices_set)),
            earliest_ts=earliest_ts,
            latest_ts=latest_ts,
            notable_count=len(notable_items),
        )

        return TriageResult(
            case_id=collection.case_id,
            case_name=collection.case_name,
            case_description=collection.description,
            is_synthetic=collection.is_synthetic,
            total_evidence_count=len(triaged_items),
            category_counts=category_counts,
            categorized_evidence=active_categorized,
            notable_evidence=notable_items,
            missing_or_unknown_info=missing_info_records,
            earliest_timestamp=earliest_ts,
            latest_timestamp=latest_ts,
            users_involved=sorted(list(users_set)),
            devices_involved=sorted(list(devices_set)),
            overall_observations=observations,
        )

    def _classify_category(self, item: EvidenceItem) -> TriageCategory:
        """Deterministic mapping from artifact types to high-level triage categories."""
        art_type = item.artifact_type

        if art_type == ArtifactType.BROWSER_HISTORY:
            return TriageCategory.BROWSER_WEB
        elif art_type == ArtifactType.EMAIL:
            return TriageCategory.EMAIL_COMMUNICATION
        elif art_type == ArtifactType.FILE_ACTIVITY:
            return TriageCategory.FILE_ACTIVITY
        elif art_type in (
            ArtifactType.SYSTEM_LOG,
            ArtifactType.AUTHENTICATION,
            ArtifactType.REGISTRY,
            ArtifactType.MEMORY_ARTIFACT,
        ):
            return TriageCategory.SYSTEM_ACTIVITY
        elif art_type == ArtifactType.USB_ACTIVITY:
            return TriageCategory.USB_EXTERNAL_DEVICE
        elif art_type == ArtifactType.NETWORK_ACTIVITY:
            return TriageCategory.NETWORK_ACTIVITY
        else:
            return TriageCategory.OTHER

    def _assess_significance(self, item: EvidenceItem) -> Tuple[str, bool]:
        """Assess the factual investigative significance and notability flag of an evidence item.

        This method can be swapped with or augmented by an LLM prompt in future iterations.
        """
        desc_lower = item.description.lower()
        action_lower = item.action.lower()
        res_lower = (item.resource_path or "").lower()
        metadata_str = str(item.metadata).lower()

        is_notable = False
        significance_parts: List[str] = []

        # 1. Check for explicit contradiction tags or anomalies
        if "contradiction" in desc_lower or "contradiction" in metadata_str:
            is_notable = True
            significance_parts.append(
                "Contains explicit conflict/contradiction flag with other case records."
            )

        # 2. Check for data staging or exfiltration
        if any(w in desc_lower or w in action_lower for w in ["upload", "exfiltration", "archive_created", "copied_to_removable"]):
            is_notable = True
            significance_parts.append(
                "Potential data staging, external transfer, or removable media exfiltration."
            )

        # 3. Check for external connections / C2
        if "outbound" in action_lower or "suspicious_ip" in metadata_str:
            is_notable = True
            significance_parts.append(
                "Outbound network communication to external or untrusted endpoint."
            )

        # 4. Check for persistence or anti-forensics
        if "service_installed" in action_lower or "cleaner" in res_lower:
            is_notable = True
            significance_parts.append(
                "System modification or potential persistence/anti-forensic utility installation."
            )

        # 5. Check for physical/hardware attach
        if item.artifact_type == ArtifactType.USB_ACTIVITY:
            is_notable = True
            significance_parts.append(
                "Removable hardware connection event requiring device serial and volume tracking."
            )

        # 6. Session and logon state changes
        if item.artifact_type == ArtifactType.AUTHENTICATION:
            significance_parts.append(
                f"Authentication state record ({item.action}) for identity and session timeline reconstruction."
            )
            if "lock" in action_lower or "logoff" in action_lower:
                is_notable = True

        # Default fallback if no specific triggers
        if not significance_parts:
            significance_parts.append(
                f"Standard evidentiary record of {item.artifact_type.value} event ({item.action})."
            )

        significance_summary = " ".join(significance_parts)
        return significance_summary, is_notable

    def _identify_missing_info(self, item: EvidenceItem) -> Optional[MissingInfoRecord]:
        """Identify missing, ambiguous, or unverified attributes in an evidence item."""
        missing: List[str] = []

        if not item.user:
            missing.append("user")
        if not item.device:
            missing.append("device")
        if not item.resource_path:
            missing.append("resource_path")
        if item.source_reliability in (SourceReliability.LOW, SourceReliability.UNVERIFIED):
            missing.append("source_reliability (unverified/low)")

        if missing:
            notes = []
            if "user" in missing:
                notes.append("Event lacks user context (system-level or unauthenticated activity).")
            if "device" in missing:
                notes.append("Origin device hostname is unspecified.")
            if "resource_path" in missing:
                notes.append("No specific target file, URL, or resource path recorded.")
            if "source_reliability (unverified/low)" in missing:
                notes.append("Source reliability requires corroboration from secondary logs.")

            return MissingInfoRecord(
                evidence_id=item.evidence_id,
                missing_fields=missing,
                note=" ".join(notes),
            )
        return None

    def _generate_observations(
        self,
        collection: EvidenceCollection,
        triaged_items: List[TriagedEvidenceItem],
        category_counts: Dict[str, int],
        users: List[str],
        devices: List[str],
        earliest_ts: Optional[datetime],
        latest_ts: Optional[datetime],
        notable_count: int,
    ) -> List[str]:
        """Synthesize high-level factual observations without hallucinating external facts."""
        obs = []

        obs.append(
            f"Case '{collection.case_name}' ({collection.case_id}) contains {len(triaged_items)} "
            f"triaged evidence records spanning {len(category_counts)} distinct forensic categories."
        )

        if earliest_ts and latest_ts:
            duration_hours = (latest_ts - earliest_ts).total_seconds() / 3600.0
            obs.append(
                f"Evidence timeline spans from {earliest_ts.isoformat()} to {latest_ts.isoformat()} "
                f"({duration_hours:.2f} hours total duration)."
            )

        obs.append(
            f"Identified {len(users)} unique user identity/account(s): {', '.join(users) if users else 'None'}."
        )

        obs.append(
            f"Identified {len(devices)} unique device/host system(s): {', '.join(devices) if devices else 'None'}."
        )

        obs.append(
            f"Flagged {notable_count} notable evidence item(s) showing elevated investigative significance "
            f"(e.g., removable media attachments, external file transfers, authentication shifts, persistence)."
        )

        if collection.is_synthetic:
            obs.append("DATASET NOTICE: This case is designated as SYNTHETIC test data.")

        return obs

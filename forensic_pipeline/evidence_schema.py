"""Evidence Schema Definition.

Standardized data models for structured digital forensic evidence,
compatible with Autopsy, Sleuth Kit, and synthetic test datasets.
"""

from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field, field_validator


class ArtifactType(str, Enum):
    """Common forensic artifact types."""
    BROWSER_HISTORY = "browser_history"
    SYSTEM_LOG = "system_log"
    EMAIL = "email"
    FILE_ACTIVITY = "file_activity"
    USB_ACTIVITY = "usb_activity"
    NETWORK_ACTIVITY = "network_activity"
    AUTHENTICATION = "authentication"
    REGISTRY = "registry"
    MEMORY_ARTIFACT = "memory_artifact"
    OTHER = "other"


class SourceReliability(str, Enum):
    """Reliability level of the evidence source."""
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    UNVERIFIED = "UNVERIFIED"


class EvidenceItem(BaseModel):
    """Standardized representation of a single forensic evidence artifact."""

    evidence_id: str = Field(
        ...,
        description="Unique identifier for the evidence item (e.g., 'EV-001').",
        min_length=1,
    )
    source: str = Field(
        ...,
        description="Origin source of the artifact (e.g., 'Security.evtx', 'Chrome History', 'MBOX').",
        min_length=1,
    )
    artifact_type: ArtifactType = Field(
        ...,
        description="Categorization of the forensic artifact.",
    )
    timestamp: Optional[datetime] = Field(
        default=None,
        description="Normalized ISO-8601 timestamp of when the event occurred (None if undetermined).",
    )
    timestamp_timezone: str = Field(
        default="UTC",
        description="Timezone designation for the timestamp (e.g., 'UTC', 'UTC+0', 'EST').",
    )
    user: Optional[str] = Field(
        default=None,
        description="User account or security identifier associated with the event.",
    )
    device: Optional[str] = Field(
        default=None,
        description="Device name, hostname, or hardware identifier.",
    )
    action: str = Field(
        ...,
        description="Specific event or action performed (e.g., 'FILE_DOWNLOAD', 'DEVICE_ATTACHED', 'USER_LOGON').",
        min_length=1,
    )
    description: str = Field(
        ...,
        description="Factual, human-readable summary of the recorded evidence item.",
        min_length=1,
    )
    resource_path: Optional[str] = Field(
        default=None,
        description="File path, URL, URI, registry key, or resource identifier involved.",
    )
    metadata: Dict[str, Any] = Field(
        default_factory=dict,
        description="Extensible key-value metadata extracted from forensic tools (e.g., hashes, event IDs).",
    )
    confidence: float = Field(
        default=1.0,
        ge=0.0,
        le=1.0,
        description="Confidence score of the evidence extraction/interpretation (0.0 to 1.0).",
    )
    source_reliability: SourceReliability = Field(
        default=SourceReliability.HIGH,
        description="Estimated reliability of the evidentiary source.",
    )

    @field_validator("artifact_type", mode="before")
    @classmethod
    def normalize_artifact_type(cls, v: Any) -> Any:
        if isinstance(v, str):
            normalized = v.strip().lower().replace(" ", "_").replace("-", "_")
            # Map common variations
            for member in ArtifactType:
                if member.value == normalized:
                    return member
        return v

    @field_validator("source_reliability", mode="before")
    @classmethod
    def normalize_source_reliability(cls, v: Any) -> Any:
        if isinstance(v, str):
            normalized = v.strip().upper()
            for member in SourceReliability:
                if member.value == normalized:
                    return member
        return v


class EvidenceCollection(BaseModel):
    """Container model for a forensic case or collection of evidence items."""

    case_id: str = Field(..., description="Unique case identifier.")
    case_name: str = Field(..., description="Human-readable case name.")
    description: Optional[str] = Field(default=None, description="Case overview description.")
    is_synthetic: bool = Field(
        default=False,
        description="Flag indicating if the dataset contains synthetic test data.",
    )
    records: List[EvidenceItem] = Field(
        default_factory=list,
        description="List of standardized evidence records.",
    )

    def get_by_id(self, evidence_id: str) -> Optional[EvidenceItem]:
        """Retrieve an evidence item by its unique ID."""
        for item in self.records:
            if item.evidence_id == evidence_id:
                return item
        return None

    def filter_by_type(self, artifact_type: ArtifactType) -> List[EvidenceItem]:
        """Filter evidence items by artifact type."""
        return [item for item in self.records if item.artifact_type == artifact_type]

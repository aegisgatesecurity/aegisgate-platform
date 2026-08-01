# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025-2026 AegisGate Security. All rights reserved.

"""
Data models for the AegisGate Python SDK v3.6.0.
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

class ViolationSeverity(str, Enum):
    """Security violation severity levels."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ViolationType(str, Enum):
    """Types of security violations."""
    PROMPT_INJECTION = "prompt_injection"
    DATA_EXFILTRATION = "data_exfiltration"
    MODEL_MANIPULATION = "model_manipulation"
    PII_EXPOSURE = "pii_exposure"
    TOXIC_CONTENT = "toxic_content"
    ADVERSARIAL_ATTACK = "adversarial_attack"
    COMPLIANCE_VIOLATION = "compliance_violation"


class LicenseType(str, Enum):
    """License tier types."""
    COMMUNITY = "community"
    DEVELOPER = "developer"
    PROFESSIONAL = "professional"
    ENTERPRISE = "enterprise"
    CUSTOM = "custom"


class SIEMProvider(str, Enum):
    """Supported SIEM providers."""
    SPLUNK = "splunk"
    ELASTICSEARCH = "elasticsearch"
    SENTINEL = "azure_sentinel"
    QRADAR = "qradar"
    CHRONICLE = "chronicle"
    CUSTOM = "custom"


class IncidentSeverity(str, Enum):
    """Incident severity levels."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class IncidentStatus(str, Enum):
    """Incident status values."""
    OPEN = "open"
    INVESTIGATING = "investigating"
    MITIGATED = "mitigated"
    RESOLVED = "resolved"
    CLOSED = "closed"


class IOCStatus(str, Enum):
    """IOC status values."""
    ACTIVE = "active"
    EXPIRED = "expired"
    RETIRED = "retired"


# ---------------------------------------------------------------------------
# Core models
# ---------------------------------------------------------------------------

@dataclass
class HealthStatus:
    """Health check response."""
    status: str
    version: str
    uptime_seconds: int
    components: Dict[str, str] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "HealthStatus":
        return cls(
            status=data.get("status", "unknown"),
            version=data.get("version", ""),
            uptime_seconds=data.get("uptime_seconds", 0),
            components=data.get("components", {}),
        )


@dataclass
class VersionInfo:
    """Version information."""
    version: str
    go_version: str
    platform: str
    build_date: Optional[datetime] = None
    git_commit: Optional[str] = None

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "VersionInfo":
        build_date = None
        if data.get("build_date"):
            build_date = datetime.fromisoformat(data["build_date"])
        return cls(
            version=data.get("version", ""),
            go_version=data.get("go_version", ""),
            platform=data.get("platform", ""),
            build_date=build_date,
            git_commit=data.get("git_commit"),
        )


@dataclass
class Module:
    """Module information."""
    name: str
    version: str
    enabled: bool
    tier: int
    description: Optional[str] = None

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Module":
        return cls(
            name=data.get("name", ""),
            version=data.get("version", ""),
            enabled=data.get("enabled", False),
            tier=data.get("tier", 0),
            description=data.get("description"),
        )


@dataclass
class License:
    """License information."""
    type: LicenseType
    customer_id: str
    expires_at: Optional[datetime] = None
    features: List[str] = field(default_factory=list)
    tier: str = "community"
    valid: bool = False

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "License":
        expires_at = None
        if data.get("expires_at"):
            expires_at = datetime.fromisoformat(data["expires_at"])
        return cls(
            type=LicenseType(data.get("type", "community")),
            customer_id=data.get("customer_id", ""),
            expires_at=expires_at,
            features=data.get("features", []),
            tier=data.get("tier", "community"),
            valid=data.get("valid", False),
        )


@dataclass
class TierInfo:
    """Tier/feature information."""
    tier: str
    features: List[str] = field(default_factory=list)
    limits: Dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "TierInfo":
        return cls(
            tier=data.get("tier", "community"),
            features=data.get("features", []),
            limits=data.get("limits", {}),
        )


@dataclass
class CertInfo:
    """TLS certificate information."""
    subject: str
    issuer: str
    not_before: Optional[datetime] = None
    not_after: Optional[datetime] = None
    fingerprint: Optional[str] = None
    serial_number: Optional[str] = None

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "CertInfo":
        not_before = None
        if data.get("not_before"):
            not_before = datetime.fromisoformat(data["not_before"])
        not_after = None
        if data.get("not_after"):
            not_after = datetime.fromisoformat(data["not_after"])
        return cls(
            subject=data.get("subject", ""),
            issuer=data.get("issuer", ""),
            not_before=not_before,
            not_after=not_after,
            fingerprint=data.get("fingerprint"),
            serial_number=data.get("serial_number"),
        )


# ---------------------------------------------------------------------------
# Violation / Detection
# ---------------------------------------------------------------------------

@dataclass
class Violation:
    """Security violation details."""
    id: str
    type: ViolationType
    severity: ViolationSeverity
    message: str
    timestamp: datetime
    source_ip: Optional[str] = None
    user_id: Optional[str] = None
    request_id: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Violation":
        timestamp = datetime.fromisoformat(data.get("timestamp", datetime.utcnow().isoformat()))
        return cls(
            id=data.get("id", ""),
            type=ViolationType(data.get("type", "prompt_injection")),
            severity=ViolationSeverity(data.get("severity", "medium")),
            message=data.get("message", ""),
            timestamp=timestamp,
            source_ip=data.get("source_ip"),
            user_id=data.get("user_id"),
            request_id=data.get("request_id"),
            metadata=data.get("metadata", {}),
        )


@dataclass
class DetectionResult:
    """Security detection result."""
    detected: bool
    confidence: float
    violations: List[Violation] = field(default_factory=list)
    processing_time_ms: float = 0.0
    detector_type: str = "unknown"

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "DetectionResult":
        violations = [Violation.from_dict(v) for v in data.get("violations", [])]
        return cls(
            detected=data.get("detected", False),
            confidence=data.get("confidence", 0.0),
            violations=violations,
            processing_time_ms=data.get("processing_time_ms", 0.0),
            detector_type=data.get("detector_type", "unknown"),
        )


@dataclass
class AnomalyResult:
    """ML anomaly detection result."""
    is_anomaly: bool
    anomaly_score: float
    baseline_score: float
    deviation: float
    features: Dict[str, float] = field(default_factory=dict)
    recommendation: Optional[str] = None

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "AnomalyResult":
        return cls(
            is_anomaly=data.get("is_anomaly", False),
            anomaly_score=data.get("anomaly_score", 0.0),
            baseline_score=data.get("baseline_score", 0.0),
            deviation=data.get("deviation", 0.0),
            features=data.get("features", {}),
            recommendation=data.get("recommendation"),
        )


@dataclass
class ProxyStats:
    """Proxy statistics."""
    requests_total: int
    requests_blocked: int
    requests_allowed: int
    avg_latency_ms: float
    violations_detected: int
    uptime_seconds: int

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ProxyStats":
        return cls(
            requests_total=data.get("requests_total", 0),
            requests_blocked=data.get("requests_blocked", 0),
            requests_allowed=data.get("requests_allowed", 0),
            avg_latency_ms=data.get("avg_latency_ms", 0.0),
            violations_detected=data.get("violations_detected", 0),
            uptime_seconds=data.get("uptime_seconds", 0),
        )


# ---------------------------------------------------------------------------
# Compliance
# ---------------------------------------------------------------------------

@dataclass
class ComplianceControl:
    """Compliance control definition."""
    id: str
    name: str
    description: str
    category: str
    severity: str
    automated: bool
    framework: str

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ComplianceControl":
        return cls(
            id=data.get("id", ""),
            name=data.get("name", ""),
            description=data.get("description", ""),
            category=data.get("category", ""),
            severity=data.get("severity", "medium"),
            automated=data.get("automated", False),
            framework=data.get("framework", ""),
        )


@dataclass
class ComplianceResult:
    """Compliance check result."""
    framework: str
    compliant: bool
    score: float
    controls_passed: int
    controls_failed: int
    controls_total: int
    failures: List[Dict[str, Any]] = field(default_factory=list)
    checked_at: datetime = field(default_factory=datetime.utcnow)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ComplianceResult":
        checked_at = datetime.utcnow()
        if data.get("checked_at"):
            checked_at = datetime.fromisoformat(data["checked_at"])
        return cls(
            framework=data.get("framework", ""),
            compliant=data.get("compliant", False),
            score=data.get("score", 0.0),
            controls_passed=data.get("controls_passed", 0),
            controls_failed=data.get("controls_failed", 0),
            controls_total=data.get("controls_total", 0),
            failures=data.get("failures", []),
            checked_at=checked_at,
        )


@dataclass
class ScanReport:
    """Security scan report."""
    id: str
    target: str
    status: str
    findings: List[Dict[str, Any]] = field(default_factory=list)
    score: float = 0.0
    created_at: Optional[datetime] = None

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ScanReport":
        created_at = None
        if data.get("created_at"):
            created_at = datetime.fromisoformat(data["created_at"])
        return cls(
            id=data.get("id", ""),
            target=data.get("target", ""),
            status=data.get("status", ""),
            findings=data.get("findings", []),
            score=data.get("score", 0.0),
            created_at=created_at,
        )


@dataclass
class ComplianceReport:
    """Compliance report."""
    id: str
    framework: str
    compliant: bool
    score: float
    controls_total: int
    controls_passed: int
    controls_failed: int
    generated_at: Optional[datetime] = None

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ComplianceReport":
        generated_at = None
        if data.get("generated_at"):
            generated_at = datetime.fromisoformat(data["generated_at"])
        return cls(
            id=data.get("id", ""),
            framework=data.get("framework", ""),
            compliant=data.get("compliant", False),
            score=data.get("score", 0.0),
            controls_total=data.get("controls_total", 0),
            controls_passed=data.get("controls_passed", 0),
            controls_failed=data.get("controls_failed", 0),
            generated_at=generated_at,
        )


@dataclass
class ComplianceIntegrity:
    """Compliance integrity verification result."""
    valid: bool
    hash: str
    verified_at: Optional[datetime] = None
    details: Dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ComplianceIntegrity":
        verified_at = None
        if data.get("verified_at"):
            verified_at = datetime.fromisoformat(data["verified_at"])
        return cls(
            valid=data.get("valid", False),
            hash=data.get("hash", ""),
            verified_at=verified_at,
            details=data.get("details", {}),
        )


@dataclass
class EvidenceResult:
    """Evidence collection result."""
    id: str
    control_id: str
    status: str
    evidence: Dict[str, Any] = field(default_factory=dict)
    collected_at: Optional[datetime] = None

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "EvidenceResult":
        collected_at = None
        if data.get("collected_at"):
            collected_at = datetime.fromisoformat(data["collected_at"])
        return cls(
            id=data.get("id", ""),
            control_id=data.get("control_id", ""),
            status=data.get("status", ""),
            evidence=data.get("evidence", {}),
            collected_at=collected_at,
        )


# ---------------------------------------------------------------------------
# Trust
# ---------------------------------------------------------------------------

@dataclass
class TrustDashboard:
    """Trust dashboard data."""
    overall_score: float
    compliance_score: float
    security_score: float
    transparency_score: float
    last_updated: Optional[datetime] = None

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "TrustDashboard":
        last_updated = None
        if data.get("last_updated"):
            last_updated = datetime.fromisoformat(data["last_updated"])
        return cls(
            overall_score=data.get("overall_score", 0.0),
            compliance_score=data.get("compliance_score", 0.0),
            security_score=data.get("security_score", 0.0),
            transparency_score=data.get("transparency_score", 0.0),
            last_updated=last_updated,
        )


@dataclass
class TrustScore:
    """Trust score for a specific dimension."""
    dimension: str
    score: float
    trend: str
    details: Dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "TrustScore":
        return cls(
            dimension=data.get("dimension", ""),
            score=data.get("score", 0.0),
            trend=data.get("trend", "stable"),
            details=data.get("details", {}),
        )


@dataclass
class TrustAnomaly:
    """Trust anomaly detection result."""
    id: str
    dimension: str
    severity: str
    description: str
    detected_at: Optional[datetime] = None

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "TrustAnomaly":
        detected_at = None
        if data.get("detected_at"):
            detected_at = datetime.fromisoformat(data["detected_at"])
        return cls(
            id=data.get("id", ""),
            dimension=data.get("dimension", ""),
            severity=data.get("severity", "medium"),
            description=data.get("description", ""),
            detected_at=detected_at,
        )


@dataclass
class TrustCompliance:
    """Trust compliance mapping."""
    framework: str
    score: float
    controls_total: int
    controls_passed: int
    controls_failed: int

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "TrustCompliance":
        return cls(
            framework=data.get("framework", ""),
            score=data.get("score", 0.0),
            controls_total=data.get("controls_total", 0),
            controls_passed=data.get("controls_passed", 0),
            controls_failed=data.get("controls_failed", 0),
        )


# ---------------------------------------------------------------------------
# Analytics
# ---------------------------------------------------------------------------

@dataclass
class AnalyticsUsage:
    """API usage analytics."""
    period: str
    total_requests: int
    blocked_requests: int
    allowed_requests: int
    by_model: Dict[str, int] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "AnalyticsUsage":
        return cls(
            period=data.get("period", ""),
            total_requests=data.get("total_requests", 0),
            blocked_requests=data.get("blocked_requests", 0),
            allowed_requests=data.get("allowed_requests", 0),
            by_model=data.get("by_model", {}),
        )


@dataclass
class AnalyticsCost:
    """Cost analytics."""
    period: str
    total_cost: float
    currency: str
    breakdown: Dict[str, float] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "AnalyticsCost":
        return cls(
            period=data.get("period", ""),
            total_cost=data.get("total_cost", 0.0),
            currency=data.get("currency", "USD"),
            breakdown=data.get("breakdown", {}),
        )


@dataclass
class AnalyticsAnomalies:
    """Anomaly analytics."""
    period: str
    anomaly_count: int
    severity_distribution: Dict[str, int] = field(default_factory=dict)
    top_anomalies: List[Dict[str, Any]] = field(default_factory=list)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "AnalyticsAnomalies":
        return cls(
            period=data.get("period", ""),
            anomaly_count=data.get("anomaly_count", 0),
            severity_distribution=data.get("severity_distribution", {}),
            top_anomalies=data.get("top_anomalies", []),
        )


@dataclass
class AnalyticsDashboard:
    """Analytics dashboard aggregate."""
    usage: AnalyticsUsage
    cost: AnalyticsCost
    anomalies: AnalyticsAnomalies

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "AnalyticsDashboard":
        return cls(
            usage=AnalyticsUsage.from_dict(data.get("usage", {})),
            cost=AnalyticsCost.from_dict(data.get("cost", {})),
            anomalies=AnalyticsAnomalies.from_dict(data.get("anomalies", {})),
        )


# ---------------------------------------------------------------------------
# Guardrails / Bridge / Cluster / Persistence
# ---------------------------------------------------------------------------

@dataclass
class GuardrailsResult:
    """Guardrails evaluation result."""
    allowed: bool
    violations: List[str] = field(default_factory=list)
    policy_id: Optional[str] = None
    confidence: float = 0.0

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "GuardrailsResult":
        return cls(
            allowed=data.get("allowed", False),
            violations=data.get("violations", []),
            policy_id=data.get("policy_id"),
            confidence=data.get("confidence", 0.0),
        )


@dataclass
class BridgeResult:
    """Bridge operation result."""
    bridge_id: str
    status: str
    source: str
    destination: str
    latency_ms: float = 0.0

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "BridgeResult":
        return cls(
            bridge_id=data.get("bridge_id", ""),
            status=data.get("status", ""),
            source=data.get("source", ""),
            destination=data.get("destination", ""),
            latency_ms=data.get("latency_ms", 0.0),
        )


@dataclass
class ClusterHealth:
    """Cluster health status."""
    node_id: str
    status: str
    role: str
    uptime_seconds: int
    connections: int = 0
    memory_usage: float = 0.0

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ClusterHealth":
        return cls(
            node_id=data.get("node_id", ""),
            status=data.get("status", ""),
            role=data.get("role", ""),
            uptime_seconds=data.get("uptime_seconds", 0),
            connections=data.get("connections", 0),
            memory_usage=data.get("memory_usage", 0.0),
        )


@dataclass
class PersistenceResult:
    """Persistence operation result."""
    key: str
    value: str
    stored_at: Optional[datetime] = None

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "PersistenceResult":
        stored_at = None
        if data.get("stored_at"):
            stored_at = datetime.fromisoformat(data["stored_at"])
        return cls(
            key=data.get("key", ""),
            value=data.get("value", ""),
            stored_at=stored_at,
        )


# ---------------------------------------------------------------------------
# Audit / Policy / SLA / SIEM / License
# ---------------------------------------------------------------------------

@dataclass
class AuditEntry:
    """Audit log entry."""
    id: str
    action: str
    actor: str
    resource: str
    timestamp: Optional[datetime] = None
    outcome: str = "success"
    details: Dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "AuditEntry":
        timestamp = None
        if data.get("timestamp"):
            timestamp = datetime.fromisoformat(data["timestamp"])
        return cls(
            id=data.get("id", ""),
            action=data.get("action", ""),
            actor=data.get("actor", ""),
            resource=data.get("resource", ""),
            timestamp=timestamp,
            outcome=data.get("outcome", "success"),
            details=data.get("details", {}),
        )


@dataclass
class Policy:
    """Security policy definition."""
    id: str
    name: str
    description: str
    enabled: bool
    rules: List[Dict[str, Any]] = field(default_factory=list)
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Policy":
        created_at = None
        if data.get("created_at"):
            created_at = datetime.fromisoformat(data["created_at"])
        updated_at = None
        if data.get("updated_at"):
            updated_at = datetime.fromisoformat(data["updated_at"])
        return cls(
            id=data.get("id", ""),
            name=data.get("name", ""),
            description=data.get("description", ""),
            enabled=data.get("enabled", True),
            rules=data.get("rules", []),
            created_at=created_at,
            updated_at=updated_at,
        )


@dataclass
class SLAInfo:
    """SLA information."""
    tier: str
    uptime_guarantee: float
    response_time_ms: int
    support_level: str
    features: List[str] = field(default_factory=list)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "SLAInfo":
        return cls(
            tier=data.get("tier", "community"),
            uptime_guarantee=data.get("uptime_guarantee", 99.9),
            response_time_ms=data.get("response_time_ms", 1000),
            support_level=data.get("support_level", "standard"),
            features=data.get("features", []),
        )


@dataclass
class SIEMConfig:
    """SIEM integration configuration."""
    provider: SIEMProvider
    endpoint: str
    api_key: Optional[str] = None
    enabled: bool = True
    batch_size: int = 100
    flush_interval_seconds: int = 30
    custom_headers: Dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "provider": self.provider.value,
            "endpoint": self.endpoint,
            "api_key": self.api_key,
            "enabled": self.enabled,
            "batch_size": self.batch_size,
            "flush_interval_seconds": self.flush_interval_seconds,
            "custom_headers": self.custom_headers,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "SIEMConfig":
        return cls(
            provider=SIEMProvider(data.get("provider", "custom")),
            endpoint=data.get("endpoint", ""),
            api_key=data.get("api_key"),
            enabled=data.get("enabled", True),
            batch_size=data.get("batch_size", 100),
            flush_interval_seconds=data.get("flush_interval_seconds", 30),
            custom_headers=data.get("custom_headers", {}),
        )


@dataclass
class SIEMEvent:
    """SIEM event for logging."""
    event_type: str
    timestamp: datetime
    severity: str
    source: str
    message: str
    details: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "event_type": self.event_type,
            "timestamp": self.timestamp.isoformat(),
            "severity": self.severity,
            "source": self.source,
            "message": self.message,
            "details": self.details,
        }


@dataclass
class SIEMStatus:
    """SIEM integration status."""
    integration_id: str
    provider: str
    status: str
    last_event_at: Optional[datetime] = None
    events_sent: int = 0

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "SIEMStatus":
        last_event_at = None
        if data.get("last_event_at"):
            last_event_at = datetime.fromisoformat(data["last_event_at"])
        return cls(
            integration_id=data.get("integration_id", ""),
            provider=data.get("provider", ""),
            status=data.get("status", ""),
            last_event_at=last_event_at,
            events_sent=data.get("events_sent", 0),
        )


@dataclass
class LicenseStatus:
    """License status information."""
    valid: bool
    tier: str
    expires_at: Optional[datetime] = None
    features: List[str] = field(default_factory=list)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "LicenseStatus":
        expires_at = None
        if data.get("expires_at"):
            expires_at = datetime.fromisoformat(data["expires_at"])
        return cls(
            valid=data.get("valid", False),
            tier=data.get("tier", "community"),
            expires_at=expires_at,
            features=data.get("features", []),
        )


# ---------------------------------------------------------------------------
# Attestation / AIBOM / A2A / Digest
# ---------------------------------------------------------------------------

@dataclass
class AttestationRequest:
    """Attestation verification request."""
    model_id: str
    version: Optional[str] = None
    evidence: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        d: Dict[str, Any] = {"model_id": self.model_id}
        if self.version:
            d["version"] = self.version
        d["evidence"] = self.evidence
        return d


@dataclass
class AttestationResult:
    """Attestation verification result."""
    verified: bool
    model_id: str
    score: float
    details: Dict[str, Any] = field(default_factory=dict)
    certificate: Optional[str] = None

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "AttestationResult":
        return cls(
            verified=data.get("verified", False),
            model_id=data.get("model_id", ""),
            score=data.get("score", 0.0),
            details=data.get("details", {}),
            certificate=data.get("certificate"),
        )


@dataclass
class AIBOMGenerateRequest:
    """AI BOM generation request."""
    model_id: str
    version: Optional[str] = None
    include_dependencies: bool = True
    format: str = "json"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "model_id": self.model_id,
            "version": self.version,
            "include_dependencies": self.include_dependencies,
            "format": self.format,
        }


@dataclass
class AIBOMVerifyResult:
    """AI BOM verification result."""
    valid: bool
    model_id: str
    bom_hash: str
    components: List[Dict[str, Any]] = field(default_factory=list)
    verified_at: Optional[datetime] = None

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "AIBOMVerifyResult":
        verified_at = None
        if data.get("verified_at"):
            verified_at = datetime.fromisoformat(data["verified_at"])
        return cls(
            valid=data.get("valid", False),
            model_id=data.get("model_id", ""),
            bom_hash=data.get("bom_hash", ""),
            components=data.get("components", []),
            verified_at=verified_at,
        )


@dataclass
class A2AIntentSignRequest:
    """A2A intent signing request."""
    agent_id: str
    intent: str
    payload: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "agent_id": self.agent_id,
            "intent": self.intent,
            "payload": self.payload,
        }


@dataclass
class A2AIntentVerifyRequest:
    """A2A intent verification request."""
    token: str
    agent_id: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        d: Dict[str, Any] = {"token": self.token}
        if self.agent_id:
            d["agent_id"] = self.agent_id
        return d


@dataclass
class A2AIntentResult:
    """A2A intent operation result."""
    valid: bool
    agent_id: str
    intent: str
    token: Optional[str] = None
    expires_at: Optional[datetime] = None

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "A2AIntentResult":
        expires_at = None
        if data.get("expires_at"):
            expires_at = datetime.fromisoformat(data["expires_at"])
        return cls(
            valid=data.get("valid", False),
            agent_id=data.get("agent_id", ""),
            intent=data.get("intent", ""),
            token=data.get("token"),
            expires_at=expires_at,
        )


@dataclass
class DigestGenerateRequest:
    """Digest generation request."""
    data: str
    algorithm: str = "sha256"

    def to_dict(self) -> Dict[str, Any]:
        return {"data": self.data, "algorithm": self.algorithm}


@dataclass
class DigestVerifyRequest:
    """Digest verification request."""
    data: str
    digest: str
    algorithm: str = "sha256"

    def to_dict(self) -> Dict[str, Any]:
        return {"data": self.data, "digest": self.digest, "algorithm": self.algorithm}


@dataclass
class DigestResult:
    """Digest operation result."""
    digest: str
    algorithm: str
    verified: bool = False

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "DigestResult":
        return cls(
            digest=data.get("digest", ""),
            algorithm=data.get("algorithm", "sha256"),
            verified=data.get("verified", False),
        )


# ---------------------------------------------------------------------------
# Incident / Evaluator
# ---------------------------------------------------------------------------

@dataclass
class IncidentCreate:
    """Incident creation request."""
    title: str
    severity: IncidentSeverity
    description: Optional[str] = None
    assignee: Optional[str] = None
    tags: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        d: Dict[str, Any] = {
            "title": self.title,
            "severity": self.severity.value,
        }
        if self.description:
            d["description"] = self.description
        if self.assignee:
            d["assignee"] = self.assignee
        d["tags"] = self.tags
        return d


@dataclass
class Incident:
    """Incident record."""
    id: str
    title: str
    severity: IncidentSeverity
    status: IncidentStatus
    description: Optional[str] = None
    assignee: Optional[str] = None
    tags: List[str] = field(default_factory=list)
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Incident":
        created_at = None
        if data.get("created_at"):
            created_at = datetime.fromisoformat(data["created_at"])
        updated_at = None
        if data.get("updated_at"):
            updated_at = datetime.fromisoformat(data["updated_at"])
        return cls(
            id=data.get("id", ""),
            title=data.get("title", ""),
            severity=IncidentSeverity(data.get("severity", "medium")),
            status=IncidentStatus(data.get("status", "open")),
            description=data.get("description"),
            assignee=data.get("assignee"),
            tags=data.get("tags", []),
            created_at=created_at,
            updated_at=updated_at,
        )


@dataclass
class IncidentTriage:
    """Incident triage result."""
    incident_id: str
    priority: str
    category: str
    recommended_actions: List[str] = field(default_factory=list)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "IncidentTriage":
        return cls(
            incident_id=data.get("incident_id", ""),
            priority=data.get("priority", "medium"),
            category=data.get("category", ""),
            recommended_actions=data.get("recommended_actions", []),
        )


@dataclass
class IncidentResolve:
    """Incident resolution request."""
    incident_id: str
    resolution: str
    root_cause: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        d: Dict[str, Any] = {
            "incident_id": self.incident_id,
            "resolution": self.resolution,
        }
        if self.root_cause:
            d["root_cause"] = self.root_cause
        return d


@dataclass
class EvaluatorRunRequest:
    """Evaluator run request."""
    model_id: str
    dataset: str
    metrics: List[str] = field(default_factory=list)
    config: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "model_id": self.model_id,
            "dataset": self.dataset,
            "metrics": self.metrics,
            "config": self.config,
        }


@dataclass
class EvaluatorVerifyRequest:
    """Evaluator verification request."""
    result_id: str
    criteria: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {"result_id": self.result_id, "criteria": self.criteria}


@dataclass
class EvaluatorResult:
    """Evaluator result."""
    id: str
    model_id: str
    dataset: str
    status: str
    metrics: Dict[str, float] = field(default_factory=dict)
    created_at: Optional[datetime] = None

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "EvaluatorResult":
        created_at = None
        if data.get("created_at"):
            created_at = datetime.fromisoformat(data["created_at"])
        return cls(
            id=data.get("id", ""),
            model_id=data.get("model_id", ""),
            dataset=data.get("dataset", ""),
            status=data.get("status", ""),
            metrics=data.get("metrics", {}),
            created_at=created_at,
        )


# ---------------------------------------------------------------------------
# ML Shadow Metrics
# ---------------------------------------------------------------------------

@dataclass
class MLShadowMetrics:
    """ML shadow model metrics."""
    TP: int = 0
    TN: int = 0
    FP: int = 0
    FN: int = 0
    Precision: float = 0.0
    Recall: float = 0.0
    F1: float = 0.0
    AUROC: float = 0.0
    TotalPredictions: int = 0
    Threshold: float = 0.5
    ModelVersion: str = ""

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "MLShadowMetrics":
        return cls(
            TP=data.get("TP", 0),
            TN=data.get("TN", 0),
            FP=data.get("FP", 0),
            FN=data.get("FN", 0),
            Precision=data.get("Precision", 0.0),
            Recall=data.get("Recall", 0.0),
            F1=data.get("F1", 0.0),
            AUROC=data.get("AUROC", 0.0),
            TotalPredictions=data.get("TotalPredictions", 0),
            Threshold=data.get("Threshold", 0.5),
            ModelVersion=data.get("ModelVersion", ""),
        )


# ---------------------------------------------------------------------------
# IOC / TSA / Webhook / User / ATLAS
# ---------------------------------------------------------------------------

@dataclass
class IOCManifest:
    """Indicator of Compromise manifest."""
    id: str
    indicators: List[Dict[str, Any]] = field(default_factory=list)
    source: str = ""
    created_at: Optional[datetime] = None

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "IOCManifest":
        created_at = None
        if data.get("created_at"):
            created_at = datetime.fromisoformat(data["created_at"])
        return cls(
            id=data.get("id", ""),
            indicators=data.get("indicators", []),
            source=data.get("source", ""),
            created_at=created_at,
        )


@dataclass
class IOCStatus:
    """IOC status information."""
    healthy: bool
    total_indicators: int
    last_sync: Optional[datetime] = None
    errors: List[str] = field(default_factory=list)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "IOCStatus":
        last_sync = None
        if data.get("last_sync"):
            last_sync = datetime.fromisoformat(data["last_sync"])
        return cls(
            healthy=data.get("healthy", False),
            total_indicators=data.get("total_indicators", 0),
            last_sync=last_sync,
            errors=data.get("errors", []),
        )


@dataclass
class TSAStatus:
    """Time Stamp Authority status."""
    available: bool
    url: str
    last_stamp: Optional[datetime] = None
    certificate_valid: bool = False

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "TSAStatus":
        last_stamp = None
        if data.get("last_stamp"):
            last_stamp = datetime.fromisoformat(data["last_stamp"])
        return cls(
            available=data.get("available", False),
            url=data.get("url", ""),
            last_stamp=last_stamp,
            certificate_valid=data.get("certificate_valid", False),
        )


@dataclass
class Webhook:
    """Webhook configuration."""
    id: str
    url: str
    events: List[str] = field(default_factory=list)
    secret: Optional[str] = None
    enabled: bool = True
    created_at: Optional[datetime] = None
    last_triggered: Optional[datetime] = None

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Webhook":
        created_at = None
        if data.get("created_at"):
            created_at = datetime.fromisoformat(data["created_at"])
        last_triggered = None
        if data.get("last_triggered"):
            last_triggered = datetime.fromisoformat(data["last_triggered"])
        return cls(
            id=data.get("id", ""),
            url=data.get("url", ""),
            events=data.get("events", []),
            secret=data.get("secret"),
            enabled=data.get("enabled", True),
            created_at=created_at,
            last_triggered=last_triggered,
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "url": self.url,
            "events": self.events,
            "secret": self.secret,
            "enabled": self.enabled,
        }


@dataclass
class User:
    """User information."""
    id: str
    email: str
    name: Optional[str] = None
    roles: List[str] = field(default_factory=list)
    created_at: Optional[datetime] = None
    last_login: Optional[datetime] = None

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "User":
        created_at = None
        if data.get("created_at"):
            created_at = datetime.fromisoformat(data["created_at"])
        last_login = None
        if data.get("last_login"):
            last_login = datetime.fromisoformat(data["last_login"])
        return cls(
            id=data.get("id", ""),
            email=data.get("email", ""),
            name=data.get("name"),
            roles=data.get("roles", []),
            created_at=created_at,
            last_login=last_login,
        )


@dataclass
class ATLASThreat:
    """MITRE ATLAS threat definition."""
    id: str
    name: str
    description: str
    tactics: List[str] = field(default_factory=list)
    platforms: List[str] = field(default_factory=list)
    detection_patterns: List[str] = field(default_factory=list)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ATLASThreat":
        return cls(
            id=data.get("id", ""),
            name=data.get("name", ""),
            description=data.get("description", ""),
            tactics=data.get("tactics", []),
            platforms=data.get("platforms", []),
            detection_patterns=data.get("detection_patterns", []),
        )


# ---------------------------------------------------------------------------
# Exports
# ---------------------------------------------------------------------------

__all__ = [
    # Enums
    "ViolationSeverity",
    "ViolationType",
    "LicenseType",
    "SIEMProvider",
    "IncidentSeverity",
    "IncidentStatus",
    "IOCStatus",
    # Core
    "HealthStatus",
    "VersionInfo",
    "Module",
    "License",
    "TierInfo",
    "CertInfo",
    # Violation / Detection
    "Violation",
    "DetectionResult",
    "AnomalyResult",
    "ProxyStats",
    # Compliance
    "ComplianceControl",
    "ComplianceResult",
    "ScanReport",
    "ComplianceReport",
    "ComplianceIntegrity",
    "EvidenceResult",
    # Trust
    "TrustDashboard",
    "TrustScore",
    "TrustAnomaly",
    "TrustCompliance",
    # Analytics
    "AnalyticsUsage",
    "AnalyticsCost",
    "AnalyticsAnomalies",
    "AnalyticsDashboard",
    # Guardrails / Bridge / Cluster / Persistence
    "GuardrailsResult",
    "BridgeResult",
    "ClusterHealth",
    "PersistenceResult",
    # Audit / Policy / SLA / SIEM / License
    "AuditEntry",
    "Policy",
    "SLAInfo",
    "SIEMConfig",
    "SIEMEvent",
    "SIEMStatus",
    "LicenseStatus",
    # Attestation / AIBOM / A2A / Digest
    "AttestationRequest",
    "AttestationResult",
    "AIBOMGenerateRequest",
    "AIBOMVerifyResult",
    "A2AIntentSignRequest",
    "A2AIntentVerifyRequest",
    "A2AIntentResult",
    "DigestGenerateRequest",
    "DigestVerifyRequest",
    "DigestResult",
    # Incident / Evaluator
    "IncidentCreate",
    "Incident",
    "IncidentTriage",
    "IncidentResolve",
    "EvaluatorRunRequest",
    "EvaluatorVerifyRequest",
    "EvaluatorResult",
    # ML
    "MLShadowMetrics",
    # IOC / TSA
    "IOCManifest",
    "IOCStatus",
    "TSAStatus",
    # Misc
    "Webhook",
    "User",
    "ATLASThreat",
]
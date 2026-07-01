"""SentinelOne Ingestion Service — fetch threats from SentinelOne REST API v2.1."""

import asyncio
import logging
import os
from datetime import datetime
from typing import Any, Dict, List, Optional

import requests

from core.config import get_integration_config
from services.siem_ingestion_service import SIEMIngestionService

logger = logging.getLogger(__name__)

_CONFIDENCE_SEVERITY = {
    "malicious": "high",
    "suspicious": "medium",
}

# Bump to critical for known high-impact classification types
_CRITICAL_CLASSIFICATIONS = frozenset(
    {"Ransomware", "Rootkit", "Exploit", "ExploitKit"}
)


def _extract_mitigation(raw: Any) -> str:
    """Return a plain mitigation-status string from either API layout.

    v2.1 returns a list of dicts with a ``status`` key; v2.0 returns a
    plain string. Both may appear at root level or inside ``threatInfo``.
    """
    if isinstance(raw, list) and raw:
        first = raw[0]
        return first.get("status", "") if isinstance(first, dict) else str(first)
    if isinstance(raw, str):
        return raw
    return ""


class SentinelOneIngestion(SIEMIngestionService):
    """Fetches threats from SentinelOne Management API v2.1.

    Credentials are read from the integration config stored by the Settings UI:
      console_url — the management console base URL
      api_token   — the API token with Threats → View permission
    """

    def __init__(self) -> None:
        super().__init__()
        self.siem_name = "SentinelOne"

    def _credentials(self):
        """Read credentials fresh each call so secrets restored after init work."""
        cfg = get_integration_config("sentinelone")
        url = (
            cfg.get("console_url")
            or cfg.get("url")
            or os.environ.get("SENTINELONE_CONSOLE_URL")
            or ""
        ).rstrip("/")
        token = (
            cfg.get("api_token")
            or cfg.get("token")
            or os.environ.get("SENTINELONE_API_TOKEN")
            or ""
        )
        # Daemon may start before the backend writes secrets.enc. If both values
        # are still empty, attempt one lazy reload from the encrypted store.
        if not url or not token:
            try:
                from services.integration_secrets import restore_all_integration_secrets
                restore_all_integration_secrets()
                url = (os.environ.get("SENTINELONE_CONSOLE_URL") or "").rstrip("/")
                token = os.environ.get("SENTINELONE_API_TOKEN") or ""
            except Exception:
                pass
        return url, token

    def _headers(self) -> Dict[str, str]:
        _, token = self._credentials()
        return {
            "Authorization": f"ApiToken {token}",
            "Content-Type": "application/json",
        }

    async def fetch_alerts(
        self,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        limit: int = 1000,
    ) -> List[Dict[str, Any]]:
        """Fetch threats from SentinelOne API v2.1 with automatic pagination.

        Args:
            start_time: Only return threats created after this time.
            end_time:   Only return threats created before this time.
            limit:      Total maximum threats to return across all pages.

        Returns:
            List of raw threat dicts as returned by the API.
        """
        url, token = self._credentials()
        if not url or not token:
            logger.warning(
                "SentinelOne not configured (missing console_url or api_token)"
            )
            return []

        base_url = f"{url}/web/api/v2.1/threats"
        # SentinelOne API max per page is 1000; we page until we have `limit` total.
        per_page = min(limit, 1000)

        base_params: Dict[str, Any] = {
            "sortBy": "createdAt",
            "sortOrder": "asc",
        }
        if start_time:
            base_params["createdAt__gte"] = start_time.strftime(
                "%Y-%m-%dT%H:%M:%S.000000Z"
            )
        if end_time:
            base_params["createdAt__lte"] = end_time.strftime(
                "%Y-%m-%dT%H:%M:%S.000000Z"
            )

        all_threats: List[Dict[str, Any]] = []
        next_cursor: Optional[str] = None
        page = 0

        try:
            while len(all_threats) < limit:
                params = dict(base_params)
                params["limit"] = min(per_page, limit - len(all_threats))
                if next_cursor:
                    params["cursor"] = next_cursor

                resp = await asyncio.to_thread(
                    requests.get,
                    base_url,
                    headers=self._headers(),
                    params=params,
                    timeout=30,
                )
                resp.raise_for_status()
                body = resp.json()
                page_threats = body.get("data", [])
                pagination = body.get("pagination", {})
                all_threats.extend(page_threats)
                page += 1

                next_cursor = pagination.get("nextCursor")
                if not next_cursor or not page_threats:
                    break

            logger.info(
                "Fetched %d threats from SentinelOne (%d page(s))",
                len(all_threats),
                page,
            )
            return all_threats
        except Exception as e:
            logger.error("SentinelOne fetch_alerts failed: %s", e)
            return all_threats  # return whatever we got before the error

    def transform_alert_to_finding(
        self, threat: Dict[str, Any]
    ) -> Optional[Dict[str, Any]]:
        """Normalize a raw SentinelOne threat into the Vigil finding format.

        Handles both the v2.1 nested layout (threatInfo / agentRealtimeInfo)
        and the older flat layout where fields appear at root level, using safe
        fallback chains throughout.
        """
        threat_id = threat.get("id")
        if not threat_id:
            return None

        external_id = str(threat_id)
        finding_id = f"s1-{external_id}"

        # v2.1 nested objects — also check root level as fallback
        threat_info = threat.get("threatInfo") or {}
        agent_info = threat.get("agentRealtimeInfo") or {}
        agent_detection = threat.get("agentDetectionInfo") or {}

        threat_name = (
            threat_info.get("threatName")
            or threat.get("threatName")
            or "SentinelOne Threat"
        )
        classification = (
            threat_info.get("classification")
            or threat.get("classification")
            or ""
        )
        confidence = (
            (
                threat_info.get("confidenceLevel")
                or threat.get("confidenceLevel")
                or "n/a"
            )
            .lower()
            .strip()
        )
        created_at = (
            threat_info.get("createdAt")
            or threat.get("createdAt")
            or threat.get("createdDate")
            or datetime.utcnow().isoformat()
        )

        # Severity: malicious → high, bumped to critical for severe families
        severity = _CONFIDENCE_SEVERITY.get(confidence, "low")
        if severity == "high" and classification in _CRITICAL_CLASSIFICATIONS:
            severity = "critical"

        # mitigationStatus: list in v2.1, string in v2.0; check both locations
        mit_str = _extract_mitigation(
            threat.get("mitigationStatus") or threat_info.get("mitigationStatus")
        )

        # Entity extraction — check nested then flat
        hostname = (
            agent_info.get("agentComputerName")
            or threat.get("agentComputerName")
            or ""
        )
        username = (
            threat.get("username")
            or threat_info.get("processUser")
            or agent_info.get("username")
            or ""
        )
        ip = (
            agent_detection.get("agentIpV4")
            or agent_info.get("agentIp")
            or threat.get("agentIp")
            or ""
        )

        # File hashes — field names differ between API versions
        sha1 = threat_info.get("sha1") or threat.get("sha1") or ""
        md5 = (
            threat_info.get("md5")
            or threat_info.get("fileMd5")
            or threat.get("md5")
            or ""
        )
        sha256 = (
            threat_info.get("sha256")
            or threat_info.get("fileSha256")
            or threat.get("sha256")
            or ""
        )
        file_hashes = [h for h in [sha1, md5, sha256] if h]

        # File / process details
        file_path = threat_info.get("filePath") or threat.get("filePath") or ""
        file_name = (
            threat_info.get("fileDisplayName")
            or threat_info.get("threatName")
            or threat.get("fileDisplayName")
            or ""
        )
        process_args = (
            threat_info.get("maliciousProcessArguments")
            or threat.get("maliciousProcessArguments")
            or ""
        )
        publisher = (
            threat_info.get("publisherName") or threat.get("publisherName") or ""
        )
        initiated_by = (
            threat_info.get("initiatedBy") or threat.get("initiatedBy") or ""
        )
        detection_type = (
            threat_info.get("detectionType") or threat.get("detectionType") or ""
        )
        os_type = agent_info.get("osType") or threat.get("osType") or ""
        os_version = agent_info.get("osRevision") or threat.get("osRevision") or ""

        # Risk score: use SentinelOne's own score when available (0–10 scale → 0.0–1.0),
        # fall back to confidence-based estimate.
        raw_score = threat_info.get("riskScore") or threat.get("riskScore")
        if raw_score is not None:
            try:
                anomaly_score = float(raw_score) / 10.0
            except (TypeError, ValueError):
                anomaly_score = 0.8 if confidence == "malicious" else 0.4
        else:
            anomaly_score = 0.8 if confidence == "malicious" else 0.4

        # MITRE ATT&CK — extract from indicators array (v2.1 field)
        mitre_predictions: Dict[str, Any] = {}
        indicators = threat.get("indicators") or []
        for ind in indicators:
            technique = ind.get("mitreTechnique") or ind.get("mitreId") or ""
            tactic = ind.get("mitreTactic") or ind.get("category") or ""
            desc = ind.get("description") or ind.get("categoryName") or ""
            if technique:
                mitre_predictions[technique] = {
                    "tactic": tactic,
                    "description": desc,
                    "confidence": 1.0,
                }

        entity_context: Dict[str, Any] = {
            "src_ips": [ip] if ip else [],
            "dest_ips": [],
            "hostnames": [hostname] if hostname else [],
            "usernames": [username] if username else [],
            "file_hashes": file_hashes,
            "file_path": file_path,
            "file_name": file_name,
            "process_args": process_args,
        }

        # Build a rich description
        desc_parts = []
        if classification:
            desc_parts.append(f"Classification: {classification}")
        if detection_type:
            desc_parts.append(f"Detection type: {detection_type}")
        if hostname:
            desc_parts.append(f"Host: {hostname}")
        if os_type:
            desc_parts.append(f"OS: {os_type} {os_version}".strip())
        if username:
            desc_parts.append(f"User: {username}")
        if file_path or file_name:
            desc_parts.append(f"File: {file_path or file_name}")
        if process_args:
            desc_parts.append(f"Args: {process_args[:200]}")
        if initiated_by:
            desc_parts.append(f"Initiated by: {initiated_by}")
        if publisher:
            desc_parts.append(f"Publisher: {publisher}")
        desc_parts.append(f"Confidence: {confidence}, Mitigation: {mit_str or 'unknown'}")
        description = " | ".join(desc_parts)

        return {
            "finding_id": finding_id,
            "data_source": "sentinelone",
            "external_id": external_id,
            "timestamp": created_at,
            "severity": severity,
            "status": "new",
            "title": threat_name or classification or "SentinelOne Threat",
            "description": description[:1000],
            "entity_context": entity_context,
            "raw_event": threat,
            "anomaly_score": round(anomaly_score, 2),
            "mitre_predictions": mitre_predictions,
            "embedding": [],
            "metadata": {
                "s1_threat_id": external_id,
                "classification": classification,
                "confidence_level": confidence,
                "mitigation_status": mit_str,
                "detection_type": detection_type,
                "initiated_by": initiated_by,
                "publisher": publisher,
                "os_type": os_type,
                "os_version": os_version,
                "is_fileless": threat_info.get("isFileless") or False,
                "reboot_required": threat_info.get("rebootRequired") or False,
                "agent_id": (
                    agent_info.get("agentId") or threat.get("agentId") or ""
                ),
                "agent_version": (
                    agent_info.get("agentVersion") or threat.get("agentVersion") or ""
                ),
                "storyline_id": (
                    threat.get("storylineId") or threat_info.get("storylineId") or ""
                ),
            },
        }

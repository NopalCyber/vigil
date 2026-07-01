"""SentinelOne federation adapter."""

from __future__ import annotations

import logging
from datetime import datetime, timedelta
from typing import Any, Dict, Optional

from core.config import is_integration_enabled
from daemon.federation.adapters._base import fresh_cursor, parse_cursor_since
from daemon.federation.registry import (
    FederationAdapter,
    FetchResult,
    register_adapter,
)

logger = logging.getLogger(__name__)


class SentinelOneAdapter:
    name = "sentinelone"

    def __init__(self) -> None:
        self._service = None

    def is_configured(self) -> bool:
        return is_integration_enabled("sentinelone")

    def default_interval(self) -> int:
        return 60  # EDR cadence — matches CrowdStrike

    def _get_service(self):
        if self._service is not None:
            return self._service
        if not self.is_configured():
            return None
        try:
            from services.sentinelone_ingestion import SentinelOneIngestion

            self._service = SentinelOneIngestion()
        except Exception as e:
            logger.warning("SentinelOne service init failed: %s", e)
            self._service = None
        return self._service

    async def fetch(
        self,
        *,
        since: Optional[datetime],
        cursor: Dict[str, Any],
        max_items: int,
    ) -> FetchResult:
        svc = self._get_service()
        if svc is None:
            # Preserve the cursor — don't advance the watermark while the
            # integration is unconfigured so the backfill window is intact
            # once credentials are added.
            return FetchResult(findings=[], cursor=cursor)

        cutoff = parse_cursor_since(cursor) or since
        if cutoff is None:
            # First run — fetch last 30 days for initial backfill
            cutoff = datetime.utcnow() - timedelta(days=30)

        logger.debug("SentinelOne fetch: cursor=%s cutoff=%s", cursor, cutoff)
        try:
            threats = await svc.fetch_alerts(start_time=cutoff, limit=max_items)
        except Exception as e:
            logger.debug("SentinelOne fetch failed: %s", e)
            threats = []

        findings = []
        last_created_at: Optional[str] = None
        for threat in threats[:max_items]:
            f = svc.transform_alert_to_finding(threat)
            if f is not None:
                findings.append(f)
            # Track the latest threat timestamp to use as the next cursor so
            # partial fetches (max_items < total threats in window) continue
            # from where they left off rather than jumping to "now".
            ts = (
                threat.get("threatInfo", {}).get("createdAt")
                or threat.get("createdAt")
            )
            if ts:
                last_created_at = ts

        if threats and last_created_at:
            # Advance ONE SECOND past the last threat's createdAt.
            # SentinelOne's createdAt__gte filter is inclusive, so storing the
            # exact timestamp causes the same threat to be re-fetched on every
            # subsequent poll. Adding 1 s makes the next query strictly after
            # the last ingested event while still catching anything that arrived
            # in the same second (sub-second arrivals are rare in practice and
            # would be caught by the Redis dedup set anyway).
            ts_clean = last_created_at.rstrip("Z")
            try:
                ts_clean = (
                    datetime.fromisoformat(ts_clean) + timedelta(seconds=1)
                ).isoformat()
            except Exception:
                pass
            new_cursor: Dict[str, Any] = {"last_poll_at": ts_clean}
        elif threats:
            # Threats returned but no parseable timestamp — fall back to now.
            new_cursor = fresh_cursor()
        else:
            # Empty response — keep the current cursor intact so transient
            # API failures don't silently drop historical events.
            new_cursor = cursor

        return FetchResult(findings=findings, cursor=new_cursor)


def _factory() -> FederationAdapter:
    return SentinelOneAdapter()


register_adapter(SentinelOneAdapter.name, _factory)

"""Unit tests for services/sentinelone_ingestion.py."""

import json
import pytest
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

from services.sentinelone_ingestion import SentinelOneIngestion

FIXTURES_DIR = Path(__file__).resolve().parent.parent / "fixtures"


@pytest.fixture
def sample_threats():
    with open(FIXTURES_DIR / "sentinelone_threats.json") as f:
        return json.load(f)


@pytest.fixture
def ingestion():
    with patch("services.sentinelone_ingestion.get_integration_config") as mock_cfg:
        mock_cfg.return_value = {
            "console_url": "https://test.sentinelone.net",
            "api_token": "test-token",
        }
        svc = SentinelOneIngestion()
        svc.ingestion_service = MagicMock()
        yield svc


# ---------------------------------------------------------------------------
# transform_alert_to_finding
# ---------------------------------------------------------------------------


class TestTransformAlertToFinding:

    def test_nested_v21_layout(self, ingestion, sample_threats):
        finding = ingestion.transform_alert_to_finding(sample_threats[0])
        assert finding is not None
        assert finding["finding_id"] == "s1-threat-001-abc"
        assert finding["external_id"] == "threat-001-abc"
        assert finding["data_source"] == "sentinelone"
        assert finding["title"] == "Cobalt Strike Beacon"
        assert finding["severity"] == "high"
        assert "WORKSTATION-WIN10" in finding["entity_context"]["hostnames"]
        assert "10.1.2.3" in finding["entity_context"]["src_ips"]
        assert "SYSTEM" in finding["entity_context"]["usernames"]

    def test_ransomware_bumped_to_critical(self, ingestion, sample_threats):
        finding = ingestion.transform_alert_to_finding(sample_threats[1])
        assert finding["severity"] == "critical"
        assert finding["title"] == "WannaCry Ransomware"

    def test_suspicious_maps_to_medium(self, ingestion, sample_threats):
        finding = ingestion.transform_alert_to_finding(sample_threats[2])
        assert finding["severity"] == "medium"

    def test_flat_v20_layout_fallback(self, ingestion, sample_threats):
        # sample_threats[2] has flat layout (no threatInfo / agentRealtimeInfo)
        finding = ingestion.transform_alert_to_finding(sample_threats[2])
        assert finding is not None
        assert finding["entity_context"]["hostnames"] == ["LAPTOP-USER01"]
        assert finding["entity_context"]["src_ips"] == ["172.16.0.50"]

    def test_file_hashes_extracted(self, ingestion, sample_threats):
        finding = ingestion.transform_alert_to_finding(sample_threats[0])
        hashes = finding["entity_context"]["file_hashes"]
        assert "d41d8cd98f00b204e9800998ecf8427e" in hashes
        assert "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" in hashes

    def test_sha256_only_threat(self, ingestion, sample_threats):
        finding = ingestion.transform_alert_to_finding(sample_threats[1])
        hashes = finding["entity_context"]["file_hashes"]
        assert len(hashes) == 1
        assert hashes[0] == "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899"

    def test_metadata_fields(self, ingestion, sample_threats):
        finding = ingestion.transform_alert_to_finding(sample_threats[0])
        meta = finding["metadata"]
        assert meta["s1_threat_id"] == "threat-001-abc"
        assert meta["classification"] == "Trojan"
        assert meta["confidence_level"] == "malicious"

    def test_anomaly_score_malicious(self, ingestion, sample_threats):
        finding = ingestion.transform_alert_to_finding(sample_threats[0])
        assert finding["anomaly_score"] == 0.8

    def test_anomaly_score_suspicious(self, ingestion, sample_threats):
        finding = ingestion.transform_alert_to_finding(sample_threats[2])
        assert finding["anomaly_score"] == 0.4

    def test_missing_id_returns_none(self, ingestion):
        finding = ingestion.transform_alert_to_finding({"threatInfo": {"threatName": "X"}})
        assert finding is None

    def test_empty_dict_returns_none(self, ingestion):
        finding = ingestion.transform_alert_to_finding({})
        assert finding is None

    def test_unknown_confidence_maps_to_low(self, ingestion):
        finding = ingestion.transform_alert_to_finding({"id": "t-x", "confidenceLevel": "n/a"})
        assert finding["severity"] == "low"

    def test_description_truncated_at_500(self, ingestion):
        long_threat = {
            "id": "t-long",
            "classification": "X" * 600,
            "confidenceLevel": "suspicious",
        }
        finding = ingestion.transform_alert_to_finding(long_threat)
        assert len(finding["description"]) <= 500


# ---------------------------------------------------------------------------
# fetch_alerts
# ---------------------------------------------------------------------------


class TestFetchAlerts:

    @pytest.mark.asyncio
    async def test_returns_threats_on_success(self, ingestion, sample_threats):
        mock_resp = MagicMock()
        mock_resp.raise_for_status = MagicMock()
        mock_resp.json.return_value = {"data": sample_threats}

        with patch("asyncio.to_thread", new=AsyncMock(return_value=mock_resp)):
            alerts = await ingestion.fetch_alerts(limit=10)

        assert len(alerts) == 3

    @pytest.mark.asyncio
    async def test_returns_empty_when_not_configured(self):
        with patch("services.sentinelone_ingestion.get_integration_config") as mock_cfg:
            mock_cfg.return_value = {}
            svc = SentinelOneIngestion()
            svc.ingestion_service = MagicMock()

        alerts = await svc.fetch_alerts()
        assert alerts == []

    @pytest.mark.asyncio
    async def test_returns_empty_on_request_error(self, ingestion):
        with patch("asyncio.to_thread", new=AsyncMock(side_effect=Exception("conn refused"))):
            alerts = await ingestion.fetch_alerts()

        assert alerts == []

    @pytest.mark.asyncio
    async def test_passes_start_time_param(self, ingestion):
        from datetime import datetime

        mock_resp = MagicMock()
        mock_resp.raise_for_status = MagicMock()
        mock_resp.json.return_value = {"data": []}

        captured = {}

        async def fake_to_thread(fn, *args, **kwargs):
            captured["params"] = kwargs.get("params", {})
            return mock_resp

        with patch("asyncio.to_thread", new=fake_to_thread):
            start = datetime(2026, 6, 30, 10, 0, 0)
            await ingestion.fetch_alerts(start_time=start)

        assert "createdAt__gte" in captured["params"]
        assert "2026-06-30" in captured["params"]["createdAt__gte"]

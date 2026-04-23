from pathlib import Path

import app as threat_app
import watchman
from fastapi.testclient import TestClient
from watchman import DetectionResult, FindingStore


def seed_finding(db_path: Path) -> int:
    store = FindingStore(db_path)
    store.save_commit_metadata(
        repo_name="psf/requests",
        commit_sha="seed123",
        author_name="alice",
        commit_message="seed finding",
        html_url=None,
    )
    store.save_finding(
        "seed123",
        "requests/api.py",
        DetectionResult(
            risk="high",
            confidence=91,
            summary="Seed reverse shell finding.",
            reasons=["launches shell"],
            indicators=["socket", "/bin/sh"],
            rule_hits=["reverse-shell-pattern"],
        ),
    )
    row = store.list_findings(limit=1)[0]
    return int(row["id"])


def test_dashboard_and_api_flow(tmp_path: Path) -> None:
    db_path = tmp_path / "dashboard.db"
    alert_path = tmp_path / "alerts.jsonl"

    original_db = watchman.DATABASE_PATH
    original_alert_path = watchman.ALERTS_LOG_PATH
    original_app_db = threat_app.DATABASE_PATH
    original_app_alert = threat_app.ALERTS_LOG_PATH
    try:
        watchman.DATABASE_PATH = db_path
        watchman.ALERTS_LOG_PATH = alert_path
        threat_app.DATABASE_PATH = db_path
        threat_app.ALERTS_LOG_PATH = alert_path

        finding_id = seed_finding(db_path)
        client = TestClient(threat_app.app)

        dashboard = client.get("/")
        assert dashboard.status_code == 200
        assert "Threat Hunter Analyst Inbox" in dashboard.text

        findings = client.get("/api/findings")
        assert findings.status_code == 200
        payload = findings.json()
        assert payload["findings"][0]["id"] == finding_id

        detail = client.get(f"/api/findings/{finding_id}")
        assert detail.status_code == 200
        assert detail.json()["finding"]["risk"] == "high"

        triage = client.post(
            f"/api/findings/{finding_id}/triage",
            data={"disposition": "true_positive", "note": "Confirmed in API test"},
        )
        assert triage.status_code == 200

        updated = client.get(f"/api/findings/{finding_id}")
        assert updated.json()["finding"]["disposition"] == "true_positive"
        assert updated.json()["finding"]["analyst_note"] == "Confirmed in API test"
    finally:
        watchman.DATABASE_PATH = original_db
        watchman.ALERTS_LOG_PATH = original_alert_path
        threat_app.DATABASE_PATH = original_app_db
        threat_app.ALERTS_LOG_PATH = original_app_alert


def test_demo_scan_endpoint_creates_alert(tmp_path: Path) -> None:
    db_path = tmp_path / "demo.db"
    alert_path = tmp_path / "alerts.jsonl"

    original_db = watchman.DATABASE_PATH
    original_alert_path = watchman.ALERTS_LOG_PATH
    original_app_db = threat_app.DATABASE_PATH
    original_app_alert = threat_app.ALERTS_LOG_PATH
    try:
        watchman.DATABASE_PATH = db_path
        watchman.ALERTS_LOG_PATH = alert_path
        threat_app.DATABASE_PATH = db_path
        threat_app.ALERTS_LOG_PATH = alert_path

        client = TestClient(threat_app.app)
        response = client.post("/api/demo/test-scan")

        assert response.status_code == 200
        payload = response.json()
        assert payload["risk"] == "high"
        assert alert_path.exists()

        alerts = client.get("/api/alerts")
        assert alerts.status_code == 200
        assert len(alerts.json()["alerts"]) == 1
    finally:
        watchman.DATABASE_PATH = original_db
        watchman.ALERTS_LOG_PATH = original_alert_path
        threat_app.DATABASE_PATH = original_app_db
        threat_app.ALERTS_LOG_PATH = original_app_alert

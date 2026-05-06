from pathlib import Path

import app as threat_app
import watchman
from fastapi.testclient import TestClient
from watchman import DetectionResult, FindingStore, default_ownership_context


def ownership(
    team_slug: str,
    team_name: str,
    user_email: str,
    user_name: str,
):
    return default_ownership_context(
        team_slug=team_slug,
        team_name=team_name,
        user_email=user_email,
        user_name=user_name,
    )


def seed_finding(db_path: Path, team_slug: str, team_name: str, user_email: str, user_name: str) -> int:
    team = ownership(team_slug, team_name, user_email, user_name)
    store = FindingStore(db_path)
    store.save_commit_metadata(
        ownership=team,
        repo_name="psf/requests",
        commit_sha=f"{team_slug}-seed123",
        author_name="alice",
        commit_message="seed finding",
        html_url=None,
    )
    finding_id = store.save_finding(
        ownership=team,
        repo_name="psf/requests",
        commit_sha=f"{team_slug}-seed123",
        file_name="requests/api.py",
        result=DetectionResult(
            risk="high",
            confidence=91,
            summary=f"Seed reverse shell finding for {team_slug}.",
            reasons=["launches shell"],
            indicators=["socket", "/bin/sh"],
            rule_hits=["reverse-shell-pattern"],
        ),
    )
    return int(finding_id)


def test_dashboard_and_api_flow_are_team_scoped(tmp_path: Path) -> None:
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

        alpha_id = seed_finding(db_path, "alpha", "Alpha Team", "alpha@example.com", "Alice")
        seed_finding(db_path, "bravo", "Bravo Team", "bravo@example.com", "Bob")
        client = TestClient(threat_app.app)

        dashboard = client.get(
            "/",
            params={
                "team_slug": "alpha",
                "team_name": "Alpha Team",
                "user_email": "alpha@example.com",
                "user_name": "Alice",
            },
        )
        assert dashboard.status_code == 200
        assert "Threat Hunter Analyst Inbox" in dashboard.text
        assert "Alpha Team" in dashboard.text

        findings = client.get(
            "/api/findings",
            headers={
                "X-Team-Slug": "alpha",
                "X-Team-Name": "Alpha Team",
                "X-User-Email": "alpha@example.com",
                "X-User-Name": "Alice",
            },
        )
        assert findings.status_code == 200
        payload = findings.json()
        assert len(payload["findings"]) == 1
        assert payload["findings"][0]["id"] == alpha_id
        assert payload["findings"][0]["team_slug"] == "alpha"

        detail = client.get(
            f"/api/findings/{alpha_id}",
            headers={
                "X-Team-Slug": "alpha",
                "X-Team-Name": "Alpha Team",
                "X-User-Email": "alpha@example.com",
                "X-User-Name": "Alice",
            },
        )
        assert detail.status_code == 200
        assert detail.json()["finding"]["risk"] == "high"

        hidden_from_other_team = client.get(
            f"/api/findings/{alpha_id}",
            headers={
                "X-Team-Slug": "bravo",
                "X-Team-Name": "Bravo Team",
                "X-User-Email": "bravo@example.com",
                "X-User-Name": "Bob",
            },
        )
        assert hidden_from_other_team.status_code == 404

        triage = client.post(
            f"/api/findings/{alpha_id}/triage",
            data={
                "disposition": "true_positive",
                "note": "Confirmed in API test",
            },
            headers={
                "X-Team-Slug": "alpha",
                "X-Team-Name": "Alpha Team",
                "X-User-Email": "alpha@example.com",
                "X-User-Name": "Alice",
            },
        )
        assert triage.status_code == 200

        updated = client.get(
            f"/api/findings/{alpha_id}",
            headers={
                "X-Team-Slug": "alpha",
                "X-Team-Name": "Alpha Team",
                "X-User-Email": "alpha@example.com",
                "X-User-Name": "Alice",
            },
        )
        assert updated.json()["finding"]["disposition"] == "true_positive"
        assert updated.json()["finding"]["analyst_note"] == "Confirmed in API test"
        assert updated.json()["finding"]["triaged_by_user_email"] == "alpha@example.com"
    finally:
        watchman.DATABASE_PATH = original_db
        watchman.ALERTS_LOG_PATH = original_alert_path
        threat_app.DATABASE_PATH = original_app_db
        threat_app.ALERTS_LOG_PATH = original_app_alert


def test_session_and_demo_scan_endpoint_create_team_specific_alerts(tmp_path: Path) -> None:
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
        session = client.get(
            "/api/session",
            headers={
                "X-Team-Slug": "soc-team",
                "X-Team-Name": "SOC Team",
                "X-User-Email": "soc@example.com",
                "X-User-Name": "Sam SOC",
            },
        )
        assert session.status_code == 200
        assert session.json()["session"]["team_slug"] == "soc-team"
        assert session.json()["store_backend"] == "sqlite"

        response = client.post(
            "/api/demo/test-scan",
            headers={
                "X-Team-Slug": "soc-team",
                "X-Team-Name": "SOC Team",
                "X-User-Email": "soc@example.com",
                "X-User-Name": "Sam SOC",
            },
        )

        assert response.status_code == 200
        payload = response.json()
        assert payload["risk"] == "high"
        assert payload["team_slug"] == "soc-team"
        assert alert_path.exists()

        findings = client.get(
            "/api/findings",
            headers={
                "X-Team-Slug": "soc-team",
                "X-Team-Name": "SOC Team",
                "X-User-Email": "soc@example.com",
                "X-User-Name": "Sam SOC",
            },
        )
        assert findings.status_code == 200
        assert len(findings.json()["findings"]) == 1

        alerts = client.get("/api/alerts")
        assert alerts.status_code == 200
        assert len(alerts.json()["alerts"]) == 1
        assert alerts.json()["alerts"][0]["team_slug"] == "soc-team"
    finally:
        watchman.DATABASE_PATH = original_db
        watchman.ALERTS_LOG_PATH = original_alert_path
        threat_app.DATABASE_PATH = original_app_db
        threat_app.ALERTS_LOG_PATH = original_app_alert

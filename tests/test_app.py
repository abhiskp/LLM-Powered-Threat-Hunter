from pathlib import Path

import app as threat_app
import watchman
from fastapi.testclient import TestClient


def register_team(client: TestClient, team_slug: str, team_name: str, user_email: str, user_name: str) -> None:
    response = client.post(
        "/auth/register",
        data={
            "team_slug": team_slug,
            "team_name": team_name,
            "user_email": user_email,
            "user_name": user_name,
            "password": "hunterpass123",
            "first_repo": "psf/requests",
        },
        follow_redirects=False,
    )
    assert response.status_code == 303


def test_login_required_and_team_dashboard_flow(tmp_path: Path) -> None:
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

        anonymous = TestClient(threat_app.app)
        redirect = anonymous.get("/", follow_redirects=False)
        assert redirect.status_code == 303
        assert redirect.headers["location"] == "/login"

        client = TestClient(threat_app.app)
        register_team(client, "alpha", "Alpha Team", "alpha@example.com", "Alice")

        dashboard = client.get("/")
        assert dashboard.status_code == 200
        assert "Alpha Team" in dashboard.text
        assert "psf/requests" in dashboard.text

        session = client.get("/api/session")
        assert session.status_code == 200
        payload = session.json()
        assert payload["session"]["team_slug"] == "alpha"
        assert payload["watchlist"][0]["repo_name"] == "psf/requests"
    finally:
        watchman.DATABASE_PATH = original_db
        watchman.ALERTS_LOG_PATH = original_alert_path
        threat_app.DATABASE_PATH = original_app_db
        threat_app.ALERTS_LOG_PATH = original_app_alert


def test_watchlist_and_findings_are_scoped_by_authenticated_team(tmp_path: Path) -> None:
    db_path = tmp_path / "scoped.db"
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

        alpha = TestClient(threat_app.app)
        register_team(alpha, "alpha", "Alpha Team", "alpha@example.com", "Alice")
        alpha.post("/api/demo/test-scan")
        alpha.post("/api/watchlist", data={"repo_name": "pallets/flask"})

        bravo = TestClient(threat_app.app)
        register_team(bravo, "bravo", "Bravo Team", "bravo@example.com", "Bob")
        bravo.post("/api/demo/test-scan")

        alpha_findings = alpha.get("/api/findings")
        bravo_findings = bravo.get("/api/findings")
        assert alpha_findings.status_code == 200
        assert bravo_findings.status_code == 200
        assert len(alpha_findings.json()["findings"]) == 1
        assert len(bravo_findings.json()["findings"]) == 1
        assert alpha_findings.json()["findings"][0]["team_slug"] == "alpha"
        assert bravo_findings.json()["findings"][0]["team_slug"] == "bravo"

        alpha_watchlist = alpha.get("/api/watchlist").json()["watchlist"]
        bravo_watchlist = bravo.get("/api/watchlist").json()["watchlist"]
        assert [row["repo_name"] for row in alpha_watchlist] == ["pallets/flask", "psf/requests"]
        assert [row["repo_name"] for row in bravo_watchlist] == ["psf/requests"]

        finding_id = alpha_findings.json()["findings"][0]["id"]
        triage = alpha.post(
            f"/api/findings/{finding_id}/triage",
            data={"disposition": "true_positive", "note": "Confirmed in API test"},
        )
        assert triage.status_code == 200

        updated = alpha.get(f"/api/findings/{finding_id}")
        assert updated.status_code == 200
        assert updated.json()["finding"]["triaged_by_user_email"] == "alpha@example.com"

        deliveries = alpha.get("/api/alert-deliveries")
        assert deliveries.status_code == 200
        assert deliveries.json()["alert_deliveries"][0]["channel"] == "log"
    finally:
        watchman.DATABASE_PATH = original_db
        watchman.ALERTS_LOG_PATH = original_alert_path
        threat_app.DATABASE_PATH = original_app_db
        threat_app.ALERTS_LOG_PATH = original_app_alert


def test_settings_and_scan_run_endpoints(tmp_path: Path, monkeypatch) -> None:
    db_path = tmp_path / "settings.db"
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
        register_team(client, "delta", "Delta Team", "delta@example.com", "Dana")

        settings_update = client.post(
            "/api/settings",
            data={
                "alert_webhook_url": "https://hooks.example.test/delta",
                "alert_min_risk": "medium",
                "alert_min_confidence": "70",
                "scans_enabled": "true",
                "scan_limit": "6",
                "scan_interval_minutes": "90",
            },
        )
        assert settings_update.status_code == 200
        settings_payload = settings_update.json()["settings"]
        assert settings_payload["alert_min_risk"] == "medium"
        assert settings_payload["alert_min_confidence"] == 70
        assert settings_payload["scan_limit"] == 6
        assert settings_payload["scan_interval_minutes"] == 90

        class FakeScanService:
            def __init__(self, store=None):
                self.store = store

            def scan_watchlist_entry(self, ownership, watchlist_id, trigger_mode):
                self.store.create_scan_run(ownership, watchlist_id, "psf/requests", trigger_mode)
                latest = self.store.list_scan_runs(ownership, limit=1)[0]["id"]
                self.store.complete_scan_run(
                    ownership,
                    latest,
                    status="completed",
                    findings_created=2,
                    high_risk_findings=1,
                )
                return {
                    "scan_run_id": latest,
                    "team_slug": ownership.team_slug,
                    "repo_name": "psf/requests",
                    "status": "completed",
                    "findings_created": 2,
                    "high_risk_findings": 1,
                    "commits_scanned": 1,
                }

            def run_cycle(self, team_slug=None):
                return [
                    {
                        "scan_run_id": 999,
                        "team_slug": team_slug or "delta",
                        "repo_name": "psf/requests",
                        "status": "completed",
                        "findings_created": 4,
                        "high_risk_findings": 2,
                        "commits_scanned": 3,
                    }
                ]

        monkeypatch.setattr(threat_app, "get_scan_service", lambda store=None: FakeScanService(store=store))

        watchlist = client.get("/api/watchlist").json()["watchlist"]
        scan_now = client.post(f"/api/watchlist/{watchlist[0]['id']}/scan-now")
        assert scan_now.status_code == 200
        assert scan_now.json()["scan_run"]["status"] == "completed"

        runs = client.get("/api/scan-runs")
        assert runs.status_code == 200
        assert runs.json()["scan_runs"][0]["findings_created"] == 2

        cycle = client.post("/api/scans/run-cycle")
        assert cycle.status_code == 200
        assert cycle.json()["scan_runs"][0]["high_risk_findings"] == 2
    finally:
        watchman.DATABASE_PATH = original_db
        watchman.ALERTS_LOG_PATH = original_alert_path
        threat_app.DATABASE_PATH = original_app_db
        threat_app.ALERTS_LOG_PATH = original_app_alert


def test_login_and_logout_cycle(tmp_path: Path) -> None:
    db_path = tmp_path / "auth.db"
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

        bootstrap = TestClient(threat_app.app)
        register_team(bootstrap, "soc", "SOC Team", "soc@example.com", "Sam SOC")

        client = TestClient(threat_app.app)
        login = client.post(
            "/auth/login",
            data={
                "team_slug": "soc",
                "user_email": "soc@example.com",
                "password": "hunterpass123",
            },
            follow_redirects=False,
        )
        assert login.status_code == 303

        assert client.get("/api/session").status_code == 200

        logout = client.post("/auth/logout", follow_redirects=False)
        assert logout.status_code == 303
        assert client.get("/api/session").status_code == 401
    finally:
        watchman.DATABASE_PATH = original_db
        watchman.ALERTS_LOG_PATH = original_alert_path
        threat_app.DATABASE_PATH = original_app_db
        threat_app.ALERTS_LOG_PATH = original_app_alert

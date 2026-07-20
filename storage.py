import json
import os
import sqlite3
from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import hashlib
from pathlib import Path
import secrets
from typing import Any, Dict, List, Optional

try:
    import psycopg2
    from psycopg2.extras import RealDictCursor
except ImportError:  # pragma: no cover - exercised only when postgres extras are absent
    psycopg2 = None
    RealDictCursor = None


VALID_DISPOSITIONS = {"new", "true_positive", "false_positive", "ignored"}


@dataclass(frozen=True)
class OwnershipContext:
    team_slug: str
    team_name: str
    user_email: str
    user_name: str


@dataclass(frozen=True)
class OwnershipRecord:
    team_id: int
    team_slug: str
    team_name: str
    user_id: int
    user_email: str
    user_name: str


@dataclass(frozen=True)
class RepoWatchlistRecord:
    id: int
    team_id: int
    repo_name: str
    is_active: bool
    created_at: str
    last_scanned_at: Optional[str]


DEFAULT_ALERT_MIN_RISK = os.getenv("ALERT_MIN_RISK", "high").strip().lower()
DEFAULT_ALERT_MIN_CONFIDENCE = int(os.getenv("ALERT_MIN_CONFIDENCE", "80"))
DEFAULT_SCAN_LIMIT = int(os.getenv("WATCHMAN_SCAN_LIMIT", "3"))
DEFAULT_SCAN_INTERVAL_MINUTES = int(os.getenv("WATCHMAN_SCAN_INTERVAL_MINUTES", "60"))
DEFAULT_SCAN_LOCK_MINUTES = int(os.getenv("WATCHMAN_SCAN_LOCK_MINUTES", "30"))


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def infer_backend_name(database_url: Optional[str], db_path: Optional[Path]) -> str:
    if database_url:
        normalized = database_url.strip().lower()
        if normalized.startswith(("postgres://", "postgresql://")):
            return "postgresql"
        if normalized.startswith("sqlite:///"):
            return "sqlite"
    return "sqlite" if db_path is not None else "sqlite"


def default_database_url() -> Optional[str]:
    value = os.getenv("WATCHMAN_DATABASE_URL")
    return value.strip() if value and value.strip() else None


def default_database_path() -> Path:
    return Path(os.getenv("WATCHMAN_DB_PATH", "security_findings.db"))


def sqlite_path_from_url(database_url: str) -> Path:
    normalized = database_url.strip()
    if normalized.startswith("sqlite:///"):
        return Path(normalized.removeprefix("sqlite:///"))
    raise ValueError(f"Unsupported sqlite database URL: {database_url}")


class BaseStoreBackend(ABC):
    backend_name: str = "unknown"

    @abstractmethod
    def resolve_ownership(self, context: OwnershipContext) -> OwnershipRecord:
        raise NotImplementedError

    @abstractmethod
    def get_membership(self, team_slug: str, user_email: str) -> Optional[OwnershipRecord]:
        raise NotImplementedError

    @abstractmethod
    def register_account(
        self,
        team_slug: str,
        team_name: str,
        user_email: str,
        user_name: str,
        password: str,
    ) -> OwnershipRecord:
        raise NotImplementedError

    @abstractmethod
    def authenticate_account(
        self,
        team_slug: str,
        user_email: str,
        password: str,
    ) -> Optional[OwnershipRecord]:
        raise NotImplementedError

    @abstractmethod
    def commit_exists(self, ownership: OwnershipContext, repo_name: str, commit_sha: str) -> bool:
        raise NotImplementedError

    @abstractmethod
    def save_commit_metadata(
        self,
        ownership: OwnershipContext,
        repo_name: str,
        commit_sha: str,
        author_name: Optional[str],
        commit_message: Optional[str],
        html_url: Optional[str],
    ) -> int:
        raise NotImplementedError

    @abstractmethod
    def save_finding(
        self,
        ownership: OwnershipContext,
        repo_name: str,
        commit_sha: str,
        file_name: str,
        result: Any,
    ) -> int:
        raise NotImplementedError

    @abstractmethod
    def list_findings(
        self,
        ownership: OwnershipContext,
        limit: int = 20,
        risk: Optional[str] = None,
        repo_name: Optional[str] = None,
        disposition: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        raise NotImplementedError

    @abstractmethod
    def get_finding(
        self,
        ownership: OwnershipContext,
        finding_id: int,
    ) -> Optional[Dict[str, Any]]:
        raise NotImplementedError

    @abstractmethod
    def get_history_context(
        self,
        ownership: OwnershipContext,
        repo_name: str,
        file_name: str,
        rule_hits: List[str],
        exclude_commit_sha: Optional[str] = None,
        limit: int = 25,
    ) -> Dict[str, Any]:
        raise NotImplementedError

    @abstractmethod
    def update_finding_triage(
        self,
        ownership: OwnershipContext,
        finding_id: int,
        disposition: str,
        analyst_note: Optional[str] = None,
        clear_note: bool = False,
    ) -> bool:
        raise NotImplementedError

    @abstractmethod
    def list_repo_watchlists(
        self,
        ownership: OwnershipContext,
        include_inactive: bool = False,
    ) -> List[Dict[str, Any]]:
        raise NotImplementedError

    @abstractmethod
    def add_repo_watchlist(
        self,
        ownership: OwnershipContext,
        repo_name: str,
    ) -> Dict[str, Any]:
        raise NotImplementedError

    @abstractmethod
    def deactivate_repo_watchlist(
        self,
        ownership: OwnershipContext,
        watchlist_id: int,
    ) -> bool:
        raise NotImplementedError

    @abstractmethod
    def get_team_settings(self, ownership: OwnershipContext) -> Dict[str, Any]:
        raise NotImplementedError

    @abstractmethod
    def update_team_settings(
        self,
        ownership: OwnershipContext,
        *,
        alert_webhook_url: Optional[str] = None,
        alert_min_risk: Optional[str] = None,
        alert_min_confidence: Optional[int] = None,
        scans_enabled: Optional[bool] = None,
        scan_limit: Optional[int] = None,
        scan_interval_minutes: Optional[int] = None,
    ) -> Dict[str, Any]:
        raise NotImplementedError

    @abstractmethod
    def create_scan_run(
        self,
        ownership: OwnershipContext,
        repo_watchlist_id: int,
        repo_name: str,
        trigger_mode: str,
    ) -> int:
        raise NotImplementedError

    @abstractmethod
    def complete_scan_run(
        self,
        ownership: OwnershipContext,
        scan_run_id: int,
        *,
        status: str,
        findings_created: int = 0,
        high_risk_findings: int = 0,
        error_message: Optional[str] = None,
    ) -> bool:
        raise NotImplementedError

    @abstractmethod
    def list_scan_runs(
        self,
        ownership: OwnershipContext,
        limit: int = 20,
    ) -> List[Dict[str, Any]]:
        raise NotImplementedError

    @abstractmethod
    def claim_scan_run(
        self,
        ownership: OwnershipContext,
        repo_watchlist_id: int,
        repo_name: str,
        trigger_mode: str,
        lock_timeout_minutes: int = DEFAULT_SCAN_LOCK_MINUTES,
    ) -> Optional[Dict[str, Any]]:
        raise NotImplementedError

    @abstractmethod
    def get_repo_watchlist(
        self,
        ownership: OwnershipContext,
        watchlist_id: int,
    ) -> Optional[Dict[str, Any]]:
        raise NotImplementedError

    @abstractmethod
    def list_scan_targets(
        self,
        *,
        team_slug: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        raise NotImplementedError

    @abstractmethod
    def record_alert_delivery(
        self,
        ownership: OwnershipContext,
        repo_name: str,
        commit_sha: str,
        file_name: str,
        channel: str,
        destination: str,
        status: str,
        error_message: Optional[str] = None,
    ) -> Dict[str, Any]:
        raise NotImplementedError

    @abstractmethod
    def list_alert_deliveries(
        self,
        ownership: OwnershipContext,
        limit: int = 20,
    ) -> List[Dict[str, Any]]:
        raise NotImplementedError


class SQLiteStoreBackend(BaseStoreBackend):
    backend_name = "sqlite"

    def __init__(self, db_path: Path) -> None:
        self.db_path = db_path
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.db_path)
        connection.row_factory = sqlite3.Row
        return connection

    def _initialize(self) -> None:
        with self._connect() as connection:
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS teams (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    slug TEXT NOT NULL UNIQUE,
                    name TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    email TEXT NOT NULL UNIQUE,
                    display_name TEXT NOT NULL,
                    password_salt TEXT,
                    password_hash TEXT,
                    created_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS team_memberships (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    team_id INTEGER NOT NULL,
                    user_id INTEGER NOT NULL,
                    role TEXT NOT NULL DEFAULT 'analyst',
                    created_at TEXT NOT NULL,
                    UNIQUE(team_id, user_id),
                    FOREIGN KEY(team_id) REFERENCES teams(id),
                    FOREIGN KEY(user_id) REFERENCES users(id)
                );

                CREATE TABLE IF NOT EXISTS commits (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    team_id INTEGER NOT NULL,
                    repo_name TEXT NOT NULL,
                    commit_sha TEXT NOT NULL,
                    author_name TEXT,
                    commit_message TEXT,
                    html_url TEXT,
                    analyzed_at TEXT NOT NULL,
                    created_by_user_id INTEGER,
                    UNIQUE(team_id, repo_name, commit_sha),
                    FOREIGN KEY(team_id) REFERENCES teams(id),
                    FOREIGN KEY(created_by_user_id) REFERENCES users(id)
                );

                CREATE TABLE IF NOT EXISTS findings (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    team_id INTEGER NOT NULL,
                    commit_id INTEGER NOT NULL,
                    commit_sha TEXT NOT NULL,
                    file_name TEXT NOT NULL,
                    risk TEXT NOT NULL,
                    confidence INTEGER NOT NULL,
                    summary TEXT NOT NULL,
                    reasons_json TEXT NOT NULL,
                    indicators_json TEXT NOT NULL,
                    yara_rule TEXT,
                    raw_response TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    rule_hits_json TEXT NOT NULL DEFAULT '[]',
                    disposition TEXT NOT NULL DEFAULT 'new',
                    analyst_note TEXT NOT NULL DEFAULT '',
                    triaged_at TEXT,
                    history_context_json TEXT NOT NULL DEFAULT '{}',
                    suppression_context_json TEXT NOT NULL DEFAULT '{}',
                    triaged_by_user_id INTEGER,
                    FOREIGN KEY(team_id) REFERENCES teams(id),
                    FOREIGN KEY(commit_id) REFERENCES commits(id),
                    FOREIGN KEY(triaged_by_user_id) REFERENCES users(id)
                );

                CREATE TABLE IF NOT EXISTS repo_watchlists (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    team_id INTEGER NOT NULL,
                    repo_name TEXT NOT NULL,
                    is_active INTEGER NOT NULL DEFAULT 1,
                    created_at TEXT NOT NULL,
                    last_scanned_at TEXT,
                    scan_interval_minutes INTEGER NOT NULL DEFAULT 60,
                    next_scan_at TEXT,
                    last_successful_scan_at TEXT,
                    last_failed_scan_at TEXT,
                    last_scan_error TEXT NOT NULL DEFAULT '',
                    UNIQUE(team_id, repo_name),
                    FOREIGN KEY(team_id) REFERENCES teams(id)
                );

                CREATE TABLE IF NOT EXISTS team_settings (
                    team_id INTEGER PRIMARY KEY,
                    alert_webhook_url TEXT,
                    alert_min_risk TEXT NOT NULL DEFAULT 'high',
                    alert_min_confidence INTEGER NOT NULL DEFAULT 80,
                    scans_enabled INTEGER NOT NULL DEFAULT 1,
                    scan_limit INTEGER NOT NULL DEFAULT 3,
                    scan_interval_minutes INTEGER NOT NULL DEFAULT 60,
                    updated_at TEXT NOT NULL,
                    FOREIGN KEY(team_id) REFERENCES teams(id)
                );

                CREATE TABLE IF NOT EXISTS scan_runs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    team_id INTEGER NOT NULL,
                    repo_watchlist_id INTEGER NOT NULL,
                    repo_name TEXT NOT NULL,
                    trigger_mode TEXT NOT NULL,
                    status TEXT NOT NULL,
                    started_at TEXT NOT NULL,
                    lock_expires_at TEXT,
                    completed_at TEXT,
                    error_message TEXT,
                    findings_created INTEGER NOT NULL DEFAULT 0,
                    high_risk_findings INTEGER NOT NULL DEFAULT 0,
                    scanner_user_id INTEGER,
                    FOREIGN KEY(team_id) REFERENCES teams(id),
                    FOREIGN KEY(repo_watchlist_id) REFERENCES repo_watchlists(id),
                    FOREIGN KEY(scanner_user_id) REFERENCES users(id)
                );

                CREATE TABLE IF NOT EXISTS alert_deliveries (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    team_id INTEGER NOT NULL,
                    repo_name TEXT NOT NULL,
                    commit_sha TEXT NOT NULL,
                    file_name TEXT NOT NULL,
                    channel TEXT NOT NULL,
                    destination TEXT NOT NULL,
                    status TEXT NOT NULL,
                    attempt_number INTEGER NOT NULL DEFAULT 1,
                    error_message TEXT,
                    created_at TEXT NOT NULL,
                    FOREIGN KEY(team_id) REFERENCES teams(id)
                );

                CREATE INDEX IF NOT EXISTS idx_commits_team_repo_sha
                    ON commits(team_id, repo_name, commit_sha);
                CREATE INDEX IF NOT EXISTS idx_findings_team_created
                    ON findings(team_id, created_at DESC);
                CREATE INDEX IF NOT EXISTS idx_findings_commit
                    ON findings(commit_id);
                CREATE INDEX IF NOT EXISTS idx_scan_runs_team_started
                    ON scan_runs(team_id, started_at DESC);
                CREATE UNIQUE INDEX IF NOT EXISTS idx_scan_runs_running_lock
                    ON scan_runs(team_id, repo_watchlist_id)
                    WHERE status = 'running';
                CREATE INDEX IF NOT EXISTS idx_alert_deliveries_team_created
                    ON alert_deliveries(team_id, created_at DESC);
                """
            )
            self._migrate_existing_schema(connection)

    def _migrate_existing_schema(self, connection: sqlite3.Connection) -> None:
        commit_columns = self._table_columns(connection, "commits")
        finding_columns = self._table_columns(connection, "findings")
        if not commit_columns or not finding_columns:
            return

        if "team_id" not in commit_columns:
            connection.execute("ALTER TABLE commits ADD COLUMN team_id INTEGER")
        if "created_by_user_id" not in commit_columns:
            connection.execute("ALTER TABLE commits ADD COLUMN created_by_user_id INTEGER")
        if "commit_id" not in finding_columns:
            connection.execute("ALTER TABLE findings ADD COLUMN commit_id INTEGER")
        if "team_id" not in finding_columns:
            connection.execute("ALTER TABLE findings ADD COLUMN team_id INTEGER")
        if "rule_hits_json" not in finding_columns:
            connection.execute("ALTER TABLE findings ADD COLUMN rule_hits_json TEXT NOT NULL DEFAULT '[]'")
        if "disposition" not in finding_columns:
            connection.execute("ALTER TABLE findings ADD COLUMN disposition TEXT NOT NULL DEFAULT 'new'")
        if "analyst_note" not in finding_columns:
            connection.execute("ALTER TABLE findings ADD COLUMN analyst_note TEXT NOT NULL DEFAULT ''")
        if "triaged_at" not in finding_columns:
            connection.execute("ALTER TABLE findings ADD COLUMN triaged_at TEXT")
        if "history_context_json" not in finding_columns:
            connection.execute("ALTER TABLE findings ADD COLUMN history_context_json TEXT NOT NULL DEFAULT '{}'")
        if "suppression_context_json" not in finding_columns:
            connection.execute("ALTER TABLE findings ADD COLUMN suppression_context_json TEXT NOT NULL DEFAULT '{}'")
        if "triaged_by_user_id" not in finding_columns:
            connection.execute("ALTER TABLE findings ADD COLUMN triaged_by_user_id INTEGER")
        user_columns = self._table_columns(connection, "users")
        if "password_salt" not in user_columns:
            connection.execute("ALTER TABLE users ADD COLUMN password_salt TEXT")
        if "password_hash" not in user_columns:
            connection.execute("ALTER TABLE users ADD COLUMN password_hash TEXT")
        repo_watchlist_columns = self._table_columns(connection, "repo_watchlists")
        if repo_watchlist_columns:
            if "scan_interval_minutes" not in repo_watchlist_columns:
                connection.execute(
                    "ALTER TABLE repo_watchlists ADD COLUMN scan_interval_minutes INTEGER NOT NULL DEFAULT 60"
                )
            if "next_scan_at" not in repo_watchlist_columns:
                connection.execute("ALTER TABLE repo_watchlists ADD COLUMN next_scan_at TEXT")
            if "last_successful_scan_at" not in repo_watchlist_columns:
                connection.execute("ALTER TABLE repo_watchlists ADD COLUMN last_successful_scan_at TEXT")
            if "last_failed_scan_at" not in repo_watchlist_columns:
                connection.execute("ALTER TABLE repo_watchlists ADD COLUMN last_failed_scan_at TEXT")
            if "last_scan_error" not in repo_watchlist_columns:
                connection.execute(
                    "ALTER TABLE repo_watchlists ADD COLUMN last_scan_error TEXT NOT NULL DEFAULT ''"
                )
        team_settings_columns = self._table_columns(connection, "team_settings")
        if team_settings_columns:
            if "alert_webhook_url" not in team_settings_columns:
                connection.execute("ALTER TABLE team_settings ADD COLUMN alert_webhook_url TEXT")
            if "alert_min_risk" not in team_settings_columns:
                connection.execute(
                    "ALTER TABLE team_settings ADD COLUMN alert_min_risk TEXT NOT NULL DEFAULT 'high'"
                )
            if "alert_min_confidence" not in team_settings_columns:
                connection.execute(
                    "ALTER TABLE team_settings ADD COLUMN alert_min_confidence INTEGER NOT NULL DEFAULT 80"
                )
            if "scans_enabled" not in team_settings_columns:
                connection.execute(
                    "ALTER TABLE team_settings ADD COLUMN scans_enabled INTEGER NOT NULL DEFAULT 1"
                )
            if "scan_limit" not in team_settings_columns:
                connection.execute(
                    "ALTER TABLE team_settings ADD COLUMN scan_limit INTEGER NOT NULL DEFAULT 3"
                )
            if "scan_interval_minutes" not in team_settings_columns:
                connection.execute(
                    "ALTER TABLE team_settings ADD COLUMN scan_interval_minutes INTEGER NOT NULL DEFAULT 60"
                )
            if "updated_at" not in team_settings_columns:
                connection.execute(
                    "ALTER TABLE team_settings ADD COLUMN updated_at TEXT NOT NULL DEFAULT ''"
                )
        scan_run_columns = self._table_columns(connection, "scan_runs")
        if scan_run_columns and "lock_expires_at" not in scan_run_columns:
            connection.execute("ALTER TABLE scan_runs ADD COLUMN lock_expires_at TEXT")
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS alert_deliveries (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                team_id INTEGER NOT NULL,
                repo_name TEXT NOT NULL,
                commit_sha TEXT NOT NULL,
                file_name TEXT NOT NULL,
                channel TEXT NOT NULL,
                destination TEXT NOT NULL,
                status TEXT NOT NULL,
                attempt_number INTEGER NOT NULL DEFAULT 1,
                error_message TEXT,
                created_at TEXT NOT NULL,
                FOREIGN KEY(team_id) REFERENCES teams(id)
            )
            """
        )
        connection.execute(
            """
            CREATE UNIQUE INDEX IF NOT EXISTS idx_scan_runs_running_lock
                ON scan_runs(team_id, repo_watchlist_id)
                WHERE status = 'running'
            """
        )
        connection.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_alert_deliveries_team_created
                ON alert_deliveries(team_id, created_at DESC)
            """
        )
        connection.execute(
            """
            UPDATE repo_watchlists
            SET scan_interval_minutes = COALESCE(scan_interval_minutes, ?),
                next_scan_at = COALESCE(next_scan_at, created_at, ?),
                last_scan_error = COALESCE(last_scan_error, '')
            """,
            (DEFAULT_SCAN_INTERVAL_MINUTES, utc_now_iso()),
        )
        connection.execute(
            """
            UPDATE team_settings
            SET scan_interval_minutes = COALESCE(scan_interval_minutes, ?)
            """,
            (DEFAULT_SCAN_INTERVAL_MINUTES,),
        )

    @staticmethod
    def _table_columns(connection: sqlite3.Connection, table_name: str) -> List[str]:
        return [
            row["name"]
            for row in connection.execute(f"PRAGMA table_info({table_name})").fetchall()
        ]

    @staticmethod
    def _row_dict(row: Optional[sqlite3.Row]) -> Optional[Dict[str, Any]]:
        return dict(row) if row is not None else None

    def resolve_ownership(self, context: OwnershipContext) -> OwnershipRecord:
        with self._connect() as connection:
            team = connection.execute(
                "SELECT id, slug, name FROM teams WHERE slug = ?",
                (context.team_slug,),
            ).fetchone()
            if team is None:
                connection.execute(
                    "INSERT INTO teams (slug, name, created_at) VALUES (?, ?, ?)",
                    (context.team_slug, context.team_name, utc_now_iso()),
                )
                team = connection.execute(
                    "SELECT id, slug, name FROM teams WHERE slug = ?",
                    (context.team_slug,),
                ).fetchone()

            user = connection.execute(
                "SELECT id, email, display_name FROM users WHERE email = ?",
                (context.user_email,),
            ).fetchone()
            if user is None:
                connection.execute(
                    "INSERT INTO users (email, display_name, created_at) VALUES (?, ?, ?)",
                    (context.user_email, context.user_name, utc_now_iso()),
                )
                user = connection.execute(
                    "SELECT id, email, display_name FROM users WHERE email = ?",
                    (context.user_email,),
                ).fetchone()
            elif user["display_name"] != context.user_name:
                connection.execute(
                    "UPDATE users SET display_name = ? WHERE id = ?",
                    (context.user_name, user["id"]),
                )
                user = connection.execute(
                    "SELECT id, email, display_name FROM users WHERE email = ?",
                    (context.user_email,),
                ).fetchone()

            connection.execute(
                """
                INSERT OR IGNORE INTO team_memberships (team_id, user_id, role, created_at)
                VALUES (?, ?, 'analyst', ?)
                """,
                (team["id"], user["id"], utc_now_iso()),
            )

        return OwnershipRecord(
            team_id=int(team["id"]),
            team_slug=str(team["slug"]),
            team_name=str(team["name"]),
            user_id=int(user["id"]),
            user_email=str(user["email"]),
            user_name=str(user["display_name"]),
        )

    def _ensure_team_settings_row(self, resolved: OwnershipRecord) -> None:
        with self._connect() as connection:
            connection.execute(
                """
                INSERT OR IGNORE INTO team_settings (
                    team_id,
                    alert_webhook_url,
                    alert_min_risk,
                    alert_min_confidence,
                    scans_enabled,
                    scan_limit,
                    scan_interval_minutes,
                    updated_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    resolved.team_id,
                    None,
                    DEFAULT_ALERT_MIN_RISK,
                    DEFAULT_ALERT_MIN_CONFIDENCE,
                    1,
                    DEFAULT_SCAN_LIMIT,
                    DEFAULT_SCAN_INTERVAL_MINUTES,
                    utc_now_iso(),
                ),
            )

    def get_membership(self, team_slug: str, user_email: str) -> Optional[OwnershipRecord]:
        with self._connect() as connection:
            row = connection.execute(
                """
                SELECT
                    teams.id AS team_id,
                    teams.slug AS team_slug,
                    teams.name AS team_name,
                    users.id AS user_id,
                    users.email AS user_email,
                    users.display_name AS user_name
                FROM team_memberships
                JOIN teams ON team_memberships.team_id = teams.id
                JOIN users ON team_memberships.user_id = users.id
                WHERE teams.slug = ? AND users.email = ?
                """,
                (team_slug, user_email),
            ).fetchone()
        if row is None:
            return None
        return OwnershipRecord(
            team_id=int(row["team_id"]),
            team_slug=str(row["team_slug"]),
            team_name=str(row["team_name"]),
            user_id=int(row["user_id"]),
            user_email=str(row["user_email"]),
            user_name=str(row["user_name"]),
        )

    def register_account(
        self,
        team_slug: str,
        team_name: str,
        user_email: str,
        user_name: str,
        password: str,
    ) -> OwnershipRecord:
        normalized_team_slug = team_slug.strip()
        normalized_team_name = team_name.strip()
        normalized_email = user_email.strip().lower()
        normalized_user_name = user_name.strip()
        ensure_password_strength(password)

        with self._connect() as connection:
            existing_team = connection.execute(
                "SELECT id FROM teams WHERE slug = ?",
                (normalized_team_slug,),
            ).fetchone()
            if existing_team is not None:
                raise ValueError("Team slug is already in use.")

            existing_user = connection.execute(
                "SELECT id, password_salt, password_hash FROM users WHERE email = ?",
                (normalized_email,),
            ).fetchone()

            if existing_user is None:
                salt = generate_password_salt()
                password_hash = hash_password(password, salt)
                connection.execute(
                    """
                    INSERT INTO users (email, display_name, password_salt, password_hash, created_at)
                    VALUES (?, ?, ?, ?, ?)
                    """,
                    (normalized_email, normalized_user_name, salt, password_hash, utc_now_iso()),
                )
                existing_user = connection.execute(
                    "SELECT id, password_salt, password_hash FROM users WHERE email = ?",
                    (normalized_email,),
                ).fetchone()
            else:
                stored_salt = existing_user["password_salt"] or ""
                stored_hash = existing_user["password_hash"] or ""
                if not stored_salt or not stored_hash:
                    raise ValueError("This user exists without a login password. Reset support is required.")
                if hash_password(password, stored_salt) != stored_hash:
                    raise ValueError("An account with this email already exists.")
                connection.execute(
                    "UPDATE users SET display_name = ? WHERE id = ?",
                    (normalized_user_name, existing_user["id"]),
                )

            connection.execute(
                "INSERT INTO teams (slug, name, created_at) VALUES (?, ?, ?)",
                (normalized_team_slug, normalized_team_name, utc_now_iso()),
            )
            team = connection.execute(
                "SELECT id, slug, name FROM teams WHERE slug = ?",
                (normalized_team_slug,),
            ).fetchone()
            user = connection.execute(
                "SELECT id, email, display_name FROM users WHERE email = ?",
                (normalized_email,),
            ).fetchone()
            connection.execute(
                """
                INSERT INTO team_memberships (team_id, user_id, role, created_at)
                VALUES (?, ?, 'owner', ?)
                """,
                (team["id"], user["id"], utc_now_iso()),
            )

        return OwnershipRecord(
            team_id=int(team["id"]),
            team_slug=str(team["slug"]),
            team_name=str(team["name"]),
            user_id=int(user["id"]),
            user_email=str(user["email"]),
            user_name=str(user["display_name"]),
        )

    def authenticate_account(
        self,
        team_slug: str,
        user_email: str,
        password: str,
    ) -> Optional[OwnershipRecord]:
        normalized_email = user_email.strip().lower()
        with self._connect() as connection:
            user = connection.execute(
                "SELECT id, email, display_name, password_salt, password_hash FROM users WHERE email = ?",
                (normalized_email,),
            ).fetchone()
            if user is None:
                return None
            stored_salt = user["password_salt"] or ""
            stored_hash = user["password_hash"] or ""
            if not stored_salt or not stored_hash:
                return None
            if hash_password(password, stored_salt) != stored_hash:
                return None
        return self.get_membership(team_slug.strip(), normalized_email)

    def commit_exists(self, ownership: OwnershipContext, repo_name: str, commit_sha: str) -> bool:
        resolved = self.resolve_ownership(ownership)
        with self._connect() as connection:
            row = connection.execute(
                """
                SELECT 1
                FROM commits
                WHERE team_id = ? AND repo_name = ? AND commit_sha = ?
                """,
                (resolved.team_id, repo_name, commit_sha),
            ).fetchone()
        return row is not None

    def save_commit_metadata(
        self,
        ownership: OwnershipContext,
        repo_name: str,
        commit_sha: str,
        author_name: Optional[str],
        commit_message: Optional[str],
        html_url: Optional[str],
    ) -> int:
        resolved = self.resolve_ownership(ownership)
        analyzed_at = utc_now_iso()
        with self._connect() as connection:
            connection.execute(
                """
                INSERT OR IGNORE INTO commits (
                    team_id, repo_name, commit_sha, author_name, commit_message, html_url, analyzed_at, created_by_user_id
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    resolved.team_id,
                    repo_name,
                    commit_sha,
                    author_name,
                    commit_message,
                    html_url,
                    analyzed_at,
                    resolved.user_id,
                ),
            )
            row = connection.execute(
                """
                SELECT id
                FROM commits
                WHERE team_id = ? AND repo_name = ? AND commit_sha = ?
                """,
                (resolved.team_id, repo_name, commit_sha),
            ).fetchone()
        if row is None:
            raise ValueError(f"Commit was not persisted for {repo_name}@{commit_sha}")
        return int(row["id"])

    def save_finding(
        self,
        ownership: OwnershipContext,
        repo_name: str,
        commit_sha: str,
        file_name: str,
        result: Any,
    ) -> int:
        resolved = self.resolve_ownership(ownership)
        commit_id = self.save_commit_metadata(
            ownership=ownership,
            repo_name=repo_name,
            commit_sha=commit_sha,
            author_name=None,
            commit_message=None,
            html_url=None,
        )
        created_at = utc_now_iso()
        with self._connect() as connection:
            cursor = connection.execute(
                """
                INSERT INTO findings (
                    team_id,
                    commit_id,
                    commit_sha,
                    file_name,
                    risk,
                    confidence,
                    summary,
                    reasons_json,
                    indicators_json,
                    yara_rule,
                    raw_response,
                    created_at,
                    rule_hits_json,
                    disposition,
                    analyst_note,
                    triaged_at,
                    history_context_json,
                    suppression_context_json,
                    triaged_by_user_id
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    resolved.team_id,
                    commit_id,
                    commit_sha,
                    file_name,
                    result.normalized_risk(),
                    result.confidence,
                    result.summary,
                    self._json(result.reasons),
                    self._json(result.indicators),
                    result.yara_rule,
                    result.raw_response,
                    created_at,
                    self._json(result.rule_hits),
                    "new",
                    "",
                    None,
                    self._json(result.history_context),
                    self._json(result.suppression_context),
                    None,
                ),
            )
        return int(cursor.lastrowid)

    def list_findings(
        self,
        ownership: OwnershipContext,
        limit: int = 20,
        risk: Optional[str] = None,
        repo_name: Optional[str] = None,
        disposition: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        resolved = self.resolve_ownership(ownership)
        query = """
            SELECT
                findings.id,
                teams.slug AS team_slug,
                teams.name AS team_name,
                commits.repo_name,
                findings.commit_sha,
                findings.file_name,
                findings.risk,
                findings.confidence,
                findings.summary,
                findings.created_at,
                findings.rule_hits_json,
                findings.disposition,
                findings.history_context_json,
                findings.suppression_context_json
            FROM findings
            JOIN commits ON findings.commit_id = commits.id
            JOIN teams ON findings.team_id = teams.id
        """
        filters = ["findings.team_id = ?"]
        params: List[Any] = [resolved.team_id]
        if risk:
            filters.append("findings.risk = ?")
            params.append(risk.lower())
        if repo_name:
            filters.append("commits.repo_name = ?")
            params.append(repo_name)
        if disposition:
            filters.append("findings.disposition = ?")
            params.append(disposition)
        query += " WHERE " + " AND ".join(filters)
        query += " ORDER BY findings.created_at DESC, findings.id DESC LIMIT ?"
        params.append(limit)
        with self._connect() as connection:
            return [dict(row) for row in connection.execute(query, params).fetchall()]

    def get_finding(
        self,
        ownership: OwnershipContext,
        finding_id: int,
    ) -> Optional[Dict[str, Any]]:
        resolved = self.resolve_ownership(ownership)
        query = """
            SELECT
                findings.id,
                teams.slug AS team_slug,
                teams.name AS team_name,
                commits.repo_name,
                findings.commit_sha,
                commits.author_name,
                commits.commit_message,
                commits.html_url,
                findings.file_name,
                findings.risk,
                findings.confidence,
                findings.summary,
                findings.reasons_json,
                findings.indicators_json,
                findings.yara_rule,
                findings.rule_hits_json,
                findings.raw_response,
                findings.created_at,
                findings.disposition,
                findings.analyst_note,
                findings.triaged_at,
                findings.history_context_json,
                findings.suppression_context_json,
                triager.email AS triaged_by_user_email,
                triager.display_name AS triaged_by_user_name
            FROM findings
            JOIN commits ON findings.commit_id = commits.id
            JOIN teams ON findings.team_id = teams.id
            LEFT JOIN users AS triager ON findings.triaged_by_user_id = triager.id
            WHERE findings.id = ? AND findings.team_id = ?
        """
        with self._connect() as connection:
            row = connection.execute(query, (finding_id, resolved.team_id)).fetchone()
        return self._row_dict(row)

    def get_history_context(
        self,
        ownership: OwnershipContext,
        repo_name: str,
        file_name: str,
        rule_hits: List[str],
        exclude_commit_sha: Optional[str] = None,
        limit: int = 25,
    ) -> Dict[str, Any]:
        resolved = self.resolve_ownership(ownership)
        query = """
            SELECT
                findings.id,
                findings.commit_sha,
                findings.rule_hits_json,
                findings.disposition
            FROM findings
            JOIN commits ON findings.commit_id = commits.id
            WHERE findings.team_id = ? AND commits.repo_name = ? AND findings.file_name = ?
            ORDER BY findings.created_at DESC, findings.id DESC
            LIMIT ?
        """
        with self._connect() as connection:
            rows = connection.execute(
                query,
                (resolved.team_id, repo_name, file_name, limit),
            ).fetchall()
        return self._build_history_context(
            rows=[dict(row) for row in rows],
            rule_hits=rule_hits,
            exclude_commit_sha=exclude_commit_sha,
        )

    def update_finding_triage(
        self,
        ownership: OwnershipContext,
        finding_id: int,
        disposition: str,
        analyst_note: Optional[str] = None,
        clear_note: bool = False,
    ) -> bool:
        normalized = disposition.strip().lower()
        if normalized not in VALID_DISPOSITIONS:
            raise ValueError(f"Invalid disposition: {disposition}")

        resolved = self.resolve_ownership(ownership)
        with self._connect() as connection:
            current = connection.execute(
                """
                SELECT analyst_note
                FROM findings
                WHERE id = ? AND team_id = ?
                """,
                (finding_id, resolved.team_id),
            ).fetchone()
            if current is None:
                return False

            if clear_note:
                note_value = ""
            elif analyst_note is None:
                note_value = current["analyst_note"]
            else:
                note_value = analyst_note.strip()

            connection.execute(
                """
                UPDATE findings
                SET disposition = ?, analyst_note = ?, triaged_at = ?, triaged_by_user_id = ?
                WHERE id = ? AND team_id = ?
                """,
                (
                    normalized,
                    note_value,
                    utc_now_iso(),
                    resolved.user_id,
                    finding_id,
                    resolved.team_id,
                ),
            )
        return True

    def list_repo_watchlists(
        self,
        ownership: OwnershipContext,
        include_inactive: bool = False,
    ) -> List[Dict[str, Any]]:
        resolved = self.resolve_ownership(ownership)
        query = """
            SELECT
                id,
                team_id,
                repo_name,
                is_active,
                created_at,
                last_scanned_at,
                scan_interval_minutes,
                next_scan_at,
                last_successful_scan_at,
                last_failed_scan_at,
                last_scan_error
            FROM repo_watchlists
            WHERE team_id = ?
        """
        params: List[Any] = [resolved.team_id]
        if not include_inactive:
            query += " AND is_active = 1"
        query += " ORDER BY repo_name ASC"
        with self._connect() as connection:
            return [dict(row) for row in connection.execute(query, params).fetchall()]

    def add_repo_watchlist(
        self,
        ownership: OwnershipContext,
        repo_name: str,
    ) -> Dict[str, Any]:
        normalized_repo = normalize_repo_name(repo_name)
        resolved = self.resolve_ownership(ownership)
        scan_interval_minutes = self.get_team_settings(ownership)["scan_interval_minutes"]
        created_at = utc_now_iso()
        with self._connect() as connection:
            connection.execute(
                """
                INSERT INTO repo_watchlists (
                    team_id,
                    repo_name,
                    is_active,
                    created_at,
                    last_scanned_at,
                    scan_interval_minutes,
                    next_scan_at,
                    last_successful_scan_at,
                    last_failed_scan_at,
                    last_scan_error
                )
                VALUES (?, ?, 1, ?, NULL, ?, ?, NULL, NULL, '')
                ON CONFLICT(team_id, repo_name) DO UPDATE SET
                    is_active = 1,
                    scan_interval_minutes = excluded.scan_interval_minutes,
                    next_scan_at = COALESCE(repo_watchlists.next_scan_at, excluded.next_scan_at)
                """,
                (
                    resolved.team_id,
                    normalized_repo,
                    created_at,
                    scan_interval_minutes,
                    created_at,
                ),
            )
            row = connection.execute(
                """
                SELECT
                    id,
                    team_id,
                    repo_name,
                    is_active,
                    created_at,
                    last_scanned_at,
                    scan_interval_minutes,
                    next_scan_at,
                    last_successful_scan_at,
                    last_failed_scan_at,
                    last_scan_error
                FROM repo_watchlists
                WHERE team_id = ? AND repo_name = ?
                """,
                (resolved.team_id, normalized_repo),
            ).fetchone()
        if row is None:
            raise ValueError(f"Unable to persist watchlist entry for {normalized_repo}")
        return dict(row)

    def deactivate_repo_watchlist(
        self,
        ownership: OwnershipContext,
        watchlist_id: int,
    ) -> bool:
        resolved = self.resolve_ownership(ownership)
        with self._connect() as connection:
            cursor = connection.execute(
                """
                UPDATE repo_watchlists
                SET is_active = 0
                WHERE id = ? AND team_id = ?
                """,
                (watchlist_id, resolved.team_id),
            )
        return cursor.rowcount > 0

    def get_team_settings(self, ownership: OwnershipContext) -> Dict[str, Any]:
        resolved = self.resolve_ownership(ownership)
        self._ensure_team_settings_row(resolved)
        with self._connect() as connection:
            row = connection.execute(
                """
                SELECT
                    team_id,
                    alert_webhook_url,
                    alert_min_risk,
                    alert_min_confidence,
                    scans_enabled,
                    scan_limit,
                    scan_interval_minutes,
                    updated_at
                FROM team_settings
                WHERE team_id = ?
                """,
                (resolved.team_id,),
            ).fetchone()
        if row is None:
            raise ValueError(f"Team settings missing for team {resolved.team_slug}")
        payload = dict(row)
        payload["scans_enabled"] = bool(payload["scans_enabled"])
        return payload

    def update_team_settings(
        self,
        ownership: OwnershipContext,
        *,
        alert_webhook_url: Optional[str] = None,
        alert_min_risk: Optional[str] = None,
        alert_min_confidence: Optional[int] = None,
        scans_enabled: Optional[bool] = None,
        scan_limit: Optional[int] = None,
        scan_interval_minutes: Optional[int] = None,
    ) -> Dict[str, Any]:
        resolved = self.resolve_ownership(ownership)
        self._ensure_team_settings_row(resolved)
        current = self.get_team_settings(ownership)
        next_values = {
            "alert_webhook_url": (
                None
                if alert_webhook_url is not None and not alert_webhook_url.strip()
                else current["alert_webhook_url"]
                if alert_webhook_url is None
                else alert_webhook_url.strip()
            ),
            "alert_min_risk": normalize_risk_level(alert_min_risk or current["alert_min_risk"]),
            "alert_min_confidence": normalize_confidence_threshold(
                current["alert_min_confidence"] if alert_min_confidence is None else alert_min_confidence
            ),
            "scans_enabled": current["scans_enabled"] if scans_enabled is None else bool(scans_enabled),
            "scan_limit": normalize_scan_limit(current["scan_limit"] if scan_limit is None else scan_limit),
            "scan_interval_minutes": normalize_scan_interval_minutes(
                current["scan_interval_minutes"] if scan_interval_minutes is None else scan_interval_minutes
            ),
            "updated_at": utc_now_iso(),
        }
        with self._connect() as connection:
            connection.execute(
                """
                UPDATE team_settings
                SET alert_webhook_url = ?,
                    alert_min_risk = ?,
                    alert_min_confidence = ?,
                    scans_enabled = ?,
                    scan_limit = ?,
                    scan_interval_minutes = ?,
                    updated_at = ?
                WHERE team_id = ?
                """,
                (
                    next_values["alert_webhook_url"],
                    next_values["alert_min_risk"],
                    next_values["alert_min_confidence"],
                    1 if next_values["scans_enabled"] else 0,
                    next_values["scan_limit"],
                    next_values["scan_interval_minutes"],
                    next_values["updated_at"],
                    resolved.team_id,
                ),
            )
            connection.execute(
                """
                UPDATE repo_watchlists
                SET scan_interval_minutes = ?
                WHERE team_id = ?
                """,
                (next_values["scan_interval_minutes"], resolved.team_id),
            )
        return self.get_team_settings(ownership)

    def create_scan_run(
        self,
        ownership: OwnershipContext,
        repo_watchlist_id: int,
        repo_name: str,
        trigger_mode: str,
    ) -> int:
        resolved = self.resolve_ownership(ownership)
        with self._connect() as connection:
            cursor = connection.execute(
                """
                INSERT INTO scan_runs (
                    team_id,
                    repo_watchlist_id,
                    repo_name,
                    trigger_mode,
                    status,
                    started_at,
                    lock_expires_at,
                    completed_at,
                    error_message,
                    findings_created,
                    high_risk_findings,
                    scanner_user_id
                )
                VALUES (?, ?, ?, ?, 'running', ?, ?, NULL, NULL, 0, 0, ?)
                """,
                (
                    resolved.team_id,
                    repo_watchlist_id,
                    repo_name,
                    trigger_mode,
                    utc_now_iso(),
                    utc_future_iso(DEFAULT_SCAN_LOCK_MINUTES),
                    resolved.user_id,
                ),
            )
        return int(cursor.lastrowid)

    def claim_scan_run(
        self,
        ownership: OwnershipContext,
        repo_watchlist_id: int,
        repo_name: str,
        trigger_mode: str,
        lock_timeout_minutes: int = DEFAULT_SCAN_LOCK_MINUTES,
    ) -> Optional[Dict[str, Any]]:
        resolved = self.resolve_ownership(ownership)
        now = utc_now_iso()
        lock_expires_at = utc_future_iso(lock_timeout_minutes)
        with self._connect() as connection:
            connection.execute(
                """
                UPDATE scan_runs
                SET status = 'failed',
                    completed_at = ?,
                    error_message = COALESCE(error_message, 'Scan lock expired before completion.'),
                    lock_expires_at = NULL
                WHERE team_id = ?
                  AND repo_watchlist_id = ?
                  AND status = 'running'
                  AND lock_expires_at IS NOT NULL
                  AND lock_expires_at <= ?
                """,
                (now, resolved.team_id, repo_watchlist_id, now),
            )
            try:
                cursor = connection.execute(
                    """
                    INSERT INTO scan_runs (
                        team_id,
                        repo_watchlist_id,
                        repo_name,
                        trigger_mode,
                        status,
                        started_at,
                        lock_expires_at,
                        completed_at,
                        error_message,
                        findings_created,
                        high_risk_findings,
                        scanner_user_id
                    )
                    VALUES (?, ?, ?, ?, 'running', ?, ?, NULL, NULL, 0, 0, ?)
                    """,
                    (
                        resolved.team_id,
                        repo_watchlist_id,
                        repo_name,
                        trigger_mode,
                        now,
                        lock_expires_at,
                        resolved.user_id,
                    ),
                )
            except sqlite3.IntegrityError:
                return None
        return {
            "id": int(cursor.lastrowid),
            "repo_watchlist_id": repo_watchlist_id,
            "repo_name": repo_name,
            "trigger_mode": trigger_mode,
            "status": "running",
            "started_at": now,
            "lock_expires_at": lock_expires_at,
        }

    def complete_scan_run(
        self,
        ownership: OwnershipContext,
        scan_run_id: int,
        *,
        status: str,
        findings_created: int = 0,
        high_risk_findings: int = 0,
        error_message: Optional[str] = None,
    ) -> bool:
        normalized_status = normalize_scan_status(status)
        resolved = self.resolve_ownership(ownership)
        with self._connect() as connection:
            row = connection.execute(
                """
                SELECT repo_watchlist_id
                FROM scan_runs
                WHERE id = ? AND team_id = ?
                """,
                (scan_run_id, resolved.team_id),
            ).fetchone()
            if row is None:
                return False
            connection.execute(
                """
                UPDATE scan_runs
                SET status = ?,
                    completed_at = ?,
                    error_message = ?,
                    lock_expires_at = NULL,
                    findings_created = ?,
                    high_risk_findings = ?
                WHERE id = ? AND team_id = ?
                """,
                (
                    normalized_status,
                    utc_now_iso(),
                    (error_message or "").strip() or None,
                    max(0, int(findings_created)),
                    max(0, int(high_risk_findings)),
                    scan_run_id,
                    resolved.team_id,
                ),
            )
            watchlist = connection.execute(
                """
                SELECT scan_interval_minutes
                FROM repo_watchlists
                WHERE id = ? AND team_id = ?
                """,
                (row["repo_watchlist_id"], resolved.team_id),
            ).fetchone()
            if watchlist is not None:
                completed_at = utc_now_iso()
                next_scan_at = utc_future_iso(
                    watchlist["scan_interval_minutes"] or DEFAULT_SCAN_INTERVAL_MINUTES
                )
                if normalized_status == "completed":
                    connection.execute(
                        """
                        UPDATE repo_watchlists
                        SET last_scanned_at = ?,
                            next_scan_at = ?,
                            last_successful_scan_at = ?,
                            last_scan_error = ''
                        WHERE id = ? AND team_id = ?
                        """,
                        (
                            completed_at,
                            next_scan_at,
                            completed_at,
                            row["repo_watchlist_id"],
                            resolved.team_id,
                        ),
                    )
                else:
                    connection.execute(
                        """
                        UPDATE repo_watchlists
                        SET last_scanned_at = ?,
                            next_scan_at = ?,
                            last_failed_scan_at = ?,
                            last_scan_error = ?
                        WHERE id = ? AND team_id = ?
                        """,
                        (
                            completed_at,
                            next_scan_at,
                            completed_at,
                            (error_message or "").strip() or "Scan failed.",
                            row["repo_watchlist_id"],
                            resolved.team_id,
                        ),
                    )
        return True

    def list_scan_runs(
        self,
        ownership: OwnershipContext,
        limit: int = 20,
    ) -> List[Dict[str, Any]]:
        resolved = self.resolve_ownership(ownership)
        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT
                    id,
                    repo_watchlist_id,
                    repo_name,
                    trigger_mode,
                    status,
                    started_at,
                    lock_expires_at,
                    completed_at,
                    error_message,
                    findings_created,
                    high_risk_findings
                FROM scan_runs
                WHERE team_id = ?
                ORDER BY started_at DESC, id DESC
                LIMIT ?
                """,
                (resolved.team_id, limit),
            ).fetchall()
        return [dict(row) for row in rows]

    def get_repo_watchlist(
        self,
        ownership: OwnershipContext,
        watchlist_id: int,
    ) -> Optional[Dict[str, Any]]:
        resolved = self.resolve_ownership(ownership)
        with self._connect() as connection:
            row = connection.execute(
                """
                SELECT
                    id,
                    team_id,
                    repo_name,
                    is_active,
                    created_at,
                    last_scanned_at,
                    scan_interval_minutes,
                    next_scan_at,
                    last_successful_scan_at,
                    last_failed_scan_at,
                    last_scan_error
                FROM repo_watchlists
                WHERE id = ? AND team_id = ?
                """,
                (watchlist_id, resolved.team_id),
            ).fetchone()
        if row is None:
            return None
        payload = dict(row)
        payload["is_active"] = bool(payload["is_active"])
        return payload

    def list_scan_targets(
        self,
        *,
        team_slug: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        query = """
            SELECT
                repo_watchlists.id AS repo_watchlist_id,
                repo_watchlists.repo_name,
                repo_watchlists.last_scanned_at,
                repo_watchlists.scan_interval_minutes,
                repo_watchlists.next_scan_at,
                repo_watchlists.last_successful_scan_at,
                repo_watchlists.last_failed_scan_at,
                repo_watchlists.last_scan_error,
                teams.slug AS team_slug,
                teams.name AS team_name,
                team_settings.alert_webhook_url,
                team_settings.alert_min_risk,
                team_settings.alert_min_confidence,
                team_settings.scans_enabled,
                team_settings.scan_limit,
                team_settings.scan_interval_minutes AS team_scan_interval_minutes
            FROM repo_watchlists
            JOIN teams ON repo_watchlists.team_id = teams.id
            LEFT JOIN team_settings ON repo_watchlists.team_id = team_settings.team_id
            WHERE repo_watchlists.is_active = 1
        """
        params: List[Any] = []
        if team_slug:
            query += " AND teams.slug = ?"
            params.append(team_slug)
        query += " ORDER BY teams.slug ASC, repo_watchlists.repo_name ASC"
        with self._connect() as connection:
            rows = [dict(row) for row in connection.execute(query, params).fetchall()]
        for row in rows:
            row["scans_enabled"] = bool(row["scans_enabled"]) if row["scans_enabled"] is not None else True
            row["alert_min_risk"] = normalize_risk_level(
                row["alert_min_risk"] or DEFAULT_ALERT_MIN_RISK
            )
            row["alert_min_confidence"] = normalize_confidence_threshold(
                row["alert_min_confidence"] if row["alert_min_confidence"] is not None else DEFAULT_ALERT_MIN_CONFIDENCE
            )
            row["scan_limit"] = normalize_scan_limit(
                row["scan_limit"] if row["scan_limit"] is not None else DEFAULT_SCAN_LIMIT
            )
            row["scan_interval_minutes"] = normalize_scan_interval_minutes(
                row["scan_interval_minutes"]
                if row["scan_interval_minutes"] is not None
                else row.get("team_scan_interval_minutes") or DEFAULT_SCAN_INTERVAL_MINUTES
            )
        return rows

    def record_alert_delivery(
        self,
        ownership: OwnershipContext,
        repo_name: str,
        commit_sha: str,
        file_name: str,
        channel: str,
        destination: str,
        status: str,
        error_message: Optional[str] = None,
    ) -> Dict[str, Any]:
        resolved = self.resolve_ownership(ownership)
        normalized_status = normalize_delivery_status(status)
        with self._connect() as connection:
            row = connection.execute(
                """
                SELECT COALESCE(MAX(attempt_number), 0) AS last_attempt
                FROM alert_deliveries
                WHERE team_id = ?
                  AND repo_name = ?
                  AND commit_sha = ?
                  AND file_name = ?
                  AND channel = ?
                  AND destination = ?
                """,
                (
                    resolved.team_id,
                    repo_name,
                    commit_sha,
                    file_name,
                    channel,
                    destination,
                ),
            ).fetchone()
            attempt_number = int(row["last_attempt"]) + 1
            created_at = utc_now_iso()
            cursor = connection.execute(
                """
                INSERT INTO alert_deliveries (
                    team_id,
                    repo_name,
                    commit_sha,
                    file_name,
                    channel,
                    destination,
                    status,
                    attempt_number,
                    error_message,
                    created_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    resolved.team_id,
                    repo_name,
                    commit_sha,
                    file_name,
                    channel,
                    destination,
                    normalized_status,
                    attempt_number,
                    (error_message or "").strip() or None,
                    created_at,
                ),
            )
        return {
            "id": int(cursor.lastrowid),
            "repo_name": repo_name,
            "commit_sha": commit_sha,
            "file_name": file_name,
            "channel": channel,
            "destination": destination,
            "status": normalized_status,
            "attempt_number": attempt_number,
            "error_message": (error_message or "").strip() or None,
            "created_at": created_at,
        }

    def list_alert_deliveries(
        self,
        ownership: OwnershipContext,
        limit: int = 20,
    ) -> List[Dict[str, Any]]:
        resolved = self.resolve_ownership(ownership)
        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT
                    id,
                    repo_name,
                    commit_sha,
                    file_name,
                    channel,
                    destination,
                    status,
                    attempt_number,
                    error_message,
                    created_at
                FROM alert_deliveries
                WHERE team_id = ?
                ORDER BY created_at DESC, id DESC
                LIMIT ?
                """,
                (resolved.team_id, limit),
            ).fetchall()
        return [dict(row) for row in rows]

    @staticmethod
    def _json(value: Any) -> str:
        return json_dumps(value)

    @staticmethod
    def _build_history_context(
        rows: List[Dict[str, Any]],
        rule_hits: List[str],
        exclude_commit_sha: Optional[str] = None,
    ) -> Dict[str, Any]:
        if exclude_commit_sha:
            rows = [row for row in rows if row["commit_sha"] != exclude_commit_sha]
        return build_history_context(rows, rule_hits)


class PostgresStoreBackend(BaseStoreBackend):
    backend_name = "postgresql"

    def __init__(self, database_url: str) -> None:
        if psycopg2 is None or RealDictCursor is None:
            raise RuntimeError(
                "PostgreSQL support requires psycopg2-binary. Install dependencies from requirements.txt."
            )
        self.database_url = database_url
        self._initialize()

    def _connect(self):
        return psycopg2.connect(self.database_url, cursor_factory=RealDictCursor)

    def _initialize(self) -> None:
        with self._connect() as connection:
            with connection.cursor() as cursor:
                cursor.execute(
                    """
                    CREATE TABLE IF NOT EXISTS teams (
                        id BIGSERIAL PRIMARY KEY,
                        slug TEXT NOT NULL UNIQUE,
                        name TEXT NOT NULL,
                        created_at TEXT NOT NULL
                    );

                    CREATE TABLE IF NOT EXISTS users (
                        id BIGSERIAL PRIMARY KEY,
                        email TEXT NOT NULL UNIQUE,
                        display_name TEXT NOT NULL,
                        password_salt TEXT,
                        password_hash TEXT,
                        created_at TEXT NOT NULL
                    );

                    CREATE TABLE IF NOT EXISTS team_memberships (
                        id BIGSERIAL PRIMARY KEY,
                        team_id BIGINT NOT NULL REFERENCES teams(id),
                        user_id BIGINT NOT NULL REFERENCES users(id),
                        role TEXT NOT NULL DEFAULT 'analyst',
                        created_at TEXT NOT NULL,
                        UNIQUE(team_id, user_id)
                    );

                    CREATE TABLE IF NOT EXISTS commits (
                        id BIGSERIAL PRIMARY KEY,
                        team_id BIGINT NOT NULL REFERENCES teams(id),
                        repo_name TEXT NOT NULL,
                        commit_sha TEXT NOT NULL,
                        author_name TEXT,
                        commit_message TEXT,
                        html_url TEXT,
                        analyzed_at TEXT NOT NULL,
                        created_by_user_id BIGINT REFERENCES users(id)
                    );

                    CREATE UNIQUE INDEX IF NOT EXISTS idx_commits_team_repo_sha
                        ON commits(team_id, repo_name, commit_sha);

                    CREATE TABLE IF NOT EXISTS findings (
                        id BIGSERIAL PRIMARY KEY,
                        team_id BIGINT NOT NULL REFERENCES teams(id),
                        commit_id BIGINT NOT NULL REFERENCES commits(id),
                        commit_sha TEXT NOT NULL,
                        file_name TEXT NOT NULL,
                        risk TEXT NOT NULL,
                        confidence INTEGER NOT NULL,
                        summary TEXT NOT NULL,
                        reasons_json TEXT NOT NULL,
                        indicators_json TEXT NOT NULL,
                        yara_rule TEXT,
                        raw_response TEXT NOT NULL,
                        created_at TEXT NOT NULL,
                        rule_hits_json TEXT NOT NULL DEFAULT '[]',
                        disposition TEXT NOT NULL DEFAULT 'new',
                        analyst_note TEXT NOT NULL DEFAULT '',
                        triaged_at TEXT,
                        history_context_json TEXT NOT NULL DEFAULT '{}',
                        suppression_context_json TEXT NOT NULL DEFAULT '{}',
                        triaged_by_user_id BIGINT REFERENCES users(id)
                    );

                    CREATE INDEX IF NOT EXISTS idx_findings_team_created
                        ON findings(team_id, created_at DESC);

                    CREATE TABLE IF NOT EXISTS repo_watchlists (
                        id BIGSERIAL PRIMARY KEY,
                        team_id BIGINT NOT NULL REFERENCES teams(id),
                        repo_name TEXT NOT NULL,
                        is_active BOOLEAN NOT NULL DEFAULT TRUE,
                        created_at TEXT NOT NULL,
                        last_scanned_at TEXT,
                        scan_interval_minutes INTEGER NOT NULL DEFAULT 60,
                        next_scan_at TEXT,
                        last_successful_scan_at TEXT,
                        last_failed_scan_at TEXT,
                        last_scan_error TEXT NOT NULL DEFAULT '',
                        UNIQUE(team_id, repo_name)
                    );

                    CREATE TABLE IF NOT EXISTS team_settings (
                        team_id BIGINT PRIMARY KEY REFERENCES teams(id),
                        alert_webhook_url TEXT,
                        alert_min_risk TEXT NOT NULL DEFAULT 'high',
                        alert_min_confidence INTEGER NOT NULL DEFAULT 80,
                        scans_enabled BOOLEAN NOT NULL DEFAULT TRUE,
                        scan_limit INTEGER NOT NULL DEFAULT 3,
                        scan_interval_minutes INTEGER NOT NULL DEFAULT 60,
                        updated_at TEXT NOT NULL
                    );

                    CREATE TABLE IF NOT EXISTS scan_runs (
                        id BIGSERIAL PRIMARY KEY,
                        team_id BIGINT NOT NULL REFERENCES teams(id),
                        repo_watchlist_id BIGINT NOT NULL REFERENCES repo_watchlists(id),
                        repo_name TEXT NOT NULL,
                        trigger_mode TEXT NOT NULL,
                        status TEXT NOT NULL,
                        started_at TEXT NOT NULL,
                        lock_expires_at TEXT,
                        completed_at TEXT,
                        error_message TEXT,
                        findings_created INTEGER NOT NULL DEFAULT 0,
                        high_risk_findings INTEGER NOT NULL DEFAULT 0,
                        scanner_user_id BIGINT REFERENCES users(id)
                    );

                    CREATE TABLE IF NOT EXISTS alert_deliveries (
                        id BIGSERIAL PRIMARY KEY,
                        team_id BIGINT NOT NULL REFERENCES teams(id),
                        repo_name TEXT NOT NULL,
                        commit_sha TEXT NOT NULL,
                        file_name TEXT NOT NULL,
                        channel TEXT NOT NULL,
                        destination TEXT NOT NULL,
                        status TEXT NOT NULL,
                        attempt_number INTEGER NOT NULL DEFAULT 1,
                        error_message TEXT,
                        created_at TEXT NOT NULL
                    );

                    CREATE INDEX IF NOT EXISTS idx_scan_runs_team_started
                        ON scan_runs(team_id, started_at DESC);
                    CREATE UNIQUE INDEX IF NOT EXISTS idx_scan_runs_running_lock
                        ON scan_runs(team_id, repo_watchlist_id)
                        WHERE status = 'running';
                    CREATE INDEX IF NOT EXISTS idx_alert_deliveries_team_created
                        ON alert_deliveries(team_id, created_at DESC);
                    """
                )
                cursor.execute("ALTER TABLE users ADD COLUMN IF NOT EXISTS password_salt TEXT")
                cursor.execute("ALTER TABLE users ADD COLUMN IF NOT EXISTS password_hash TEXT")
                cursor.execute(
                    "ALTER TABLE repo_watchlists ADD COLUMN IF NOT EXISTS scan_interval_minutes INTEGER NOT NULL DEFAULT 60"
                )
                cursor.execute("ALTER TABLE repo_watchlists ADD COLUMN IF NOT EXISTS next_scan_at TEXT")
                cursor.execute(
                    "ALTER TABLE repo_watchlists ADD COLUMN IF NOT EXISTS last_successful_scan_at TEXT"
                )
                cursor.execute("ALTER TABLE repo_watchlists ADD COLUMN IF NOT EXISTS last_failed_scan_at TEXT")
                cursor.execute(
                    "ALTER TABLE repo_watchlists ADD COLUMN IF NOT EXISTS last_scan_error TEXT NOT NULL DEFAULT ''"
                )
                cursor.execute(
                    "ALTER TABLE team_settings ADD COLUMN IF NOT EXISTS scan_interval_minutes INTEGER NOT NULL DEFAULT 60"
                )
                cursor.execute("ALTER TABLE scan_runs ADD COLUMN IF NOT EXISTS lock_expires_at TEXT")
                cursor.execute(
                    """
                    UPDATE repo_watchlists
                    SET scan_interval_minutes = COALESCE(scan_interval_minutes, %s),
                        next_scan_at = COALESCE(next_scan_at, created_at, %s),
                        last_scan_error = COALESCE(last_scan_error, '')
                    """
                    ,
                    (DEFAULT_SCAN_INTERVAL_MINUTES, utc_now_iso()),
                )
                cursor.execute(
                    """
                    UPDATE team_settings
                    SET scan_interval_minutes = COALESCE(scan_interval_minutes, %s)
                    """,
                    (DEFAULT_SCAN_INTERVAL_MINUTES,),
                )
            connection.commit()

    def resolve_ownership(self, context: OwnershipContext) -> OwnershipRecord:
        with self._connect() as connection:
            with connection.cursor() as cursor:
                cursor.execute(
                    """
                    INSERT INTO teams (slug, name, created_at)
                    VALUES (%s, %s, %s)
                    ON CONFLICT (slug) DO UPDATE SET name = EXCLUDED.name
                    RETURNING id, slug, name
                    """,
                    (context.team_slug, context.team_name, utc_now_iso()),
                )
                team = cursor.fetchone()

                cursor.execute(
                    """
                    INSERT INTO users (email, display_name, created_at)
                    VALUES (%s, %s, %s)
                    ON CONFLICT (email) DO UPDATE SET display_name = EXCLUDED.display_name
                    RETURNING id, email, display_name
                    """,
                    (context.user_email, context.user_name, utc_now_iso()),
                )
                user = cursor.fetchone()

                cursor.execute(
                    """
                    INSERT INTO team_memberships (team_id, user_id, role, created_at)
                    VALUES (%s, %s, 'analyst', %s)
                    ON CONFLICT (team_id, user_id) DO NOTHING
                    """,
                    (team["id"], user["id"], utc_now_iso()),
                )
            connection.commit()

        return OwnershipRecord(
            team_id=int(team["id"]),
            team_slug=str(team["slug"]),
            team_name=str(team["name"]),
            user_id=int(user["id"]),
            user_email=str(user["email"]),
            user_name=str(user["display_name"]),
        )

    def _ensure_team_settings_row(self, resolved: OwnershipRecord) -> None:
        with self._connect() as connection:
            with connection.cursor() as cursor:
                cursor.execute(
                    """
                    INSERT INTO team_settings (
                        team_id,
                        alert_webhook_url,
                        alert_min_risk,
                        alert_min_confidence,
                        scans_enabled,
                        scan_limit,
                        scan_interval_minutes,
                        updated_at
                    )
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                    ON CONFLICT (team_id) DO NOTHING
                    """,
                    (
                        resolved.team_id,
                        None,
                        DEFAULT_ALERT_MIN_RISK,
                        DEFAULT_ALERT_MIN_CONFIDENCE,
                        True,
                        DEFAULT_SCAN_LIMIT,
                        DEFAULT_SCAN_INTERVAL_MINUTES,
                        utc_now_iso(),
                    ),
                )
            connection.commit()

    def get_membership(self, team_slug: str, user_email: str) -> Optional[OwnershipRecord]:
        query = """
            SELECT
                teams.id AS team_id,
                teams.slug AS team_slug,
                teams.name AS team_name,
                users.id AS user_id,
                users.email AS user_email,
                users.display_name AS user_name
            FROM team_memberships
            JOIN teams ON team_memberships.team_id = teams.id
            JOIN users ON team_memberships.user_id = users.id
            WHERE teams.slug = %s AND users.email = %s
        """
        with self._connect() as connection:
            with connection.cursor() as cursor:
                cursor.execute(query, (team_slug, user_email.lower()))
                row = cursor.fetchone()
        if row is None:
            return None
        return OwnershipRecord(
            team_id=int(row["team_id"]),
            team_slug=str(row["team_slug"]),
            team_name=str(row["team_name"]),
            user_id=int(row["user_id"]),
            user_email=str(row["user_email"]),
            user_name=str(row["user_name"]),
        )

    def register_account(
        self,
        team_slug: str,
        team_name: str,
        user_email: str,
        user_name: str,
        password: str,
    ) -> OwnershipRecord:
        normalized_team_slug = team_slug.strip()
        normalized_team_name = team_name.strip()
        normalized_email = user_email.strip().lower()
        normalized_user_name = user_name.strip()
        ensure_password_strength(password)

        with self._connect() as connection:
            with connection.cursor() as cursor:
                cursor.execute("SELECT id FROM teams WHERE slug = %s", (normalized_team_slug,))
                if cursor.fetchone() is not None:
                    raise ValueError("Team slug is already in use.")

                cursor.execute(
                    """
                    SELECT id, password_salt, password_hash
                    FROM users
                    WHERE email = %s
                    """,
                    (normalized_email,),
                )
                existing_user = cursor.fetchone()
                if existing_user is None:
                    salt = generate_password_salt()
                    password_hash = hash_password(password, salt)
                    cursor.execute(
                        """
                        INSERT INTO users (email, display_name, password_salt, password_hash, created_at)
                        VALUES (%s, %s, %s, %s, %s)
                        RETURNING id, email, display_name
                        """,
                        (normalized_email, normalized_user_name, salt, password_hash, utc_now_iso()),
                    )
                    user = cursor.fetchone()
                else:
                    stored_salt = existing_user["password_salt"] or ""
                    stored_hash = existing_user["password_hash"] or ""
                    if not stored_salt or not stored_hash:
                        raise ValueError("This user exists without a login password. Reset support is required.")
                    if hash_password(password, stored_salt) != stored_hash:
                        raise ValueError("An account with this email already exists.")
                    cursor.execute(
                        """
                        UPDATE users
                        SET display_name = %s
                        WHERE id = %s
                        RETURNING id, email, display_name
                        """,
                        (normalized_user_name, existing_user["id"]),
                    )
                    user = cursor.fetchone()

                cursor.execute(
                    """
                    INSERT INTO teams (slug, name, created_at)
                    VALUES (%s, %s, %s)
                    RETURNING id, slug, name
                    """,
                    (normalized_team_slug, normalized_team_name, utc_now_iso()),
                )
                team = cursor.fetchone()
                cursor.execute(
                    """
                    INSERT INTO team_memberships (team_id, user_id, role, created_at)
                    VALUES (%s, %s, 'owner', %s)
                    """,
                    (team["id"], user["id"], utc_now_iso()),
                )
            connection.commit()

        return OwnershipRecord(
            team_id=int(team["id"]),
            team_slug=str(team["slug"]),
            team_name=str(team["name"]),
            user_id=int(user["id"]),
            user_email=str(user["email"]),
            user_name=str(user["display_name"]),
        )

    def authenticate_account(
        self,
        team_slug: str,
        user_email: str,
        password: str,
    ) -> Optional[OwnershipRecord]:
        normalized_email = user_email.strip().lower()
        with self._connect() as connection:
            with connection.cursor() as cursor:
                cursor.execute(
                    """
                    SELECT password_salt, password_hash
                    FROM users
                    WHERE email = %s
                    """,
                    (normalized_email,),
                )
                row = cursor.fetchone()
        if row is None:
            return None
        stored_salt = row["password_salt"] or ""
        stored_hash = row["password_hash"] or ""
        if not stored_salt or not stored_hash:
            return None
        if hash_password(password, stored_salt) != stored_hash:
            return None
        return self.get_membership(team_slug.strip(), normalized_email)

    def commit_exists(self, ownership: OwnershipContext, repo_name: str, commit_sha: str) -> bool:
        resolved = self.resolve_ownership(ownership)
        with self._connect() as connection:
            with connection.cursor() as cursor:
                cursor.execute(
                    """
                    SELECT 1
                    FROM commits
                    WHERE team_id = %s AND repo_name = %s AND commit_sha = %s
                    """,
                    (resolved.team_id, repo_name, commit_sha),
                )
                row = cursor.fetchone()
        return row is not None

    def save_commit_metadata(
        self,
        ownership: OwnershipContext,
        repo_name: str,
        commit_sha: str,
        author_name: Optional[str],
        commit_message: Optional[str],
        html_url: Optional[str],
    ) -> int:
        resolved = self.resolve_ownership(ownership)
        with self._connect() as connection:
            with connection.cursor() as cursor:
                cursor.execute(
                    """
                    INSERT INTO commits (
                        team_id, repo_name, commit_sha, author_name, commit_message, html_url, analyzed_at, created_by_user_id
                    )
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                    ON CONFLICT (team_id, repo_name, commit_sha) DO UPDATE
                    SET analyzed_at = EXCLUDED.analyzed_at
                    RETURNING id
                    """,
                    (
                        resolved.team_id,
                        repo_name,
                        commit_sha,
                        author_name,
                        commit_message,
                        html_url,
                        utc_now_iso(),
                        resolved.user_id,
                    ),
                )
                row = cursor.fetchone()
            connection.commit()
        return int(row["id"])

    def save_finding(
        self,
        ownership: OwnershipContext,
        repo_name: str,
        commit_sha: str,
        file_name: str,
        result: Any,
    ) -> int:
        resolved = self.resolve_ownership(ownership)
        commit_id = self.save_commit_metadata(
            ownership=ownership,
            repo_name=repo_name,
            commit_sha=commit_sha,
            author_name=None,
            commit_message=None,
            html_url=None,
        )
        with self._connect() as connection:
            with connection.cursor() as cursor:
                cursor.execute(
                    """
                    INSERT INTO findings (
                        team_id, commit_id, commit_sha, file_name, risk, confidence, summary,
                        reasons_json, indicators_json, yara_rule, raw_response, created_at,
                        rule_hits_json, disposition, analyst_note, triaged_at,
                        history_context_json, suppression_context_json, triaged_by_user_id
                    )
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                    RETURNING id
                    """,
                    (
                        resolved.team_id,
                        commit_id,
                        commit_sha,
                        file_name,
                        result.normalized_risk(),
                        result.confidence,
                        result.summary,
                        json_dumps(result.reasons),
                        json_dumps(result.indicators),
                        result.yara_rule,
                        result.raw_response,
                        utc_now_iso(),
                        json_dumps(result.rule_hits),
                        "new",
                        "",
                        None,
                        json_dumps(result.history_context),
                        json_dumps(result.suppression_context),
                        None,
                    ),
                )
                row = cursor.fetchone()
            connection.commit()
        return int(row["id"])

    def list_findings(
        self,
        ownership: OwnershipContext,
        limit: int = 20,
        risk: Optional[str] = None,
        repo_name: Optional[str] = None,
        disposition: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        resolved = self.resolve_ownership(ownership)
        query = """
            SELECT
                findings.id,
                teams.slug AS team_slug,
                teams.name AS team_name,
                commits.repo_name,
                findings.commit_sha,
                findings.file_name,
                findings.risk,
                findings.confidence,
                findings.summary,
                findings.created_at,
                findings.rule_hits_json,
                findings.disposition,
                findings.history_context_json,
                findings.suppression_context_json
            FROM findings
            JOIN commits ON findings.commit_id = commits.id
            JOIN teams ON findings.team_id = teams.id
            WHERE findings.team_id = %s
        """
        params: List[Any] = [resolved.team_id]
        if risk:
            query += " AND findings.risk = %s"
            params.append(risk.lower())
        if repo_name:
            query += " AND commits.repo_name = %s"
            params.append(repo_name)
        if disposition:
            query += " AND findings.disposition = %s"
            params.append(disposition)
        query += " ORDER BY findings.created_at DESC, findings.id DESC LIMIT %s"
        params.append(limit)
        with self._connect() as connection:
            with connection.cursor() as cursor:
                cursor.execute(query, params)
                return [dict(row) for row in cursor.fetchall()]

    def get_finding(
        self,
        ownership: OwnershipContext,
        finding_id: int,
    ) -> Optional[Dict[str, Any]]:
        resolved = self.resolve_ownership(ownership)
        query = """
            SELECT
                findings.id,
                teams.slug AS team_slug,
                teams.name AS team_name,
                commits.repo_name,
                findings.commit_sha,
                commits.author_name,
                commits.commit_message,
                commits.html_url,
                findings.file_name,
                findings.risk,
                findings.confidence,
                findings.summary,
                findings.reasons_json,
                findings.indicators_json,
                findings.yara_rule,
                findings.rule_hits_json,
                findings.raw_response,
                findings.created_at,
                findings.disposition,
                findings.analyst_note,
                findings.triaged_at,
                findings.history_context_json,
                findings.suppression_context_json,
                triager.email AS triaged_by_user_email,
                triager.display_name AS triaged_by_user_name
            FROM findings
            JOIN commits ON findings.commit_id = commits.id
            JOIN teams ON findings.team_id = teams.id
            LEFT JOIN users AS triager ON findings.triaged_by_user_id = triager.id
            WHERE findings.id = %s AND findings.team_id = %s
        """
        with self._connect() as connection:
            with connection.cursor() as cursor:
                cursor.execute(query, (finding_id, resolved.team_id))
                row = cursor.fetchone()
        return dict(row) if row else None

    def get_history_context(
        self,
        ownership: OwnershipContext,
        repo_name: str,
        file_name: str,
        rule_hits: List[str],
        exclude_commit_sha: Optional[str] = None,
        limit: int = 25,
    ) -> Dict[str, Any]:
        resolved = self.resolve_ownership(ownership)
        query = """
            SELECT
                findings.id,
                findings.commit_sha,
                findings.rule_hits_json,
                findings.disposition
            FROM findings
            JOIN commits ON findings.commit_id = commits.id
            WHERE findings.team_id = %s AND commits.repo_name = %s AND findings.file_name = %s
            ORDER BY findings.created_at DESC, findings.id DESC
            LIMIT %s
        """
        with self._connect() as connection:
            with connection.cursor() as cursor:
                cursor.execute(query, (resolved.team_id, repo_name, file_name, limit))
                rows = [dict(row) for row in cursor.fetchall()]
        return build_history_context(rows, rule_hits, exclude_commit_sha)

    def update_finding_triage(
        self,
        ownership: OwnershipContext,
        finding_id: int,
        disposition: str,
        analyst_note: Optional[str] = None,
        clear_note: bool = False,
    ) -> bool:
        normalized = disposition.strip().lower()
        if normalized not in VALID_DISPOSITIONS:
            raise ValueError(f"Invalid disposition: {disposition}")

        resolved = self.resolve_ownership(ownership)
        with self._connect() as connection:
            with connection.cursor() as cursor:
                cursor.execute(
                    """
                    SELECT analyst_note
                    FROM findings
                    WHERE id = %s AND team_id = %s
                    """,
                    (finding_id, resolved.team_id),
                )
                current = cursor.fetchone()
                if current is None:
                    return False

                if clear_note:
                    note_value = ""
                elif analyst_note is None:
                    note_value = current["analyst_note"]
                else:
                    note_value = analyst_note.strip()

                cursor.execute(
                    """
                    UPDATE findings
                    SET disposition = %s, analyst_note = %s, triaged_at = %s, triaged_by_user_id = %s
                    WHERE id = %s AND team_id = %s
                    """,
                    (
                        normalized,
                        note_value,
                        utc_now_iso(),
                        resolved.user_id,
                        finding_id,
                        resolved.team_id,
                    ),
                )
            connection.commit()
        return True

    def list_repo_watchlists(
        self,
        ownership: OwnershipContext,
        include_inactive: bool = False,
    ) -> List[Dict[str, Any]]:
        resolved = self.resolve_ownership(ownership)
        query = """
            SELECT
                id,
                team_id,
                repo_name,
                is_active,
                created_at,
                last_scanned_at,
                scan_interval_minutes,
                next_scan_at,
                last_successful_scan_at,
                last_failed_scan_at,
                last_scan_error
            FROM repo_watchlists
            WHERE team_id = %s
        """
        params: List[Any] = [resolved.team_id]
        if not include_inactive:
            query += " AND is_active = TRUE"
        query += " ORDER BY repo_name ASC"
        with self._connect() as connection:
            with connection.cursor() as cursor:
                cursor.execute(query, params)
                return [dict(row) for row in cursor.fetchall()]

    def add_repo_watchlist(
        self,
        ownership: OwnershipContext,
        repo_name: str,
    ) -> Dict[str, Any]:
        normalized_repo = normalize_repo_name(repo_name)
        resolved = self.resolve_ownership(ownership)
        scan_interval_minutes = self.get_team_settings(ownership)["scan_interval_minutes"]
        created_at = utc_now_iso()
        with self._connect() as connection:
            with connection.cursor() as cursor:
                cursor.execute(
                    """
                    INSERT INTO repo_watchlists (
                        team_id,
                        repo_name,
                        is_active,
                        created_at,
                        last_scanned_at,
                        scan_interval_minutes,
                        next_scan_at,
                        last_successful_scan_at,
                        last_failed_scan_at,
                        last_scan_error
                    )
                    VALUES (%s, %s, TRUE, %s, NULL, %s, %s, NULL, NULL, '')
                    ON CONFLICT(team_id, repo_name) DO UPDATE SET
                        is_active = TRUE,
                        scan_interval_minutes = EXCLUDED.scan_interval_minutes,
                        next_scan_at = COALESCE(repo_watchlists.next_scan_at, EXCLUDED.next_scan_at)
                    RETURNING
                        id,
                        team_id,
                        repo_name,
                        is_active,
                        created_at,
                        last_scanned_at,
                        scan_interval_minutes,
                        next_scan_at,
                        last_successful_scan_at,
                        last_failed_scan_at,
                        last_scan_error
                    """,
                    (
                        resolved.team_id,
                        normalized_repo,
                        created_at,
                        scan_interval_minutes,
                        created_at,
                    ),
                )
                row = cursor.fetchone()
            connection.commit()
        return dict(row)

    def deactivate_repo_watchlist(
        self,
        ownership: OwnershipContext,
        watchlist_id: int,
    ) -> bool:
        resolved = self.resolve_ownership(ownership)
        with self._connect() as connection:
            with connection.cursor() as cursor:
                cursor.execute(
                    """
                    UPDATE repo_watchlists
                    SET is_active = FALSE
                    WHERE id = %s AND team_id = %s
                    """,
                    (watchlist_id, resolved.team_id),
                )
                updated = cursor.rowcount > 0
            connection.commit()
        return updated

    def get_team_settings(self, ownership: OwnershipContext) -> Dict[str, Any]:
        resolved = self.resolve_ownership(ownership)
        self._ensure_team_settings_row(resolved)
        with self._connect() as connection:
            with connection.cursor() as cursor:
                cursor.execute(
                    """
                    SELECT
                        team_id,
                        alert_webhook_url,
                        alert_min_risk,
                        alert_min_confidence,
                        scans_enabled,
                        scan_limit,
                        scan_interval_minutes,
                        updated_at
                    FROM team_settings
                    WHERE team_id = %s
                    """,
                    (resolved.team_id,),
                )
                row = cursor.fetchone()
        if row is None:
            raise ValueError(f"Team settings missing for team {resolved.team_slug}")
        payload = dict(row)
        payload["scans_enabled"] = bool(payload["scans_enabled"])
        return payload

    def update_team_settings(
        self,
        ownership: OwnershipContext,
        *,
        alert_webhook_url: Optional[str] = None,
        alert_min_risk: Optional[str] = None,
        alert_min_confidence: Optional[int] = None,
        scans_enabled: Optional[bool] = None,
        scan_limit: Optional[int] = None,
        scan_interval_minutes: Optional[int] = None,
    ) -> Dict[str, Any]:
        resolved = self.resolve_ownership(ownership)
        self._ensure_team_settings_row(resolved)
        current = self.get_team_settings(ownership)
        next_values = {
            "alert_webhook_url": (
                None
                if alert_webhook_url is not None and not alert_webhook_url.strip()
                else current["alert_webhook_url"]
                if alert_webhook_url is None
                else alert_webhook_url.strip()
            ),
            "alert_min_risk": normalize_risk_level(alert_min_risk or current["alert_min_risk"]),
            "alert_min_confidence": normalize_confidence_threshold(
                current["alert_min_confidence"] if alert_min_confidence is None else alert_min_confidence
            ),
            "scans_enabled": current["scans_enabled"] if scans_enabled is None else bool(scans_enabled),
            "scan_limit": normalize_scan_limit(current["scan_limit"] if scan_limit is None else scan_limit),
            "scan_interval_minutes": normalize_scan_interval_minutes(
                current["scan_interval_minutes"] if scan_interval_minutes is None else scan_interval_minutes
            ),
            "updated_at": utc_now_iso(),
        }
        with self._connect() as connection:
            with connection.cursor() as cursor:
                cursor.execute(
                    """
                    UPDATE team_settings
                    SET alert_webhook_url = %s,
                        alert_min_risk = %s,
                        alert_min_confidence = %s,
                        scans_enabled = %s,
                        scan_limit = %s,
                        scan_interval_minutes = %s,
                        updated_at = %s
                    WHERE team_id = %s
                    """,
                    (
                        next_values["alert_webhook_url"],
                        next_values["alert_min_risk"],
                        next_values["alert_min_confidence"],
                        next_values["scans_enabled"],
                        next_values["scan_limit"],
                        next_values["scan_interval_minutes"],
                        next_values["updated_at"],
                        resolved.team_id,
                    ),
                )
                cursor.execute(
                    """
                    UPDATE repo_watchlists
                    SET scan_interval_minutes = %s
                    WHERE team_id = %s
                    """,
                    (next_values["scan_interval_minutes"], resolved.team_id),
                )
            connection.commit()
        return self.get_team_settings(ownership)

    def create_scan_run(
        self,
        ownership: OwnershipContext,
        repo_watchlist_id: int,
        repo_name: str,
        trigger_mode: str,
    ) -> int:
        resolved = self.resolve_ownership(ownership)
        with self._connect() as connection:
            with connection.cursor() as cursor:
                cursor.execute(
                    """
                    INSERT INTO scan_runs (
                        team_id,
                        repo_watchlist_id,
                        repo_name,
                    trigger_mode,
                    status,
                    started_at,
                    lock_expires_at,
                    completed_at,
                    error_message,
                    findings_created,
                        high_risk_findings,
                        scanner_user_id
                    )
                    VALUES (%s, %s, %s, %s, 'running', %s, %s, NULL, NULL, 0, 0, %s)
                    RETURNING id
                    """,
                    (
                        resolved.team_id,
                        repo_watchlist_id,
                        repo_name,
                        trigger_mode,
                        utc_now_iso(),
                        utc_future_iso(DEFAULT_SCAN_LOCK_MINUTES),
                        resolved.user_id,
                    ),
                )
                row = cursor.fetchone()
            connection.commit()
        return int(row["id"])

    def claim_scan_run(
        self,
        ownership: OwnershipContext,
        repo_watchlist_id: int,
        repo_name: str,
        trigger_mode: str,
        lock_timeout_minutes: int = DEFAULT_SCAN_LOCK_MINUTES,
    ) -> Optional[Dict[str, Any]]:
        resolved = self.resolve_ownership(ownership)
        now = utc_now_iso()
        lock_expires_at = utc_future_iso(lock_timeout_minutes)
        with self._connect() as connection:
            with connection.cursor() as cursor:
                cursor.execute(
                    """
                    UPDATE scan_runs
                    SET status = 'failed',
                        completed_at = %s,
                        error_message = COALESCE(error_message, 'Scan lock expired before completion.'),
                        lock_expires_at = NULL
                    WHERE team_id = %s
                      AND repo_watchlist_id = %s
                      AND status = 'running'
                      AND lock_expires_at IS NOT NULL
                      AND lock_expires_at <= %s
                    """,
                    (now, resolved.team_id, repo_watchlist_id, now),
                )
                try:
                    cursor.execute(
                        """
                        INSERT INTO scan_runs (
                            team_id,
                            repo_watchlist_id,
                            repo_name,
                            trigger_mode,
                            status,
                            started_at,
                            lock_expires_at,
                            completed_at,
                            error_message,
                            findings_created,
                            high_risk_findings,
                            scanner_user_id
                        )
                        VALUES (%s, %s, %s, %s, 'running', %s, %s, NULL, NULL, 0, 0, %s)
                        RETURNING id
                        """,
                        (
                            resolved.team_id,
                            repo_watchlist_id,
                            repo_name,
                            trigger_mode,
                            now,
                            lock_expires_at,
                            resolved.user_id,
                        ),
                    )
                except psycopg2.errors.UniqueViolation:
                    connection.rollback()
                    return None
                row = cursor.fetchone()
            connection.commit()
        return {
            "id": int(row["id"]),
            "repo_watchlist_id": repo_watchlist_id,
            "repo_name": repo_name,
            "trigger_mode": trigger_mode,
            "status": "running",
            "started_at": now,
            "lock_expires_at": lock_expires_at,
        }

    def complete_scan_run(
        self,
        ownership: OwnershipContext,
        scan_run_id: int,
        *,
        status: str,
        findings_created: int = 0,
        high_risk_findings: int = 0,
        error_message: Optional[str] = None,
    ) -> bool:
        normalized_status = normalize_scan_status(status)
        resolved = self.resolve_ownership(ownership)
        with self._connect() as connection:
            with connection.cursor() as cursor:
                cursor.execute(
                    """
                    SELECT repo_watchlist_id
                    FROM scan_runs
                    WHERE id = %s AND team_id = %s
                    """,
                    (scan_run_id, resolved.team_id),
                )
                row = cursor.fetchone()
                if row is None:
                    return False
                cursor.execute(
                    """
                    UPDATE scan_runs
                    SET status = %s,
                        completed_at = %s,
                        error_message = %s,
                        lock_expires_at = NULL,
                        findings_created = %s,
                        high_risk_findings = %s
                    WHERE id = %s AND team_id = %s
                    """,
                    (
                        normalized_status,
                        utc_now_iso(),
                        (error_message or "").strip() or None,
                        max(0, int(findings_created)),
                        max(0, int(high_risk_findings)),
                        scan_run_id,
                        resolved.team_id,
                    ),
                )
                cursor.execute(
                    """
                    SELECT scan_interval_minutes
                    FROM repo_watchlists
                    WHERE id = %s AND team_id = %s
                    """,
                    (row["repo_watchlist_id"], resolved.team_id),
                )
                watchlist = cursor.fetchone()
                if watchlist is not None and normalized_status == "completed":
                    completed_at = utc_now_iso()
                    next_scan_at = utc_future_iso(
                        watchlist["scan_interval_minutes"] or DEFAULT_SCAN_INTERVAL_MINUTES
                    )
                    cursor.execute(
                        """
                        UPDATE repo_watchlists
                        SET last_scanned_at = %s,
                            next_scan_at = %s,
                            last_successful_scan_at = %s,
                            last_scan_error = ''
                        WHERE id = %s AND team_id = %s
                        """,
                        (
                            completed_at,
                            next_scan_at,
                            completed_at,
                            row["repo_watchlist_id"],
                            resolved.team_id,
                        ),
                    )
                elif watchlist is not None:
                    completed_at = utc_now_iso()
                    next_scan_at = utc_future_iso(
                        watchlist["scan_interval_minutes"] or DEFAULT_SCAN_INTERVAL_MINUTES
                    )
                    cursor.execute(
                        """
                        UPDATE repo_watchlists
                        SET last_scanned_at = %s,
                            next_scan_at = %s,
                            last_failed_scan_at = %s,
                            last_scan_error = %s
                        WHERE id = %s AND team_id = %s
                        """,
                        (
                            completed_at,
                            next_scan_at,
                            completed_at,
                            (error_message or "").strip() or "Scan failed.",
                            row["repo_watchlist_id"],
                            resolved.team_id,
                        ),
                    )
            connection.commit()
        return True

    def list_scan_runs(
        self,
        ownership: OwnershipContext,
        limit: int = 20,
    ) -> List[Dict[str, Any]]:
        resolved = self.resolve_ownership(ownership)
        with self._connect() as connection:
            with connection.cursor() as cursor:
                cursor.execute(
                    """
                    SELECT
                        id,
                        repo_watchlist_id,
                        repo_name,
                        trigger_mode,
                        status,
                        started_at,
                        lock_expires_at,
                        completed_at,
                        error_message,
                        findings_created,
                        high_risk_findings
                    FROM scan_runs
                    WHERE team_id = %s
                    ORDER BY started_at DESC, id DESC
                    LIMIT %s
                    """,
                    (resolved.team_id, limit),
                )
                return [dict(row) for row in cursor.fetchall()]

    def get_repo_watchlist(
        self,
        ownership: OwnershipContext,
        watchlist_id: int,
    ) -> Optional[Dict[str, Any]]:
        resolved = self.resolve_ownership(ownership)
        with self._connect() as connection:
            with connection.cursor() as cursor:
                cursor.execute(
                    """
                    SELECT
                        id,
                        team_id,
                        repo_name,
                        is_active,
                        created_at,
                        last_scanned_at,
                        scan_interval_minutes,
                        next_scan_at,
                        last_successful_scan_at,
                        last_failed_scan_at,
                        last_scan_error
                    FROM repo_watchlists
                    WHERE id = %s AND team_id = %s
                    """,
                    (watchlist_id, resolved.team_id),
                )
                row = cursor.fetchone()
        if row is None:
            return None
        payload = dict(row)
        payload["is_active"] = bool(payload["is_active"])
        return payload

    def list_scan_targets(
        self,
        *,
        team_slug: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        query = """
            SELECT
                repo_watchlists.id AS repo_watchlist_id,
                repo_watchlists.repo_name,
                repo_watchlists.last_scanned_at,
                repo_watchlists.scan_interval_minutes,
                repo_watchlists.next_scan_at,
                repo_watchlists.last_successful_scan_at,
                repo_watchlists.last_failed_scan_at,
                repo_watchlists.last_scan_error,
                teams.slug AS team_slug,
                teams.name AS team_name,
                team_settings.alert_webhook_url,
                team_settings.alert_min_risk,
                team_settings.alert_min_confidence,
                team_settings.scans_enabled,
                team_settings.scan_limit,
                team_settings.scan_interval_minutes AS team_scan_interval_minutes
            FROM repo_watchlists
            JOIN teams ON repo_watchlists.team_id = teams.id
            LEFT JOIN team_settings ON repo_watchlists.team_id = team_settings.team_id
            WHERE repo_watchlists.is_active = TRUE
        """
        params: List[Any] = []
        if team_slug:
            query += " AND teams.slug = %s"
            params.append(team_slug)
        query += " ORDER BY teams.slug ASC, repo_watchlists.repo_name ASC"
        with self._connect() as connection:
            with connection.cursor() as cursor:
                cursor.execute(query, params)
                rows = [dict(row) for row in cursor.fetchall()]
        for row in rows:
            row["scans_enabled"] = bool(row["scans_enabled"]) if row["scans_enabled"] is not None else True
            row["alert_min_risk"] = normalize_risk_level(
                row["alert_min_risk"] or DEFAULT_ALERT_MIN_RISK
            )
            row["alert_min_confidence"] = normalize_confidence_threshold(
                row["alert_min_confidence"] if row["alert_min_confidence"] is not None else DEFAULT_ALERT_MIN_CONFIDENCE
            )
            row["scan_limit"] = normalize_scan_limit(
                row["scan_limit"] if row["scan_limit"] is not None else DEFAULT_SCAN_LIMIT
            )
            row["scan_interval_minutes"] = normalize_scan_interval_minutes(
                row["scan_interval_minutes"]
                if row["scan_interval_minutes"] is not None
                else row.get("team_scan_interval_minutes") or DEFAULT_SCAN_INTERVAL_MINUTES
            )
        return rows

    def record_alert_delivery(
        self,
        ownership: OwnershipContext,
        repo_name: str,
        commit_sha: str,
        file_name: str,
        channel: str,
        destination: str,
        status: str,
        error_message: Optional[str] = None,
    ) -> Dict[str, Any]:
        resolved = self.resolve_ownership(ownership)
        normalized_status = normalize_delivery_status(status)
        with self._connect() as connection:
            with connection.cursor() as cursor:
                cursor.execute(
                    """
                    SELECT COALESCE(MAX(attempt_number), 0) AS last_attempt
                    FROM alert_deliveries
                    WHERE team_id = %s
                      AND repo_name = %s
                      AND commit_sha = %s
                      AND file_name = %s
                      AND channel = %s
                      AND destination = %s
                    """,
                    (
                        resolved.team_id,
                        repo_name,
                        commit_sha,
                        file_name,
                        channel,
                        destination,
                    ),
                )
                row = cursor.fetchone()
                attempt_number = int(row["last_attempt"]) + 1
                created_at = utc_now_iso()
                cursor.execute(
                    """
                    INSERT INTO alert_deliveries (
                        team_id,
                        repo_name,
                        commit_sha,
                        file_name,
                        channel,
                        destination,
                        status,
                        attempt_number,
                        error_message,
                        created_at
                    )
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                    RETURNING id
                    """,
                    (
                        resolved.team_id,
                        repo_name,
                        commit_sha,
                        file_name,
                        channel,
                        destination,
                        normalized_status,
                        attempt_number,
                        (error_message or "").strip() or None,
                        created_at,
                    ),
                )
                inserted = cursor.fetchone()
            connection.commit()
        return {
            "id": int(inserted["id"]),
            "repo_name": repo_name,
            "commit_sha": commit_sha,
            "file_name": file_name,
            "channel": channel,
            "destination": destination,
            "status": normalized_status,
            "attempt_number": attempt_number,
            "error_message": (error_message or "").strip() or None,
            "created_at": created_at,
        }

    def list_alert_deliveries(
        self,
        ownership: OwnershipContext,
        limit: int = 20,
    ) -> List[Dict[str, Any]]:
        resolved = self.resolve_ownership(ownership)
        with self._connect() as connection:
            with connection.cursor() as cursor:
                cursor.execute(
                    """
                    SELECT
                        id,
                        repo_name,
                        commit_sha,
                        file_name,
                        channel,
                        destination,
                        status,
                        attempt_number,
                        error_message,
                        created_at
                    FROM alert_deliveries
                    WHERE team_id = %s
                    ORDER BY created_at DESC, id DESC
                    LIMIT %s
                    """,
                    (resolved.team_id, limit),
                )
                return [dict(row) for row in cursor.fetchall()]


class FindingStore:
    def __init__(
        self,
        db_path: Optional[Path] = None,
        database_url: Optional[str] = None,
    ) -> None:
        self.database_url = database_url or default_database_url()
        if self.database_url and self.database_url.strip().lower().startswith("sqlite:///"):
            self.db_path = sqlite_path_from_url(self.database_url)
        else:
            self.db_path = db_path or default_database_path()
        self.backend_name = infer_backend_name(self.database_url, self.db_path)
        if self.backend_name == "postgresql":
            self._backend: BaseStoreBackend = PostgresStoreBackend(self.database_url or "")
        else:
            self._backend = SQLiteStoreBackend(self.db_path)

    def __getattr__(self, item: str) -> Any:
        return getattr(self._backend, item)


def json_dumps(value: Any) -> str:
    return json.dumps(value)


def generate_password_salt() -> str:
    return secrets.token_hex(16)


def hash_password(password: str, salt: str) -> str:
    return hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt.encode("utf-8"),
        200_000,
    ).hex()


def ensure_password_strength(password: str) -> None:
    if len(password) < 8:
        raise ValueError("Password must be at least 8 characters long.")


def normalize_repo_name(repo_name: str) -> str:
    normalized = repo_name.strip()
    if normalized.count("/") != 1:
        raise ValueError("Repository must be in owner/name format.")
    owner, repo = normalized.split("/", 1)
    owner = owner.strip()
    repo = repo.strip()
    if not owner or not repo:
        raise ValueError("Repository must be in owner/name format.")
    return f"{owner}/{repo}"


def normalize_risk_level(risk: str) -> str:
    normalized = (risk or "").strip().lower()
    if normalized not in {"low", "medium", "high"}:
        raise ValueError("alert_min_risk must be one of: low, medium, high")
    return normalized


def normalize_confidence_threshold(value: int) -> int:
    confidence = int(value)
    return max(0, min(100, confidence))


def normalize_scan_limit(value: int) -> int:
    limit = int(value)
    if limit < 1:
        raise ValueError("scan_limit must be at least 1")
    return min(limit, 50)


def normalize_scan_interval_minutes(value: int) -> int:
    interval = int(value)
    if interval < 1:
        raise ValueError("scan_interval_minutes must be at least 1")
    return min(interval, 7 * 24 * 60)


def normalize_scan_status(value: str) -> str:
    normalized = (value or "").strip().lower()
    if normalized not in {"running", "completed", "failed"}:
        raise ValueError("Invalid scan run status")
    return normalized


def normalize_delivery_status(value: str) -> str:
    normalized = (value or "").strip().lower()
    if normalized not in {"delivered", "failed"}:
        raise ValueError("Invalid delivery status")
    return normalized


def utc_future_iso(minutes: int) -> str:
    return (datetime.now(timezone.utc) + timedelta(minutes=int(minutes))).isoformat()


def build_history_context(
    rows: List[Dict[str, Any]],
    rule_hits: List[str],
    exclude_commit_sha: Optional[str] = None,
) -> Dict[str, Any]:
    if exclude_commit_sha:
        rows = [row for row in rows if row["commit_sha"] != exclude_commit_sha]

    context: Dict[str, Any] = {
        "same_file_finding_count": len(rows),
        "matching_rule_hit_count": 0,
        "matching_true_positive_count": 0,
        "matching_false_positive_count": 0,
        "matching_ignored_count": 0,
        "related_finding_ids": [],
        "adjustment": "none",
        "note": "",
    }
    if not rows or not rule_hits:
        return context

    current_rule_hits = set(rule_hits)
    matching_rows = []
    for row in rows:
        prior_rule_hits = set(json.loads(row.get("rule_hits_json") or "[]"))
        if prior_rule_hits.intersection(current_rule_hits):
            matching_rows.append(row)

    context["matching_rule_hit_count"] = len(matching_rows)
    context["related_finding_ids"] = [row["id"] for row in matching_rows[:5]]
    context["matching_true_positive_count"] = sum(
        1 for row in matching_rows if row["disposition"] == "true_positive"
    )
    context["matching_false_positive_count"] = sum(
        1 for row in matching_rows if row["disposition"] == "false_positive"
    )
    context["matching_ignored_count"] = sum(
        1 for row in matching_rows if row["disposition"] == "ignored"
    )

    softening_count = (
        context["matching_false_positive_count"] + context["matching_ignored_count"]
    )
    if softening_count >= 1 and context["matching_true_positive_count"] == 0:
        context["adjustment"] = "reduced"
        context["note"] = (
            f"Historical context reduced risk because {softening_count} similar "
            "finding(s) in this team/repo/file were previously triaged as false positive or ignored."
        )
    elif context["matching_true_positive_count"] >= 1:
        context["adjustment"] = "reinforced"
        context["note"] = (
            f"Historical context reinforced confidence because "
            f"{context['matching_true_positive_count']} similar finding(s) in this team/repo/file "
            "were previously confirmed as true positive."
        )

    return context

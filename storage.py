import json
import os
import sqlite3
from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
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
                    UNIQUE(team_id, repo_name),
                    FOREIGN KEY(team_id) REFERENCES teams(id)
                );

                CREATE INDEX IF NOT EXISTS idx_commits_team_repo_sha
                    ON commits(team_id, repo_name, commit_sha);
                CREATE INDEX IF NOT EXISTS idx_findings_team_created
                    ON findings(team_id, created_at DESC);
                CREATE INDEX IF NOT EXISTS idx_findings_commit
                    ON findings(commit_id);
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
                        UNIQUE(team_id, repo_name)
                    );
                    """
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

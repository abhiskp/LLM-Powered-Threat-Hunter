import base64
import hashlib
import hmac
import json
import os
from datetime import datetime, timezone
from typing import Any, Dict, Optional


SESSION_COOKIE_NAME = "watchman_session"
DEFAULT_SESSION_SECRET = os.getenv("WATCHMAN_SESSION_SECRET", "change-me-in-production")
SESSION_MAX_AGE_SECONDS = int(os.getenv("WATCHMAN_SESSION_MAX_AGE_SECONDS", "604800"))


def _b64encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("utf-8").rstrip("=")


def _b64decode(value: str) -> bytes:
    padding = "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode(value + padding)


def _session_secret() -> bytes:
    return DEFAULT_SESSION_SECRET.encode("utf-8")


def create_session_cookie(team_slug: str, user_email: str) -> str:
    payload = {
        "team_slug": team_slug,
        "user_email": user_email.lower(),
        "issued_at": datetime.now(timezone.utc).timestamp(),
    }
    payload_raw = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
    payload_part = _b64encode(payload_raw)
    signature = hmac.new(_session_secret(), payload_part.encode("utf-8"), hashlib.sha256).hexdigest()
    return f"{payload_part}.{signature}"


def parse_session_cookie(cookie_value: Optional[str]) -> Optional[Dict[str, Any]]:
    if not cookie_value:
        return None
    try:
        payload_part, signature = cookie_value.split(".", 1)
    except ValueError:
        return None

    expected = hmac.new(_session_secret(), payload_part.encode("utf-8"), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(signature, expected):
        return None

    try:
        payload = json.loads(_b64decode(payload_part).decode("utf-8"))
    except (ValueError, json.JSONDecodeError):
        return None

    issued_at = float(payload.get("issued_at", 0))
    age_seconds = datetime.now(timezone.utc).timestamp() - issued_at
    if age_seconds < 0 or age_seconds > SESSION_MAX_AGE_SECONDS:
        return None

    if not payload.get("team_slug") or not payload.get("user_email"):
        return None
    return payload

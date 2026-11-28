import os
from dotenv import load_dotenv

load_dotenv()


def _as_bool(value: str | None, default: bool = False) -> bool:
    if value is None:
        return default
    return value.strip().lower() in ("1", "true", "yes", "on")


def _normalize_database_url(url: str | None) -> str:
    if not url:
        return "sqlite:///buildcompare_dev.db"
    if url.startswith("postgres://"):
        return url.replace("postgres://", "postgresql+psycopg://", 1)
    if url.startswith("postgresql://") and "+psycopg" not in url:
        return url.replace("postgresql://", "postgresql+psycopg://", 1)
    return url


class Config:
    SECRET_KEY = os.getenv("SECRET_KEY", "dev-secret-key")
    SQLALCHEMY_DATABASE_URI = _normalize_database_url(os.getenv("DATABASE_URL"))
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # Session & Cookie Security
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    SESSION_COOKIE_SECURE = _as_bool(
        os.getenv("SESSION_COOKIE_SECURE"),
        default=_as_bool(os.getenv("RENDER")),
    )
    PERMANENT_SESSION_LIFETIME = int(
        os.getenv("PERMANENT_SESSION_LIFETIME", str(60 * 60 * 12))
    )

    # Rate Limiter Settings
    RATELIMIT_STORAGE_URI = os.getenv("RATELIMIT_STORAGE_URI", "memory://")
    RATELIMIT_HEADERS_ENABLED = True

    # Auth Route Rate Limits
    AUTH_LOGIN_LIMIT = os.getenv("AUTH_LOGIN_LIMIT", "10 per minute; 50 per hour")
    AUTH_REGISTER_LIMIT = os.getenv("AUTH_REGISTER_LIMIT", "5 per minute; 20 per hour")
    AUTH_ADMIN_SETUP_LIMIT = os.getenv(
        "AUTH_ADMIN_SETUP_LIMIT", "5 per minute; 15 per hour"
    )
    AUTH_FORGOT_LIMIT = os.getenv("AUTH_FORGOT_LIMIT", "5 per minute; 15 per hour")
    AUTH_RESET_LIMIT = os.getenv("AUTH_RESET_LIMIT", "10 per minute")

    # Upload & Email Timeouts
    MAX_PERMIT_SIZE_BYTES = int(
        os.getenv("MAX_PERMIT_SIZE_BYTES", str(5 * 1024 * 1024))
    )
    BREVO_TIMEOUT_SECONDS = int(os.getenv("BREVO_TIMEOUT_SECONDS", "8"))
    SMTP_TIMEOUT_SECONDS = int(os.getenv("SMTP_TIMEOUT_SECONDS", "10"))


class TestConfig(Config):
    TESTING = True
    SQLALCHEMY_DATABASE_URI = "sqlite:///:memory:"
    WTF_CSRF_ENABLED = False    
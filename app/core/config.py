"""Single, immutable configuration source for the authentication service.

The service reads one ``.env`` file and validates all cross-field security rules
before FastAPI starts accepting traffic. Database schema creation and migrations
remain the responsibility of the external migration service.
"""

from __future__ import annotations

import base64
import logging
from enum import StrEnum
from functools import lru_cache
from pathlib import Path
from urllib.parse import urlparse
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from cryptography.hazmat.primitives.serialization import (
    load_pem_private_key,
    load_pem_public_key,
)
from pydantic import Field, SecretStr, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Environment(StrEnum):
    """Supported runtime environments."""

    DEVELOPMENT = "development"
    TESTING = "testing"
    STAGING = "staging"
    PRODUCTION = "production"


class RateLimitBackend(StrEnum):
    """Supported request rate-limit storage backends."""

    DISABLED = "disabled"
    MEMORY = "memory"
    REDIS = "redis"


class JWTAlgorithm(StrEnum):
    """Supported JWT signing algorithms."""

    HS256 = "HS256"
    RS256 = "RS256"


class AppSettings(BaseSettings):
    """Validated process-level settings.

    No other settings class exists in this project. Request handlers obtain this
    exact instance from ``app.state.settings`` through dependency injection.
    """

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
        frozen=True,
    )

    # Application
    ENVIRONMENT: Environment = Environment.DEVELOPMENT
    PROJECT_NAME: str = "pharmacy_identity_service"
    API_V1_STR: str = "/api/v1"
    APP_VERSION: str = "1.0.0"
    DEBUG: bool = False
    TIMEZONE: str = "Asia/Kolkata"
    BASE_DIR: Path = Path(__file__).resolve().parents[2]

    # Server and HTTP policy
    HOST: str = "127.0.0.1"
    PORT: int = Field(default=8000, ge=1, le=65_535)
    DOCS_ENABLED: bool = True
    HOST_VALIDATION_ENABLED: bool = True
    ALLOWED_HOSTS: list[str] = Field(
        default_factory=lambda: ["localhost", "127.0.0.1", "testserver"]
    )
    CORS_ALLOWED_ORIGINS: list[str] = Field(default_factory=list)
    CORS_ALLOW_CREDENTIALS: bool = False
    MAX_REQUEST_BODY_BYTES: int = Field(default=2_097_152, ge=1)
    SLOW_REQUEST_THRESHOLD_MS: int = Field(default=1_000, ge=1)
    SECURE_HEADERS_ENABLED: bool = True
    HSTS_ENABLED: bool = False
    TRUSTED_PROXY_ENABLED: bool = False
    TRUSTED_PROXY_CIDRS: list[str] = Field(default_factory=list)

    # Logging
    LOG_LEVEL: str = "INFO"
    LOG_JSON: bool = False
    LOG_TO_FILE: bool = False
    LOG_DIR: Path = Path("logs")
    LOG_FILE: str = "app.log"
    LOG_MAX_BYTES: int = Field(default=10_000_000, ge=1)
    LOG_BACKUP_COUNT: int = Field(default=5, ge=0)
    LOG_QUEUE_SIZE: int = Field(default=10_000, ge=100)

    # PostgreSQL, the only persistence technology used by this service
    POSTGRES_URL: SecretStr | None = None
    POSTGRES_CONNECT_TIMEOUT_SECONDS: int = Field(default=5, ge=1, le=60)
    POSTGRES_COMMAND_TIMEOUT_SECONDS: int = Field(default=15, ge=1, le=300)
    SQL_POOL_SIZE: int = Field(default=10, ge=1)
    SQL_MAX_OVERFLOW: int = Field(default=10, ge=0)
    SQL_POOL_TIMEOUT_SECONDS: int = Field(default=10, ge=1)
    SQL_POOL_RECYCLE_SECONDS: int = Field(default=1_800, ge=0)
    SQL_POOL_PRE_PING: bool = True
    SQL_ECHO: bool = False
    DATABASE_STARTUP_CHECK: bool = True
    DATABASE_SCHEMA_CHECK: bool = True

    # When false, the service starts in degraded mode if PostgreSQL is unavailable.
    # Enable only when deployment policy explicitly requires fail-fast behavior.
    DATABASE_FAIL_FAST: bool = False

    HEALTHCHECK_TIMEOUT_SECONDS: float = Field(default=3.0, gt=0)
    DEEP_HEALTH_ENABLED: bool = True

    # Shared secret hashing and password policy
    AUTH_PEPPER: SecretStr | None = None
    PASSWORD_MIN_LENGTH: int = Field(default=12, ge=10, le=128)
    PASSWORD_HISTORY_COUNT: int = Field(default=5, ge=0, le=24)
    LOGIN_MAX_FAILED_ATTEMPTS: int = Field(default=5, ge=2, le=20)
    LOGIN_LOCKOUT_MINUTES: int = Field(default=15, ge=1, le=1_440)

    # JWT access, refresh, and password-reset tokens
    JWT_ALGORITHM: JWTAlgorithm = JWTAlgorithm.HS256
    JWT_SECRET: SecretStr | None = None
    JWT_PRIVATE_KEY_B64: SecretStr | None = None
    JWT_PUBLIC_KEY_B64: SecretStr | None = None
    JWT_KEY_ID: str = "primary"
    JWT_PREVIOUS_PUBLIC_KEYS_B64: dict[str, str] = Field(default_factory=dict)
    JWT_ISSUER: str = "pharmacy-platform-identity"
    JWT_AUDIENCE: str = "pharmacy-platform"
    ACCESS_TOKEN_TTL_MINUTES: int = Field(default=15, ge=1, le=60)
    REFRESH_TOKEN_TTL_DAYS: int = Field(default=30, ge=1, le=365)
    PASSWORD_RESET_TOKEN_TTL_MINUTES: int = Field(default=10, ge=2, le=30)

    # OTP
    OTP_TTL_SECONDS: int = Field(default=300, ge=60, le=900)
    OTP_MAX_ATTEMPTS: int = Field(default=5, ge=2, le=10)
    OTP_RESEND_COOLDOWN_SECONDS: int = Field(default=60, ge=1, le=600)
    OTP_MAX_RESENDS: int = Field(default=5, ge=1, le=20)
    OTP_RESEND_WINDOW_SECONDS: int = Field(default=3_600, ge=300, le=86_400)
    OTP_DEV_EXPOSE_CODE: bool = False

    # User registration and authorization
    EMAIL_VERIFICATION_REQUIRED: bool = True
    PHONE_VERIFICATION_REQUIRED: bool = True
    DEFAULT_ROLE_CODE: str = "customer"
    DEFAULT_ROLE_REQUIRED: bool = True
    AUTH_CHECK_SESSION_ON_EACH_REQUEST: bool = True
    AUTH_REFRESH_AUTHZ_ON_EACH_REQUEST: bool = True

    # Replaceable authentication rate limiting. Memory is suitable only for
    # local development and deterministic tests; production requires Redis.
    RATE_LIMIT_BACKEND: RateLimitBackend = RateLimitBackend.MEMORY
    REDIS_URL: SecretStr | None = None
    RATE_LIMIT_KEY_PREFIX: str = "identity:rate-limit"
    REGISTRATION_RATE_LIMIT: int = Field(default=5, ge=1, le=1_000)
    REGISTRATION_RATE_WINDOW_SECONDS: int = Field(default=600, ge=1, le=86_400)
    LOGIN_RATE_LIMIT: int = Field(default=10, ge=1, le=1_000)
    LOGIN_RATE_WINDOW_SECONDS: int = Field(default=300, ge=1, le=86_400)
    OTP_REQUEST_RATE_LIMIT: int = Field(default=5, ge=1, le=1_000)
    OTP_REQUEST_RATE_WINDOW_SECONDS: int = Field(default=600, ge=1, le=86_400)
    OTP_VERIFY_RATE_LIMIT: int = Field(default=10, ge=1, le=1_000)
    OTP_VERIFY_RATE_WINDOW_SECONDS: int = Field(default=300, ge=1, le=86_400)
    PASSWORD_RESET_RATE_LIMIT: int = Field(default=5, ge=1, le=1_000)
    PASSWORD_RESET_RATE_WINDOW_SECONDS: int = Field(default=900, ge=1, le=86_400)
    TOKEN_REFRESH_RATE_LIMIT: int = Field(default=30, ge=1, le=5_000)
    TOKEN_REFRESH_RATE_WINDOW_SECONDS: int = Field(default=60, ge=1, le=86_400)

    # Notification integration. The HTTP call remains intentionally commented
    # inside AuthNotificationGateway until the notification service is ready.
    NOTIFICATION_API_URL: str = ""
    NOTIFICATION_API_KEY: SecretStr | None = None
    NOTIFICATION_TIMEOUT_SECONDS: float = Field(default=5.0, gt=0, le=60)

    @field_validator("API_V1_STR")
    @classmethod
    def validate_api_prefix(cls, value: str) -> str:
        normalized = value.strip()
        if not normalized.startswith("/") or normalized == "/":
            raise ValueError("API_V1_STR must be a non-root path beginning with '/'")
        if "?" in normalized or "#" in normalized:
            raise ValueError("API_V1_STR must not contain a query or fragment")
        return normalized.rstrip("/")

    @field_validator(
        "PROJECT_NAME",
        "APP_VERSION",
        "JWT_KEY_ID",
        "JWT_ISSUER",
        "JWT_AUDIENCE",
        "DEFAULT_ROLE_CODE",
        "LOG_FILE",
    )
    @classmethod
    def normalize_non_blank(cls, value: str) -> str:
        normalized = value.strip()
        if not normalized:
            raise ValueError("value must not be blank")
        return normalized

    @field_validator("LOG_LEVEL")
    @classmethod
    def validate_log_level(cls, value: str) -> str:
        normalized = value.strip().upper()
        if normalized not in logging.getLevelNamesMapping():
            raise ValueError(f"Invalid LOG_LEVEL: {value}")
        return normalized

    @field_validator("TIMEZONE")
    @classmethod
    def validate_timezone(cls, value: str) -> str:
        normalized = value.strip()
        try:
            ZoneInfo(normalized)
        except ZoneInfoNotFoundError as exc:
            raise ValueError(f"Invalid TIMEZONE: {normalized}") from exc
        return normalized

    @field_validator("ALLOWED_HOSTS", "CORS_ALLOWED_ORIGINS", "TRUSTED_PROXY_CIDRS")
    @classmethod
    def normalize_string_lists(cls, values: list[str]) -> list[str]:
        normalized = [item.strip() for item in values if item and item.strip()]
        return list(dict.fromkeys(normalized))

    @field_validator("TRUSTED_PROXY_CIDRS")
    @classmethod
    def validate_proxy_cidrs(cls, values: list[str]) -> list[str]:
        import ipaddress

        for value in values:
            try:
                ipaddress.ip_network(value, strict=False)
            except ValueError as exc:
                raise ValueError(f"Invalid trusted proxy CIDR: {value}") from exc
        return values

    @field_validator("RATE_LIMIT_KEY_PREFIX")
    @classmethod
    def normalize_rate_limit_prefix(cls, value: str) -> str:
        normalized = value.strip().strip(":")
        if not normalized or len(normalized) > 128:
            raise ValueError("RATE_LIMIT_KEY_PREFIX must contain 1 to 128 characters")
        return normalized

    @field_validator("NOTIFICATION_API_URL")
    @classmethod
    def normalize_notification_url(cls, value: str) -> str:
        return value.strip()

    @model_validator(mode="after")
    def validate_cross_field_rules(self) -> "AppSettings":
        if self.SQL_POOL_SIZE + self.SQL_MAX_OVERFLOW > 200:
            raise ValueError(
                "SQL_POOL_SIZE plus SQL_MAX_OVERFLOW must not exceed 200 per process"
            )

        postgres_url = self._required_secret(self.POSTGRES_URL, "POSTGRES_URL")
        if not postgres_url.startswith("postgresql+asyncpg://"):
            raise ValueError("POSTGRES_URL must use postgresql+asyncpg")

        pepper = self._required_secret(self.AUTH_PEPPER, "AUTH_PEPPER")
        if len(pepper) < 32:
            raise ValueError("AUTH_PEPPER must contain at least 32 characters")

        if self.JWT_ALGORITHM is JWTAlgorithm.HS256:
            secret = self._required_secret(self.JWT_SECRET, "JWT_SECRET")
            if len(secret) < 64:
                raise ValueError("JWT_SECRET must contain at least 64 characters")
            if self.ENVIRONMENT == Environment.PRODUCTION:
                raise ValueError("Production must use JWT_ALGORITHM=RS256")
        else:
            self._validate_rsa_keys()

        if self.AUTH_REFRESH_AUTHZ_ON_EACH_REQUEST and not self.AUTH_CHECK_SESSION_ON_EACH_REQUEST:
            raise ValueError(
                "AUTH_REFRESH_AUTHZ_ON_EACH_REQUEST requires "
                "AUTH_CHECK_SESSION_ON_EACH_REQUEST=true"
            )

        if self.CORS_ALLOW_CREDENTIALS and "*" in self.CORS_ALLOWED_ORIGINS:
            raise ValueError("Wildcard CORS origins cannot be used with credentials")

        if self.TRUSTED_PROXY_ENABLED and not self.TRUSTED_PROXY_CIDRS:
            raise ValueError(
                "TRUSTED_PROXY_CIDRS is required when TRUSTED_PROXY_ENABLED=true"
            )

        if self.RATE_LIMIT_BACKEND is RateLimitBackend.REDIS:
            redis_url = self._required_secret(self.REDIS_URL, "REDIS_URL")
            parsed_redis = urlparse(redis_url)
            if parsed_redis.scheme not in {"redis", "rediss"} or not parsed_redis.netloc:
                raise ValueError("REDIS_URL must be a redis:// or rediss:// URL")

        if self.NOTIFICATION_API_URL:
            parsed = urlparse(self.NOTIFICATION_API_URL)
            if parsed.scheme not in {"http", "https"} or not parsed.netloc:
                raise ValueError("NOTIFICATION_API_URL must be an HTTP or HTTPS URL")

        if self.ENVIRONMENT == Environment.PRODUCTION:
            self._validate_production_rules()

        return self

    def _validate_rsa_keys(self) -> None:
        private_key = self.jwt_private_key
        public_key = self.jwt_public_key
        if not private_key or not public_key:
            raise ValueError(
                "RS256 requires JWT_PRIVATE_KEY_B64 and JWT_PUBLIC_KEY_B64"
            )
        try:
            private_object = load_pem_private_key(
                private_key.encode("utf-8"),
                password=None,
            )
            public_object = load_pem_public_key(public_key.encode("utf-8"))
            if private_object.public_key().public_numbers() != public_object.public_numbers():
                raise ValueError("JWT private and public keys do not form a pair")
        except ValueError:
            raise
        except Exception as exc:
            raise ValueError("RS256 JWT keys are not valid PEM keys") from exc

        for key_id, encoded_key in self.JWT_PREVIOUS_PUBLIC_KEYS_B64.items():
            if not key_id.strip() or not encoded_key.strip():
                raise ValueError(
                    "Previous JWT key identifiers and values must not be blank"
                )
            try:
                load_pem_public_key(
                    self._decode_pem(
                        encoded_key,
                        f"previous JWT key {key_id}",
                    ).encode("utf-8")
                )
            except Exception as exc:
                raise ValueError(
                    f"JWT_PREVIOUS_PUBLIC_KEYS_B64 contains invalid key: {key_id}"
                ) from exc

    def _validate_production_rules(self) -> None:
        if self.DEBUG:
            raise ValueError("DEBUG must be false in production")
        if self.SQL_ECHO:
            raise ValueError("SQL_ECHO must be false in production")
        if not self.LOG_JSON:
            raise ValueError("LOG_JSON must be true in production")
        if self.LOG_TO_FILE:
            raise ValueError("LOG_TO_FILE must be false in production containers")
        if not self.SECURE_HEADERS_ENABLED:
            raise ValueError("SECURE_HEADERS_ENABLED must be true in production")
        if not self.HSTS_ENABLED:
            raise ValueError("HSTS_ENABLED must be true in production")
        if not self.HOST_VALIDATION_ENABLED:
            raise ValueError("HOST_VALIDATION_ENABLED must be true in production")
        if not self.ALLOWED_HOSTS or "*" in self.ALLOWED_HOSTS:
            raise ValueError("Production ALLOWED_HOSTS must contain explicit hosts")
        if "*" in self.CORS_ALLOWED_ORIGINS:
            raise ValueError("Production CORS origins must not contain a wildcard")
        if self.OTP_DEV_EXPOSE_CODE:
            raise ValueError("OTP_DEV_EXPOSE_CODE must be false in production")
        if self.DOCS_ENABLED:
            raise ValueError("DOCS_ENABLED must be false in production")
        if self.RATE_LIMIT_BACKEND is not RateLimitBackend.REDIS:
            raise ValueError("Production requires RATE_LIMIT_BACKEND=redis")

    @staticmethod
    def _required_secret(value: SecretStr | None, name: str) -> str:
        if value is None:
            raise ValueError(f"{name} is required")
        normalized = value.get_secret_value().strip()
        if not normalized:
            raise ValueError(f"{name} is required")
        return normalized

    @staticmethod
    def _optional_secret(value: SecretStr | None) -> str | None:
        if value is None:
            return None
        normalized = value.get_secret_value().strip()
        return normalized or None

    @property
    def postgres_url_value(self) -> str:
        return self._required_secret(self.POSTGRES_URL, "POSTGRES_URL")

    @property
    def auth_pepper_value(self) -> str:
        return self._required_secret(self.AUTH_PEPPER, "AUTH_PEPPER")

    @property
    def jwt_secret_value(self) -> str | None:
        return self._optional_secret(self.JWT_SECRET)

    @property
    def jwt_private_key(self) -> str | None:
        return self._decode_optional_pem(
            self.JWT_PRIVATE_KEY_B64,
            "JWT_PRIVATE_KEY_B64",
        )

    @property
    def jwt_public_key(self) -> str | None:
        return self._decode_optional_pem(
            self.JWT_PUBLIC_KEY_B64,
            "JWT_PUBLIC_KEY_B64",
        )

    @property
    def jwt_decoding_keys(self) -> dict[str, str]:
        if self.JWT_ALGORITHM is JWTAlgorithm.HS256:
            secret = self.jwt_secret_value
            return {self.JWT_KEY_ID: secret} if secret else {}

        keys: dict[str, str] = {}
        if self.jwt_public_key:
            keys[self.JWT_KEY_ID] = self.jwt_public_key
        for key_id, encoded_key in self.JWT_PREVIOUS_PUBLIC_KEYS_B64.items():
            keys[key_id] = self._decode_pem(
                encoded_key,
                f"previous JWT key {key_id}",
            )
        return keys

    @property
    def notification_api_key_value(self) -> str | None:
        return self._optional_secret(self.NOTIFICATION_API_KEY)

    @property
    def redis_url_value(self) -> str:
        return self._required_secret(self.REDIS_URL, "REDIS_URL")

    @property
    def log_directory(self) -> Path:
        if self.LOG_DIR.is_absolute():
            return self.LOG_DIR
        return self.BASE_DIR / self.LOG_DIR

    @classmethod
    def _decode_optional_pem(
        cls,
        value: SecretStr | None,
        name: str,
    ) -> str | None:
        encoded = cls._optional_secret(value)
        return None if encoded is None else cls._decode_pem(encoded, name)

    @staticmethod
    def _decode_pem(value: str, name: str) -> str:
        try:
            return base64.b64decode(value, validate=True).decode("utf-8")
        except Exception as exc:
            raise ValueError(
                f"{name} must be valid base64-encoded UTF-8 PEM"
            ) from exc


@lru_cache(maxsize=1)
def get_settings() -> AppSettings:
    """Return the single cached settings instance."""

    return AppSettings()


def clear_settings_cache() -> None:
    """Clear cached settings for isolated tests."""

    get_settings.cache_clear()


__all__ = [
    "AppSettings",
    "Environment",
    "JWTAlgorithm",
    "RateLimitBackend",
    "clear_settings_cache",
    "get_settings",
]

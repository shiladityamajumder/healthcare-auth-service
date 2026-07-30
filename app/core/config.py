"""File: app/core/config.py
Central, immutable configuration for the authentication service.

The service reads configuration from environment variables and one optional
``.env`` file. Pydantic validates individual values and cross-field security
rules before FastAPI starts accepting requests.

PostgreSQL remains the authoritative persistence store for identity data.
Redis and MongoDB are optional infrastructure integrations. Database schema
creation and migrations remain the responsibility of external migration
processes.
"""

from __future__ import annotations

import base64
import binascii
import ipaddress
import logging
from enum import StrEnum
from functools import lru_cache
from pathlib import Path
from typing import Self
from urllib.parse import urlparse
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import (
    load_pem_private_key,
    load_pem_public_key,
)
from pydantic import Field, SecretStr, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Environment(StrEnum):
    """Supported application runtime environments."""

    DEVELOPMENT = "development"
    TESTING = "testing"
    STAGING = "staging"
    PRODUCTION = "production"


class RateLimitBackend(StrEnum):
    """Supported rate-limit persistence backends."""

    DISABLED = "disabled"
    MEMORY = "memory"
    REDIS = "redis"


class JWTAlgorithm(StrEnum):
    """JWT signing algorithms supported by the service."""

    HS256 = "HS256"
    RS256 = "RS256"


class AppSettings(BaseSettings):
    """Validated process-level application configuration.

    This is the only settings model used by the service. One immutable settings
    instance should be created during startup and attached to
    ``app.state.settings``.

    Request handlers and application services should receive this instance
    through dependency injection rather than reading environment variables
    directly.
    """

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
        frozen=True,
    )

    # -------------------------------------------------------------------------
    # Application
    # -------------------------------------------------------------------------

    ENVIRONMENT: Environment = Environment.DEVELOPMENT
    PROJECT_NAME: str = "pharmacy_identity_service"
    API_V1_STR: str = "/api/v1"
    APP_VERSION: str = "1.0.0"
    DEBUG: bool = False
    TIMEZONE: str = "Asia/Kolkata"
    BASE_DIR: Path = Path(__file__).resolve().parents[2]

    # -------------------------------------------------------------------------
    # Server and HTTP policy
    # -------------------------------------------------------------------------

    HOST: str = "127.0.0.1"
    PORT: int = Field(
        default=8000,
        ge=1,
        le=65_535,
    )

    DOCS_ENABLED: bool = True

    HOST_VALIDATION_ENABLED: bool = True
    ALLOWED_HOSTS: list[str] = Field(
        default_factory=lambda: [
            "localhost",
            "127.0.0.1",
            "testserver",
        ]
    )

    CORS_ALLOWED_ORIGINS: list[str] = Field(default_factory=list)
    CORS_ALLOW_CREDENTIALS: bool = False

    MAX_REQUEST_BODY_BYTES: int = Field(
        default=2_097_152,
        ge=1,
    )
    SLOW_REQUEST_THRESHOLD_MS: int = Field(
        default=1_000,
        ge=1,
    )

    SECURE_HEADERS_ENABLED: bool = True
    HSTS_ENABLED: bool = False

    TRUSTED_PROXY_ENABLED: bool = False
    TRUSTED_PROXY_CIDRS: list[str] = Field(default_factory=list)

    # -------------------------------------------------------------------------
    # Logging
    # -------------------------------------------------------------------------

    LOG_LEVEL: str = "INFO"
    LOG_JSON: bool = False
    LOG_TO_FILE: bool = False

    LOG_DIR: Path = Path("logs")
    LOG_FILE: str = "app.log"

    LOG_MAX_BYTES: int = Field(
        default=10_000_000,
        ge=1,
    )
    LOG_BACKUP_COUNT: int = Field(
        default=5,
        ge=0,
    )
    LOG_QUEUE_SIZE: int = Field(
        default=10_000,
        ge=100,
    )

    # -------------------------------------------------------------------------
    # PostgreSQL
    # -------------------------------------------------------------------------

    # PostgreSQL remains the authoritative persistence store for users,
    # credentials, sessions, roles, permissions, and authentication state.
    POSTGRES_URL: SecretStr | None = None

    POSTGRES_CONNECT_TIMEOUT_SECONDS: int = Field(
        default=5,
        ge=1,
        le=60,
    )
    POSTGRES_COMMAND_TIMEOUT_SECONDS: int = Field(
        default=15,
        ge=1,
        le=300,
    )

    SQL_POOL_SIZE: int = Field(
        default=10,
        ge=1,
        le=200,
    )
    SQL_MAX_OVERFLOW: int = Field(
        default=10,
        ge=0,
        le=200,
    )
    SQL_POOL_TIMEOUT_SECONDS: int = Field(
        default=10,
        ge=1,
        le=300,
    )
    SQL_POOL_RECYCLE_SECONDS: int = Field(
        default=1_800,
        ge=0,
        le=86_400,
    )
    SQL_POOL_PRE_PING: bool = True
    SQL_ECHO: bool = False

    DATABASE_STARTUP_CHECK: bool = True
    DATABASE_SCHEMA_CHECK: bool = True

    # When false, the service may start in degraded mode when PostgreSQL is
    # unavailable. Enable fail-fast only when deployment policy requires it.
    DATABASE_FAIL_FAST: bool = False

    # -------------------------------------------------------------------------
    # Redis
    # -------------------------------------------------------------------------

    # Redis may be enabled explicitly for caching or idempotency. It is also
    # considered enabled automatically when Redis is selected as the
    # rate-limiting backend.
    ENABLE_REDIS: bool = False
    REDIS_URL: SecretStr | None = None

    REDIS_MAX_CONNECTIONS: int = Field(
        default=50,
        ge=1,
        le=1_000,
    )
    REDIS_POOL_TIMEOUT_SECONDS: float = Field(
        default=3.0,
        gt=0,
        le=60,
    )
    REDIS_SOCKET_TIMEOUT_SECONDS: float = Field(
        default=3.0,
        gt=0,
        le=60,
    )
    REDIS_CONNECT_TIMEOUT_SECONDS: float = Field(
        default=3.0,
        gt=0,
        le=60,
    )
    REDIS_HEALTH_CHECK_INTERVAL_SECONDS: int = Field(
        default=30,
        ge=0,
        le=3_600,
    )

    # -------------------------------------------------------------------------
    # MongoDB
    # -------------------------------------------------------------------------

    # MongoDB is optional and must not become a second source of truth for
    # users, sessions, credentials, roles, or permissions.
    ENABLE_MONGO: bool = False
    MONGO_URI: SecretStr | None = None
    MONGO_DB_NAME: str = ""

    MONGO_MIN_POOL_SIZE: int = Field(
        default=0,
        ge=0,
        le=500,
    )
    MONGO_MAX_POOL_SIZE: int = Field(
        default=20,
        ge=1,
        le=500,
    )
    MONGO_WAIT_QUEUE_TIMEOUT_MS: int = Field(
        default=5_000,
        ge=100,
        le=300_000,
    )
    MONGO_SERVER_SELECTION_TIMEOUT_MS: int = Field(
        default=5_000,
        ge=100,
        le=300_000,
    )
    MONGO_CONNECT_TIMEOUT_MS: int = Field(
        default=5_000,
        ge=100,
        le=300_000,
    )
    MONGO_SOCKET_TIMEOUT_MS: int = Field(
        default=15_000,
        ge=100,
        le=600_000,
    )
    MONGO_RETRY_READS: bool = True
    MONGO_RETRY_WRITES: bool = True

    # -------------------------------------------------------------------------
    # Health checks
    # -------------------------------------------------------------------------

    HEALTHCHECK_TIMEOUT_SECONDS: float = Field(
        default=3.0,
        gt=0,
        le=60,
    )
    DEEP_HEALTH_ENABLED: bool = True

    # -------------------------------------------------------------------------
    # Password hashing and account lockout
    # -------------------------------------------------------------------------

    AUTH_PEPPER: SecretStr | None = None

    PASSWORD_MIN_LENGTH: int = Field(
        default=12,
        ge=10,
        le=128,
    )
    PASSWORD_HISTORY_COUNT: int = Field(
        default=5,
        ge=0,
        le=24,
    )

    LOGIN_MAX_FAILED_ATTEMPTS: int = Field(
        default=5,
        ge=2,
        le=20,
    )
    LOGIN_LOCKOUT_MINUTES: int = Field(
        default=15,
        ge=1,
        le=1_440,
    )

    # -------------------------------------------------------------------------
    # JWT access, refresh, and password-reset tokens
    # -------------------------------------------------------------------------

    JWT_ALGORITHM: JWTAlgorithm = JWTAlgorithm.HS256

    # Used only when JWT_ALGORITHM is HS256.
    JWT_SECRET: SecretStr | None = None

    # Base64-encoded PEM keys used only when JWT_ALGORITHM is RS256.
    JWT_PRIVATE_KEY_B64: SecretStr | None = None
    JWT_PUBLIC_KEY_B64: SecretStr | None = None

    # Current signing-key identifier written to the JWT ``kid`` header.
    JWT_KEY_ID: str = "primary"

    # Previous public keys retained temporarily for safe signing-key rotation.
    JWT_PREVIOUS_PUBLIC_KEYS_B64: dict[str, str] = Field(
        default_factory=dict
    )

    JWT_ISSUER: str = "pharmacy-platform-identity"
    JWT_AUDIENCE: str = "pharmacy-platform"

    ACCESS_TOKEN_TTL_MINUTES: int = Field(
        default=15,
        ge=1,
        le=60,
    )
    REFRESH_TOKEN_TTL_DAYS: int = Field(
        default=30,
        ge=1,
        le=365,
    )
    PASSWORD_RESET_TOKEN_TTL_MINUTES: int = Field(
        default=10,
        ge=2,
        le=30,
    )

    # -------------------------------------------------------------------------
    # One-time password policy
    # -------------------------------------------------------------------------

    OTP_TTL_SECONDS: int = Field(
        default=300,
        ge=60,
        le=900,
    )
    OTP_MAX_ATTEMPTS: int = Field(
        default=5,
        ge=2,
        le=10,
    )
    OTP_RESEND_COOLDOWN_SECONDS: int = Field(
        default=60,
        ge=1,
        le=600,
    )
    OTP_MAX_RESENDS: int = Field(
        default=5,
        ge=1,
        le=20,
    )
    OTP_RESEND_WINDOW_SECONDS: int = Field(
        default=3_600,
        ge=300,
        le=86_400,
    )

    # This setting must never be enabled in production.
    OTP_DEV_EXPOSE_CODE: bool = False

    # -------------------------------------------------------------------------
    # Registration and authorization behavior
    # -------------------------------------------------------------------------

    EMAIL_VERIFICATION_REQUIRED: bool = True
    PHONE_VERIFICATION_REQUIRED: bool = True

    DEFAULT_ROLE_CODE: str = "customer"
    DEFAULT_ROLE_REQUIRED: bool = True

    # Validate the persisted session before authorizing protected requests.
    AUTH_CHECK_SESSION_ON_EACH_REQUEST: bool = True

    # Refresh role and permission information for protected requests.
    AUTH_REFRESH_AUTHZ_ON_EACH_REQUEST: bool = True

    # -------------------------------------------------------------------------
    # Authentication rate limiting
    # -------------------------------------------------------------------------

    # Memory storage is only suitable for local development and deterministic
    # tests. Distributed production deployments require Redis.
    RATE_LIMIT_BACKEND: RateLimitBackend = RateLimitBackend.MEMORY
    RATE_LIMIT_KEY_PREFIX: str = "identity:rate-limit"

    REGISTRATION_RATE_LIMIT: int = Field(
        default=5,
        ge=1,
        le=1_000,
    )
    REGISTRATION_RATE_WINDOW_SECONDS: int = Field(
        default=600,
        ge=1,
        le=86_400,
    )

    LOGIN_RATE_LIMIT: int = Field(
        default=10,
        ge=1,
        le=1_000,
    )
    LOGIN_RATE_WINDOW_SECONDS: int = Field(
        default=300,
        ge=1,
        le=86_400,
    )

    OTP_REQUEST_RATE_LIMIT: int = Field(
        default=5,
        ge=1,
        le=1_000,
    )
    OTP_REQUEST_RATE_WINDOW_SECONDS: int = Field(
        default=600,
        ge=1,
        le=86_400,
    )

    OTP_VERIFY_RATE_LIMIT: int = Field(
        default=10,
        ge=1,
        le=1_000,
    )
    OTP_VERIFY_RATE_WINDOW_SECONDS: int = Field(
        default=300,
        ge=1,
        le=86_400,
    )

    PASSWORD_RESET_RATE_LIMIT: int = Field(
        default=5,
        ge=1,
        le=1_000,
    )
    PASSWORD_RESET_RATE_WINDOW_SECONDS: int = Field(
        default=900,
        ge=1,
        le=86_400,
    )

    TOKEN_REFRESH_RATE_LIMIT: int = Field(
        default=30,
        ge=1,
        le=5_000,
    )
    TOKEN_REFRESH_RATE_WINDOW_SECONDS: int = Field(
        default=60,
        ge=1,
        le=86_400,
    )

    # -------------------------------------------------------------------------
    # Notification service integration
    # -------------------------------------------------------------------------

    # The outbound HTTP call remains intentionally disabled inside the
    # notification gateway until the notification service is available.
    NOTIFICATION_API_URL: str = ""
    NOTIFICATION_API_KEY: SecretStr | None = None
    NOTIFICATION_TIMEOUT_SECONDS: float = Field(
        default=5.0,
        gt=0,
        le=60,
    )

    # -------------------------------------------------------------------------
    # Field validation
    # -------------------------------------------------------------------------

    @field_validator("API_V1_STR")
    @classmethod
    def validate_api_prefix(cls, value: str) -> str:
        """Validate and normalize the public API route prefix."""
        normalized = value.strip()

        if not normalized.startswith("/") or normalized == "/":
            raise ValueError(
                "API_V1_STR must be a non-root path beginning with '/'"
            )

        if "?" in normalized or "#" in normalized:
            raise ValueError(
                "API_V1_STR must not contain a query or fragment"
            )

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
    def normalize_required_string(cls, value: str) -> str:
        """Strip whitespace and reject blank required strings."""
        normalized = value.strip()

        if not normalized:
            raise ValueError("value must not be blank")

        return normalized

    @field_validator("MONGO_DB_NAME")
    @classmethod
    def normalize_mongo_database_name(cls, value: str) -> str:
        """Normalize the optional MongoDB database name."""
        return value.strip()

    @field_validator("LOG_LEVEL")
    @classmethod
    def validate_log_level(cls, value: str) -> str:
        """Normalize and validate the Python logging level."""
        normalized = value.strip().upper()

        if normalized not in logging.getLevelNamesMapping():
            raise ValueError(f"Invalid LOG_LEVEL: {value}")

        return normalized

    @field_validator("TIMEZONE")
    @classmethod
    def validate_timezone(cls, value: str) -> str:
        """Validate that the configured timezone is available."""
        normalized = value.strip()

        try:
            ZoneInfo(normalized)
        except ZoneInfoNotFoundError as exc:
            raise ValueError(
                f"Invalid TIMEZONE: {normalized}"
            ) from exc

        return normalized

    @field_validator(
        "ALLOWED_HOSTS",
        "CORS_ALLOWED_ORIGINS",
        "TRUSTED_PROXY_CIDRS",
    )
    @classmethod
    def normalize_string_lists(cls, values: list[str]) -> list[str]:
        """Strip blank items and remove duplicate values."""
        normalized = [
            item.strip()
            for item in values
            if item and item.strip()
        ]

        return list(dict.fromkeys(normalized))

    @field_validator("TRUSTED_PROXY_CIDRS")
    @classmethod
    def validate_proxy_cidrs(cls, values: list[str]) -> list[str]:
        """Validate trusted proxy IPv4 and IPv6 network ranges."""
        for value in values:
            try:
                ipaddress.ip_network(
                    value,
                    strict=False,
                )
            except ValueError as exc:
                raise ValueError(
                    f"Invalid trusted proxy CIDR: {value}"
                ) from exc

        return values

    @field_validator("RATE_LIMIT_KEY_PREFIX")
    @classmethod
    def normalize_rate_limit_prefix(cls, value: str) -> str:
        """Normalize and validate the Redis rate-limit key prefix."""
        normalized = value.strip().strip(":")

        if not normalized or len(normalized) > 128:
            raise ValueError(
                "RATE_LIMIT_KEY_PREFIX must contain 1 to 128 characters"
            )

        return normalized

    @field_validator("NOTIFICATION_API_URL")
    @classmethod
    def normalize_notification_url(cls, value: str) -> str:
        """Remove surrounding whitespace from the notification URL."""
        return value.strip()

    # -------------------------------------------------------------------------
    # Cross-field validation
    # -------------------------------------------------------------------------

    @model_validator(mode="after")
    def validate_cross_field_rules(self) -> Self:
        """Validate security and infrastructure configuration dependencies."""
        self._validate_postgres_settings()
        self._validate_redis_settings()
        self._validate_mongo_settings()
        self._validate_password_security()
        self._validate_jwt_settings()
        self._validate_authorization_settings()
        self._validate_http_settings()
        self._validate_proxy_settings()
        self._validate_notification_settings()

        if self.ENVIRONMENT is Environment.PRODUCTION:
            self._validate_production_rules()

        return self

    def _validate_postgres_settings(self) -> None:
        """Validate PostgreSQL configuration and pool sizing."""
        total_connections = self.SQL_POOL_SIZE + self.SQL_MAX_OVERFLOW

        if total_connections > 200:
            raise ValueError(
                "SQL_POOL_SIZE plus SQL_MAX_OVERFLOW must not exceed "
                "200 per process"
            )

        postgres_url = self._required_secret(
            self.POSTGRES_URL,
            "POSTGRES_URL",
        )

        parsed_url = urlparse(postgres_url)

        if (
            parsed_url.scheme != "postgresql+asyncpg"
            or not parsed_url.netloc
        ):
            raise ValueError(
                "POSTGRES_URL must be a valid postgresql+asyncpg URL"
            )

    def _validate_redis_settings(self) -> None:
        """Validate Redis settings when Redis is required."""
        if not self.redis_enabled:
            return

        redis_url = self._required_secret(
            self.REDIS_URL,
            "REDIS_URL",
        )
        parsed_url = urlparse(redis_url)

        if (
            parsed_url.scheme not in {"redis", "rediss"}
            or not parsed_url.netloc
        ):
            raise ValueError(
                "REDIS_URL must be a valid redis:// or rediss:// URL"
            )

    def _validate_mongo_settings(self) -> None:
        """Validate optional MongoDB settings and pool sizing."""
        if self.MONGO_MIN_POOL_SIZE > self.MONGO_MAX_POOL_SIZE:
            raise ValueError(
                "MONGO_MIN_POOL_SIZE must not exceed MONGO_MAX_POOL_SIZE"
            )

        if not self.ENABLE_MONGO:
            return

        mongo_uri = self._required_secret(
            self.MONGO_URI,
            "MONGO_URI",
        )
        parsed_uri = urlparse(mongo_uri)

        if (
            parsed_uri.scheme not in {"mongodb", "mongodb+srv"}
            or not parsed_uri.netloc
        ):
            raise ValueError(
                "MONGO_URI must be a valid mongodb:// or mongodb+srv:// URI"
            )

        if not self.MONGO_DB_NAME:
            raise ValueError(
                "MONGO_DB_NAME is required when ENABLE_MONGO=true"
            )

        if len(self.MONGO_DB_NAME) > 64:
            raise ValueError(
                "MONGO_DB_NAME must not exceed 64 characters"
            )

        if "\x00" in self.MONGO_DB_NAME:
            raise ValueError(
                "MONGO_DB_NAME must not contain null characters"
            )

    def _validate_password_security(self) -> None:
        """Validate the application-wide password pepper."""
        pepper = self._required_secret(
            self.AUTH_PEPPER,
            "AUTH_PEPPER",
        )

        if len(pepper) < 32:
            raise ValueError(
                "AUTH_PEPPER must contain at least 32 characters"
            )

    def _validate_jwt_settings(self) -> None:
        """Validate settings for the selected JWT algorithm."""
        if self.JWT_ALGORITHM is JWTAlgorithm.HS256:
            secret = self._required_secret(
                self.JWT_SECRET,
                "JWT_SECRET",
            )

            if len(secret) < 64:
                raise ValueError(
                    "JWT_SECRET must contain at least 64 characters"
                )

            if self.ENVIRONMENT is Environment.PRODUCTION:
                raise ValueError(
                    "Production must use JWT_ALGORITHM=RS256"
                )

            return

        self._validate_rsa_keys()

    def _validate_authorization_settings(self) -> None:
        """Validate session and authorization dependencies."""
        if (
            self.AUTH_REFRESH_AUTHZ_ON_EACH_REQUEST
            and not self.AUTH_CHECK_SESSION_ON_EACH_REQUEST
        ):
            raise ValueError(
                "AUTH_REFRESH_AUTHZ_ON_EACH_REQUEST requires "
                "AUTH_CHECK_SESSION_ON_EACH_REQUEST=true"
            )

    def _validate_http_settings(self) -> None:
        """Validate CORS-related HTTP security rules."""
        if (
            self.CORS_ALLOW_CREDENTIALS
            and "*" in self.CORS_ALLOWED_ORIGINS
        ):
            raise ValueError(
                "Wildcard CORS origins cannot be used with credentials"
            )

    def _validate_proxy_settings(self) -> None:
        """Require trusted networks when proxy handling is enabled."""
        if (
            self.TRUSTED_PROXY_ENABLED
            and not self.TRUSTED_PROXY_CIDRS
        ):
            raise ValueError(
                "TRUSTED_PROXY_CIDRS is required when "
                "TRUSTED_PROXY_ENABLED=true"
            )

    def _validate_notification_settings(self) -> None:
        """Validate the optional notification-service URL."""
        if not self.NOTIFICATION_API_URL:
            return

        parsed_url = urlparse(self.NOTIFICATION_API_URL)

        if (
            parsed_url.scheme not in {"http", "https"}
            or not parsed_url.netloc
        ):
            raise ValueError(
                "NOTIFICATION_API_URL must be a valid HTTP or HTTPS URL"
            )

    # -------------------------------------------------------------------------
    # RSA key validation
    # -------------------------------------------------------------------------

    def _validate_rsa_keys(self) -> None:
        """Validate current and previous RS256 signing keys."""
        private_key_pem = self.jwt_private_key
        public_key_pem = self.jwt_public_key

        if not private_key_pem or not public_key_pem:
            raise ValueError(
                "RS256 requires JWT_PRIVATE_KEY_B64 and JWT_PUBLIC_KEY_B64"
            )

        private_object = self._load_rsa_private_key(private_key_pem)
        public_object = self._load_rsa_public_key(
            public_key_pem,
            setting_name="JWT_PUBLIC_KEY_B64",
        )

        derived_public_numbers = (
            private_object.public_key().public_numbers()
        )
        configured_public_numbers = public_object.public_numbers()

        if derived_public_numbers != configured_public_numbers:
            raise ValueError(
                "JWT private and public keys do not form a pair"
            )

        if self.JWT_KEY_ID in self.JWT_PREVIOUS_PUBLIC_KEYS_B64:
            raise ValueError(
                "JWT_KEY_ID must not also exist in "
                "JWT_PREVIOUS_PUBLIC_KEYS_B64"
            )

        self._validate_previous_rsa_public_keys()

    @staticmethod
    def _load_rsa_private_key(
        private_key_pem: str,
    ) -> rsa.RSAPrivateKey:
        """Load and validate an unencrypted RSA private key."""
        try:
            private_object = load_pem_private_key(
                private_key_pem.encode("utf-8"),
                password=None,
            )
        except (TypeError, ValueError) as exc:
            raise ValueError(
                "JWT_PRIVATE_KEY_B64 must contain a valid, unencrypted "
                "PEM private key"
            ) from exc

        if not isinstance(private_object, rsa.RSAPrivateKey):
            raise ValueError(
                "JWT_PRIVATE_KEY_B64 must contain an RSA private key "
                "when JWT_ALGORITHM=RS256"
            )

        return private_object

    @staticmethod
    def _load_rsa_public_key(
        public_key_pem: str,
        *,
        setting_name: str,
    ) -> rsa.RSAPublicKey:
        """Load and validate an RSA public key."""
        try:
            public_object = load_pem_public_key(
                public_key_pem.encode("utf-8")
            )
        except (TypeError, ValueError) as exc:
            raise ValueError(
                f"{setting_name} must contain a valid PEM public key"
            ) from exc

        if not isinstance(public_object, rsa.RSAPublicKey):
            raise ValueError(
                f"{setting_name} must contain an RSA public key "
                "when JWT_ALGORITHM=RS256"
            )

        return public_object

    def _validate_previous_rsa_public_keys(self) -> None:
        """Validate public keys retained for JWT key rotation."""
        for key_id, encoded_key in self.JWT_PREVIOUS_PUBLIC_KEYS_B64.items():
            normalized_key_id = key_id.strip()
            normalized_encoded_key = encoded_key.strip()

            if not normalized_key_id or not normalized_encoded_key:
                raise ValueError(
                    "Previous JWT key identifiers and values "
                    "must not be blank"
                )

            public_key_pem = self._decode_pem(
                normalized_encoded_key,
                f"previous JWT key {normalized_key_id}",
            )

            self._load_rsa_public_key(
                public_key_pem,
                setting_name=(
                    "JWT_PREVIOUS_PUBLIC_KEYS_B64"
                    f"[{normalized_key_id}]"
                ),
            )

    # -------------------------------------------------------------------------
    # Production policy
    # -------------------------------------------------------------------------

    def _validate_production_rules(self) -> None:
        """Enforce mandatory production security requirements."""
        if self.DEBUG:
            raise ValueError(
                "DEBUG must be false in production"
            )

        if self.SQL_ECHO:
            raise ValueError(
                "SQL_ECHO must be false in production"
            )

        if not self.LOG_JSON:
            raise ValueError(
                "LOG_JSON must be true in production"
            )

        if self.LOG_TO_FILE:
            raise ValueError(
                "LOG_TO_FILE must be false in production containers"
            )

        if not self.SECURE_HEADERS_ENABLED:
            raise ValueError(
                "SECURE_HEADERS_ENABLED must be true in production"
            )

        if not self.HSTS_ENABLED:
            raise ValueError(
                "HSTS_ENABLED must be true in production"
            )

        if not self.HOST_VALIDATION_ENABLED:
            raise ValueError(
                "HOST_VALIDATION_ENABLED must be true in production"
            )

        if not self.ALLOWED_HOSTS or "*" in self.ALLOWED_HOSTS:
            raise ValueError(
                "Production ALLOWED_HOSTS must contain explicit hosts"
            )

        if "*" in self.CORS_ALLOWED_ORIGINS:
            raise ValueError(
                "Production CORS origins must not contain a wildcard"
            )

        if self.OTP_DEV_EXPOSE_CODE:
            raise ValueError(
                "OTP_DEV_EXPOSE_CODE must be false in production"
            )

        if self.DOCS_ENABLED:
            raise ValueError(
                "DOCS_ENABLED must be false in production"
            )

        if self.RATE_LIMIT_BACKEND is not RateLimitBackend.REDIS:
            raise ValueError(
                "Production requires RATE_LIMIT_BACKEND=redis"
            )

    # -------------------------------------------------------------------------
    # Secret accessors
    # -------------------------------------------------------------------------

    @staticmethod
    def _required_secret(
        value: SecretStr | None,
        name: str,
    ) -> str:
        """Return a required, trimmed, nonblank secret."""
        if value is None:
            raise ValueError(f"{name} is required")

        normalized = value.get_secret_value().strip()

        if not normalized:
            raise ValueError(f"{name} is required")

        return normalized

    @staticmethod
    def _optional_secret(
        value: SecretStr | None,
    ) -> str | None:
        """Return a trimmed optional secret."""
        if value is None:
            return None

        normalized = value.get_secret_value().strip()

        return normalized or None

    @property
    def postgres_url_value(self) -> str:
        """Return the validated PostgreSQL connection URL."""
        return self._required_secret(
            self.POSTGRES_URL,
            "POSTGRES_URL",
        )

    @property
    def redis_enabled(self) -> bool:
        """Return whether the process requires a Redis client.

        Redis is required when explicitly enabled or when selected as the
        authentication rate-limit backend.
        """
        return (
            self.ENABLE_REDIS
            or self.RATE_LIMIT_BACKEND is RateLimitBackend.REDIS
        )

    @property
    def redis_url_value(self) -> str:
        """Return the validated Redis connection URL."""
        return self._required_secret(
            self.REDIS_URL,
            "REDIS_URL",
        )

    @property
    def mongo_uri_value(self) -> str:
        """Return the validated MongoDB connection URI."""
        return self._required_secret(
            self.MONGO_URI,
            "MONGO_URI",
        )

    @property
    def auth_pepper_value(self) -> str:
        """Return the validated authentication pepper."""
        return self._required_secret(
            self.AUTH_PEPPER,
            "AUTH_PEPPER",
        )

    @property
    def jwt_secret_value(self) -> str | None:
        """Return the optional HS256 signing secret."""
        return self._optional_secret(self.JWT_SECRET)

    @property
    def jwt_private_key(self) -> str | None:
        """Return the decoded RS256 private PEM key."""
        return self._decode_optional_pem(
            self.JWT_PRIVATE_KEY_B64,
            "JWT_PRIVATE_KEY_B64",
        )

    @property
    def jwt_public_key(self) -> str | None:
        """Return the decoded current RS256 public PEM key."""
        return self._decode_optional_pem(
            self.JWT_PUBLIC_KEY_B64,
            "JWT_PUBLIC_KEY_B64",
        )

    @property
    def jwt_decoding_keys(self) -> dict[str, str]:
        """Return JWT verification keys indexed by key identifier."""
        if self.JWT_ALGORITHM is JWTAlgorithm.HS256:
            secret = self.jwt_secret_value

            return {
                self.JWT_KEY_ID: secret
            } if secret else {}

        keys: dict[str, str] = {}

        current_public_key = self.jwt_public_key

        if current_public_key:
            keys[self.JWT_KEY_ID] = current_public_key

        for key_id, encoded_key in self.JWT_PREVIOUS_PUBLIC_KEYS_B64.items():
            normalized_key_id = key_id.strip()

            keys[normalized_key_id] = self._decode_pem(
                encoded_key.strip(),
                f"previous JWT key {normalized_key_id}",
            )

        return keys

    @property
    def notification_api_key_value(self) -> str | None:
        """Return the optional notification-service API key."""
        return self._optional_secret(self.NOTIFICATION_API_KEY)

    @property
    def log_directory(self) -> Path:
        """Return the resolved absolute logging directory."""
        if self.LOG_DIR.is_absolute():
            return self.LOG_DIR

        return self.BASE_DIR / self.LOG_DIR

    # -------------------------------------------------------------------------
    # PEM decoding
    # -------------------------------------------------------------------------

    @classmethod
    def _decode_optional_pem(
        cls,
        value: SecretStr | None,
        name: str,
    ) -> str | None:
        """Decode an optional base64-encoded PEM secret."""
        encoded_value = cls._optional_secret(value)

        if encoded_value is None:
            return None

        return cls._decode_pem(
            encoded_value,
            name,
        )

    @staticmethod
    def _decode_pem(
        value: str,
        name: str,
    ) -> str:
        """Decode a base64-encoded UTF-8 PEM value."""
        try:
            decoded_bytes = base64.b64decode(
                value,
                validate=True,
            )

            return decoded_bytes.decode("utf-8")
        except (
            binascii.Error,
            UnicodeDecodeError,
            ValueError,
        ) as exc:
            raise ValueError(
                f"{name} must be valid base64-encoded UTF-8 PEM"
            ) from exc


@lru_cache(maxsize=1)
def get_settings() -> AppSettings:
    """Return the process-wide cached settings instance."""
    return AppSettings()


def clear_settings_cache() -> None:
    """Clear the settings cache for isolated automated tests."""
    get_settings.cache_clear()


__all__ = [
    "AppSettings",
    "Environment",
    "JWTAlgorithm",
    "RateLimitBackend",
    "clear_settings_cache",
    "get_settings",
]
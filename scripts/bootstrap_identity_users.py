"""Create or synchronize initial privileged identity users from a JSON manifest.

Run after ``seed_identity_master_data.py`` has created the required roles::

    python -m scripts.bootstrap_identity_users --config bootstrap_users.json

The script is idempotent by normalized email. It creates missing users, profiles,
password history, and global role assignments. Existing accounts are not given a
new password unless ``--rotate-passwords`` is explicitly supplied.

Keep the JSON manifest outside source control because it contains plaintext
bootstrap passwords. Delete it after the initial bootstrap is complete.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.identity.normalization import normalize_email, normalize_phone
from app.auth.security.passwords import PasswordManager
from app.core.config import AppSettings
from app.db.postgres import PostgreSQLDatabase
from app.db.uow import SQLAlchemyUnitOfWork
from app.models.enums import UserStatus
from app.models.identity import (
    PasswordHistory,
    Roles,
    UserProfiles,
    UserRoles,
    Users,
)


@dataclass(frozen=True, slots=True)
class BootstrapUser:
    """Validated user definition loaded from the bootstrap manifest."""

    email: str
    phone_country_code: str
    phone_number: str
    password: str
    first_name: str
    last_name: str | None
    preferred_name: str | None
    preferred_locale: str
    timezone_name: str
    role_codes: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class BootstrapSummary:
    """Change counts produced by one successful run."""

    users_created: int = 0
    users_updated: int = 0
    profiles_created: int = 0
    profiles_updated: int = 0
    passwords_rotated: int = 0
    roles_assigned: int = 0

    def add(self, other: BootstrapSummary) -> BootstrapSummary:
        return BootstrapSummary(
            users_created=self.users_created + other.users_created,
            users_updated=self.users_updated + other.users_updated,
            profiles_created=self.profiles_created + other.profiles_created,
            profiles_updated=self.profiles_updated + other.profiles_updated,
            passwords_rotated=self.passwords_rotated + other.passwords_rotated,
            roles_assigned=self.roles_assigned + other.roles_assigned,
        )


def _required_string(item: dict[str, Any], field: str) -> str:
    value = item.get(field)
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"'{field}' must be a non-empty string.")
    return value.strip()


def _optional_string(item: dict[str, Any], field: str) -> str | None:
    value = item.get(field)
    if value is None:
        return None
    if not isinstance(value, str):
        raise ValueError(f"'{field}' must be a string or null.")
    normalized = value.strip()
    return normalized or None


def _load_manifest(path: Path) -> tuple[BootstrapUser, ...]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise ValueError(f"Bootstrap manifest was not found: {path}") from exc
    except json.JSONDecodeError as exc:
        raise ValueError(f"Bootstrap manifest contains invalid JSON: {exc}") from exc

    if not isinstance(payload, dict) or not isinstance(payload.get("users"), list):
        raise ValueError("The manifest root must contain a 'users' array.")

    users: list[BootstrapUser] = []
    seen_emails: set[str] = set()
    seen_phones: set[tuple[str, str]] = set()

    for index, raw_user in enumerate(payload["users"], start=1):
        if not isinstance(raw_user, dict):
            raise ValueError(f"users[{index}] must be an object.")

        email = normalize_email(_required_string(raw_user, "email"))
        country_code, phone_number = normalize_phone(
            _required_string(raw_user, "phone_country_code"),
            _required_string(raw_user, "phone_number"),
        )
        role_codes = raw_user.get("role_codes")
        if not isinstance(role_codes, list) or not role_codes:
            raise ValueError(f"users[{index}].role_codes must be a non-empty array.")
        normalized_roles = tuple(
            dict.fromkeys(
                _required_string({"role": role}, "role")
                for role in role_codes
            )
        )

        if email in seen_emails:
            raise ValueError(f"Duplicate email in manifest: {email}")
        phone_key = (country_code, phone_number)
        if phone_key in seen_phones:
            raise ValueError(
                "Duplicate phone in manifest: "
                f"{country_code}{phone_number}"
            )
        seen_emails.add(email)
        seen_phones.add(phone_key)

        users.append(
            BootstrapUser(
                email=email,
                phone_country_code=country_code,
                phone_number=phone_number,
                password=_required_string(raw_user, "password"),
                first_name=_required_string(raw_user, "first_name"),
                last_name=_optional_string(raw_user, "last_name"),
                preferred_name=_optional_string(raw_user, "preferred_name"),
                preferred_locale=(
                    _optional_string(raw_user, "preferred_locale") or "en-IN"
                ),
                timezone_name=(
                    _optional_string(raw_user, "timezone") or "Asia/Kolkata"
                ),
                role_codes=normalized_roles,
            )
        )

    if not users:
        raise ValueError("The bootstrap manifest must contain at least one user.")
    return tuple(users)


async def _active_roles(
    session: AsyncSession,
    role_codes: frozenset[str],
) -> dict[str, Roles]:
    records = await session.scalars(
        select(Roles).where(
            Roles.code.in_(role_codes),
            Roles.is_deleted.is_(False),
        )
    )
    by_code = {record.code: record for record in records}
    missing = role_codes - by_code.keys()
    if missing:
        raise RuntimeError(
            "Required roles are missing. Run seed_identity_master_data first: "
            f"{sorted(missing)}"
        )
    return by_code


async def _existing_user(
    session: AsyncSession,
    user: BootstrapUser,
) -> Users | None:
    by_email = await session.scalar(
        select(Users)
        .where(Users.email_normalized == user.email)
        .with_for_update()
    )
    by_phone = await session.scalar(
        select(Users)
        .where(
            Users.phone_country_code == user.phone_country_code,
            Users.phone_number == user.phone_number,
        )
        .with_for_update()
    )
    if by_email is not None and by_phone is not None and by_email.id != by_phone.id:
        raise RuntimeError(
            "The manifest email and phone belong to different existing users: "
            f"{user.email} / {user.phone_country_code}{user.phone_number}"
        )
    return by_email or by_phone


async def _sync_profile(
    session: AsyncSession,
    *,
    account: Users,
    seed: BootstrapUser,
) -> tuple[int, int]:
    profile = await session.scalar(
        select(UserProfiles)
        .where(
            UserProfiles.user_id == account.id,
            UserProfiles.is_deleted.is_(False),
        )
        .with_for_update()
    )
    if profile is None:
        session.add(
            UserProfiles(
                user_id=account.id,
                first_name=seed.first_name,
                last_name=seed.last_name,
                preferred_name=seed.preferred_name,
                created_by=account.id,
                updated_by=account.id,
            )
        )
        return 1, 0

    changed = False
    for field, value in (
        ("first_name", seed.first_name),
        ("last_name", seed.last_name),
        ("preferred_name", seed.preferred_name),
    ):
        if getattr(profile, field) != value:
            setattr(profile, field, value)
            changed = True
    if changed:
        profile.updated_by = account.id
    return 0, int(changed)


async def _assign_missing_roles(
    session: AsyncSession,
    *,
    account: Users,
    roles: dict[str, Roles],
    requested_codes: tuple[str, ...],
) -> int:
    current_role_ids = set(
        await session.scalars(
            select(UserRoles.role_id).where(
                UserRoles.user_id == account.id,
                UserRoles.scope_type.is_(None),
                UserRoles.scope_id.is_(None),
                UserRoles.is_active.is_(True),
            )
        )
    )
    missing_roles = [
        roles[code]
        for code in requested_codes
        if roles[code].id not in current_role_ids
    ]
    session.add_all(
        UserRoles(
            user_id=account.id,
            role_id=role.id,
            scope_type=None,
            scope_id=None,
            is_active=True,
        )
        for role in missing_roles
    )
    return len(missing_roles)


async def _sync_user(
    session: AsyncSession,
    *,
    seed: BootstrapUser,
    roles: dict[str, Roles],
    passwords: PasswordManager,
    rotate_passwords: bool,
) -> BootstrapSummary:
    now = datetime.now(timezone.utc)
    account = await _existing_user(session, seed)
    created = account is None
    updated = False
    password_rotated = 0

    if account is None:
        passwords.validate_strength(
            seed.password,
            email=seed.email,
            phone_number=seed.phone_number,
        )
        password_hash = await passwords.hash(seed.password)
        account = Users(
            id=uuid.uuid4(),
            email=seed.email,
            email_normalized=seed.email,
            phone_country_code=seed.phone_country_code,
            phone_number=seed.phone_number,
            password_hash=password_hash,
            status=UserStatus.ACTIVE,
            email_verified_at=now,
            phone_verified_at=now,
            preferred_locale=seed.preferred_locale,
            timezone=seed.timezone_name,
        )
        session.add(account)

        # Flush the parent row before inserting records that reference it.
        # These ORM mappings intentionally do not define relationships, so
        # SQLAlchemy cannot infer the required insert ordering from mapper
        # dependencies alone.
        await session.flush([account])

        session.add(
            PasswordHistory(
                user_id=account.id,
                password_hash=password_hash,
            )
        )
    else:
        expected = {
            "email": seed.email,
            "email_normalized": seed.email,
            "phone_country_code": seed.phone_country_code,
            "phone_number": seed.phone_number,
            "status": UserStatus.ACTIVE,
            "preferred_locale": seed.preferred_locale,
            "timezone": seed.timezone_name,
        }
        for field, value in expected.items():
            if getattr(account, field) != value:
                setattr(account, field, value)
                updated = True
        if account.email_verified_at is None:
            account.email_verified_at = now
            updated = True
        if account.phone_verified_at is None:
            account.phone_verified_at = now
            updated = True
        if rotate_passwords:
            passwords.validate_strength(
                seed.password,
                email=seed.email,
                phone_number=seed.phone_number,
            )
            password_hash = await passwords.hash(seed.password)
            account.password_hash = password_hash
            account.failed_login_count = 0
            account.locked_until = None
            session.add(
                PasswordHistory(
                    user_id=account.id,
                    password_hash=password_hash,
                )
            )
            password_rotated = 1

    await session.flush()
    profiles_created, profiles_updated = await _sync_profile(
        session,
        account=account,
        seed=seed,
    )
    roles_assigned = await _assign_missing_roles(
        session,
        account=account,
        roles=roles,
        requested_codes=seed.role_codes,
    )
    return BootstrapSummary(
        users_created=int(created),
        users_updated=int(updated),
        profiles_created=profiles_created,
        profiles_updated=profiles_updated,
        passwords_rotated=password_rotated,
        roles_assigned=roles_assigned,
    )


async def bootstrap_users(
    settings: AppSettings,
    *,
    seeds: tuple[BootstrapUser, ...],
    rotate_passwords: bool,
) -> BootstrapSummary:
    """Create and synchronize bootstrap identities in one transaction."""
    database = PostgreSQLDatabase(settings)
    passwords = PasswordManager(settings)
    required_roles = frozenset(
        code for seed in seeds for code in seed.role_codes
    )
    try:
        async with database.session() as session, SQLAlchemyUnitOfWork(session):
            await session.execute(
                text(
                    "SELECT pg_advisory_xact_lock("
                    "hashtextextended(:key, 0))"
                ),
                {"key": "identity-bootstrap-users-v1"},
            )
            roles = await _active_roles(session, required_roles)
            summary = BootstrapSummary()
            for seed in seeds:
                summary = summary.add(
                    await _sync_user(
                        session,
                        seed=seed,
                        roles=roles,
                        passwords=passwords,
                        rotate_passwords=rotate_passwords,
                    )
                )
            return summary
    finally:
        await database.close()


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Create or synchronize initial privileged identity users.",
    )
    parser.add_argument(
        "--config",
        required=True,
        type=Path,
        help="Path to the private bootstrap-user JSON manifest.",
    )
    parser.add_argument(
        "--check-only",
        action="store_true",
        help="Validate and display users without connecting to PostgreSQL.",
    )
    parser.add_argument(
        "--rotate-passwords",
        action="store_true",
        help="Replace passwords for existing manifest users.",
    )
    return parser


def main() -> int:
    args = _parser().parse_args()
    seeds = _load_manifest(args.config)
    if args.check_only:
        print(f"Manifest valid: {len(seeds)} bootstrap users.")
        for seed in seeds:
            print(f"- {seed.email}: {', '.join(seed.role_codes)}")
        return 0

    summary = asyncio.run(
        bootstrap_users(
            AppSettings(),
            seeds=seeds,
            rotate_passwords=args.rotate_passwords,
        )
    )
    print(
        "Bootstrap users synchronized: "
        f"users(created={summary.users_created}, updated={summary.users_updated}), "
        f"profiles(created={summary.profiles_created}, "
        f"updated={summary.profiles_updated}), "
        f"passwords_rotated={summary.passwords_rotated}, "
        f"roles_assigned={summary.roles_assigned}."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
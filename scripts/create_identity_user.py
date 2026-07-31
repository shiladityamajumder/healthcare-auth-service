"""Interactively create one identity user with profile and roles.

Example::

    python -m scripts.create_identity_user \
        --email admin@example.com \
        --phone-country-code +91 \
        --phone-number 9876543210 \
        --first-name Admin \
        --last-name User \
        --role platform_admin

The password is requested securely through ``getpass`` and is never accepted as
an argument, preventing it from being stored in shell history.
"""

from __future__ import annotations

import argparse
import asyncio
import getpass
import uuid
from datetime import UTC, datetime

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
from sqlalchemy import select


async def create_user(args: argparse.Namespace, password: str) -> uuid.UUID:
    settings = AppSettings()
    email = normalize_email(args.email)
    country_code, phone_number = normalize_phone(
        args.phone_country_code,
        args.phone_number,
    )
    passwords = PasswordManager(settings)
    passwords.validate_strength(
        password,
        email=email,
        phone_number=phone_number,
    )
    password_hash = await passwords.hash(password)
    database = PostgreSQLDatabase(settings)

    try:
        async with database.session() as session, SQLAlchemyUnitOfWork(session):
            existing = await session.scalar(
                select(Users.id).where(
                    (Users.email_normalized == email)
                    | (
                        (Users.phone_country_code == country_code)
                        & (Users.phone_number == phone_number)
                    )
                )
            )
            if existing is not None:
                raise RuntimeError(
                    "A user already exists with this email or phone number."
                )

            role_codes = tuple(dict.fromkeys(args.role))
            role_records = list(
                await session.scalars(
                    select(Roles).where(
                        Roles.code.in_(role_codes),
                        Roles.is_deleted.is_(False),
                    )
                )
            )
            roles_by_code = {role.code: role for role in role_records}
            missing = set(role_codes) - roles_by_code.keys()
            if missing:
                raise RuntimeError(
                    "Unknown or inactive roles: " f"{sorted(missing)}"
                )

            now = datetime.now(UTC)
            user_id = uuid.uuid4()
            account = Users(
                id=user_id,
                email=email,
                email_normalized=email,
                phone_country_code=country_code,
                phone_number=phone_number,
                password_hash=password_hash,
                status=UserStatus.ACTIVE,
                email_verified_at=now,
                phone_verified_at=now,
                preferred_locale=args.preferred_locale,
                timezone=args.timezone,
            )
            session.add(account)

            # Persist the parent user before inserting profile, password-history,
            # and role-assignment rows that reference identity.users.
            await session.flush([account])

            session.add(
                UserProfiles(
                    user_id=user_id,
                    first_name=args.first_name.strip(),
                    last_name=args.last_name.strip() if args.last_name else None,
                    preferred_name=(
                        args.preferred_name.strip()
                        if args.preferred_name
                        else None
                    ),
                    created_by=user_id,
                    updated_by=user_id,
                )
            )
            session.add(
                PasswordHistory(
                    user_id=user_id,
                    password_hash=password_hash,
                )
            )
            session.add_all(
                UserRoles(
                    user_id=user_id,
                    role_id=roles_by_code[code].id,
                    scope_type=None,
                    scope_id=None,
                    is_active=True,
                )
                for code in role_codes
            )
            return user_id
    finally:
        await database.close()


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Interactively create one identity user.",
    )
    parser.add_argument("--email", required=True)
    parser.add_argument("--phone-country-code", required=True)
    parser.add_argument("--phone-number", required=True)
    parser.add_argument("--first-name", required=True)
    parser.add_argument("--last-name")
    parser.add_argument("--preferred-name")
    parser.add_argument("--preferred-locale", default="en-IN")
    parser.add_argument("--timezone", default="Asia/Kolkata")
    parser.add_argument(
        "--role",
        action="append",
        required=True,
        help="Role code. Repeat the option to assign multiple roles.",
    )
    return parser


def main() -> int:
    args = _parser().parse_args()
    password = getpass.getpass("Password: ")
    confirmation = getpass.getpass("Confirm password: ")
    if password != confirmation:
        raise SystemExit("Passwords do not match.")
    user_id = asyncio.run(create_user(args, password))
    print(f"Identity user created: {user_id}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


# python -m scripts.create_identity_user `
#   --email admin@example.com `
#   --phone-country-code +91 `
#   --phone-number 9876543210 `
#   --first-name Shiladitya `
#   --last-name Admin `
#   --role platform_admin
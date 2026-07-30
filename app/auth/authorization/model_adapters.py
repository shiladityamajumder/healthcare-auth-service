"""Translate SQLAlchemy identity models into policy-owned immutable state.

Pylance correctly treats class-level SQLAlchemy attributes as ``Mapped[T]``
descriptors when performing structural protocol checks. Application code reads
``T`` from model instances at runtime. These adapters isolate that static
typing boundary instead of spreading casts through business services.
"""

from __future__ import annotations

from app.auth.authorization.policies import AccountAccessState, PasswordHistoryState
from app.models.identity import Users


def account_access_state(user: Users) -> AccountAccessState:
    """Copy persisted account fields into policy-owned immutable state."""
    return AccountAccessState(
        status=user.status,
        account_closed_at=user.account_closed_at,
        locked_until=user.locked_until,
        email=user.email,
        email_verified_at=user.email_verified_at,
        phone_number=user.phone_number,
        phone_verified_at=user.phone_verified_at,
    )


def password_history_state(user: Users) -> PasswordHistoryState:
    """Copy persisted password-history fields into immutable policy state."""
    return PasswordHistoryState(
        id=user.id,
        password_hash=user.password_hash,
    )


__all__ = ["account_access_state", "password_history_state"]

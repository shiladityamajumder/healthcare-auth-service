"""File: tests/unit/test_identity_model_contract.py

Purpose:
Protects identity/profile ORM schema placement, ownership, active-row
uniqueness, and phone-identity database constraints.

Dependency flow:
SQLAlchemy identity mapping metadata
-> table/constraint inspection
-> external schema contract assertions
"""

from __future__ import annotations

from app.db.base import Base
from app.models.identity import ApiClients, Sessions, UserProfiles, Users
from app.models.platform import FileObjects
from sqlalchemy import select
from sqlalchemy.dialects import postgresql


def test_identity_models_use_external_identity_schema() -> None:
    assert Users.__table__.schema == "identity"
    assert UserProfiles.__table__.schema == "identity"
    assert Sessions.__table__.schema == "identity"
    assert ApiClients.__table__.schema == "identity"


def test_identity_metadata_has_no_unresolved_foreign_keys() -> None:
    assert Base.metadata.sorted_tables


def test_phone_uniqueness_is_partial_not_nulls_not_distinct() -> None:
    indexes = {index.name: index for index in Users.__table__.indexes}
    phone_index = indexes["uq_identity_users_phone_present"]
    assert phone_index.unique is True
    where = str(phone_index.dialect_options["postgresql"]["where"])
    assert "phone_country_code IS NOT NULL" in where
    assert "phone_number IS NOT NULL" in where


def test_phone_identity_requires_both_fields() -> None:
    constraints = {constraint.name for constraint in Users.__table__.constraints}
    assert "ck_identity_users_phone_pair_complete" in constraints


def test_user_profile_belongs_to_identity_user() -> None:
    foreign_keys = {
        foreign_key.target_fullname for foreign_key in UserProfiles.__table__.foreign_keys
    }
    assert "identity.users.id" in foreign_keys


def test_avatar_is_a_platform_file_object_reference() -> None:
    avatar_file_id = UserProfiles.__table__.columns["avatar_file_id"]

    assert avatar_file_id.type.compile(dialect=postgresql.dialect()) == "UUID"
    assert avatar_file_id.nullable is True
    assert {foreign_key.target_fullname for foreign_key in avatar_file_id.foreign_keys} == {
        "platform.file_objects.id"
    }


def test_file_object_projection_matches_platform_schema() -> None:
    assert FileObjects.__table__.schema == "platform"
    assert FileObjects.public_url.nullable is True
    assert FileObjects.object_key.type.length == 512
    assert FileObjects.public_url.type.length == 2048
    assert "avatar_public_url" not in UserProfiles.__table__.columns


def test_avatar_url_projection_is_filtered_to_safe_public_files() -> None:
    statement = select(UserProfiles).compile(
        dialect=postgresql.dialect(),
        compile_kwargs={"literal_binds": True},
    )
    sql = str(statement)

    assert "platform.file_objects" in sql
    assert "identity.user_profile.avatar" in sql
    assert "image/%%" in sql
    assert "access_type = 'public'" in sql
    assert "status = 'available'" in sql
    assert "malware_scan_status = 'clean'" in sql
    assert "is_deleted IS false" in sql


def test_identity_timestamps_match_timezone_aware_postgres_columns() -> None:
    dialect = postgresql.dialect()

    assert UserProfiles.created_at.type.compile(dialect=dialect) == "TIMESTAMP WITH TIME ZONE"
    assert Users.last_login_at.type.compile(dialect=dialect) == "TIMESTAMP WITH TIME ZONE"


def test_user_profile_has_one_active_row_per_user() -> None:
    indexes = {index.name: index for index in UserProfiles.__table__.indexes}
    active_index = indexes["uq_identity_user_profiles_user_active"]
    assert active_index.unique is True
    where = str(active_index.dialect_options["postgresql"]["where"])
    assert "is_deleted = false" in where

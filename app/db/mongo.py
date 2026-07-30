"""File: app/db/mongo.py
    Asynchronous MongoDB client lifecycle adapter using PyMongo Async.
"""

from __future__ import annotations

from typing import Any

from pymongo import AsyncMongoClient
from pymongo.asynchronous.database import AsyncDatabase

from app.core.config import AppSettings
from app.core.logging import get_logger

logger = get_logger(__name__)

type Document = dict[str, Any]


class MongoDatabase:
    """Own a process-wide asynchronous MongoDB client.

    One adapter instance should be created during application startup and
    shared across requests. The underlying PyMongo client manages its own
    connection pool and is safe for concurrent asynchronous operations.

    Repositories should consume the configured ``database`` proxy rather than
    creating independent MongoDB clients.
    """

    def __init__(
        self,
        *,
        uri: str,
        database_name: str,
        settings: AppSettings,
    ) -> None:
        """Initialize the MongoDB client and database proxy.

        Args:
            uri: Validated MongoDB connection URI.
            database_name: Database used by application repositories.
            settings: Validated application configuration.

        Raises:
            ValueError: If the URI or database name is blank.
        """
        normalized_uri = uri.strip()
        normalized_database_name = database_name.strip()

        if not normalized_uri:
            raise ValueError("MongoDB URI must not be blank")

        if not normalized_database_name:
            raise ValueError("MongoDB database name must not be blank")

        self._client: AsyncMongoClient[Document] = AsyncMongoClient(
            normalized_uri,
            appname=settings.PROJECT_NAME,
            minPoolSize=settings.MONGO_MIN_POOL_SIZE,
            maxPoolSize=settings.MONGO_MAX_POOL_SIZE,
            serverSelectionTimeoutMS=(
                settings.MONGO_SERVER_SELECTION_TIMEOUT_MS
            ),
            connectTimeoutMS=settings.MONGO_CONNECT_TIMEOUT_MS,
            socketTimeoutMS=settings.MONGO_SOCKET_TIMEOUT_MS,
            retryReads=True,
            retryWrites=settings.MONGO_RETRY_WRITES,
            uuidRepresentation="standard",
        )

        self._database: AsyncDatabase[Document] = self._client.get_database(
            normalized_database_name,
        )

        logger.info(
            "MongoDB client initialized",
            extra={
                "database": normalized_database_name,
                "min_pool_size": settings.MONGO_MIN_POOL_SIZE,
                "max_pool_size": settings.MONGO_MAX_POOL_SIZE,
            },
        )

    @classmethod
    def from_settings(
        cls,
        settings: AppSettings,
    ) -> MongoDatabase:
        """Build the MongoDB adapter from validated configuration.

        Args:
            settings: Validated application configuration.

        Returns:
            Initialized MongoDB adapter.

        Raises:
            RuntimeError: If MongoDB is disabled or incompletely configured.
        """
        if not settings.ENABLE_MONGO:
            raise RuntimeError("MongoDB is not enabled")

        uri = settings.mongo_uri_value

        if not uri:
            raise RuntimeError("MongoDB URI is not configured")

        if not settings.MONGO_DB_NAME:
            raise RuntimeError("MongoDB database name is not configured")

        return cls(
            uri=uri,
            database_name=settings.MONGO_DB_NAME,
            settings=settings,
        )

    @property
    def client(self) -> AsyncMongoClient[Document]:
        """Return the shared MongoDB client.

        Direct client access should be limited to infrastructure operations
        such as sessions, administrative commands, or transaction handling.

        Returns:
            Shared asynchronous MongoDB client.
        """
        return self._client

    @property
    def database(self) -> AsyncDatabase[Document]:
        """Return the configured database proxy.

        Returns:
            MongoDB database proxy consumed by repositories.
        """
        return self._database

    async def ping(self) -> None:
        """Verify MongoDB server selection and command execution.

        Raises:
            Exception: Propagates connectivity, authentication, timeout, and
                server-selection failures to the lifecycle boundary.
        """
        await self._client.admin.command("ping")

        logger.debug("MongoDB connectivity verified")

    async def close(self) -> None:
        """Close the MongoDB client and all managed connection pools."""
        await self._client.close()

        logger.info("MongoDB client closed")


__all__ = [
    "Document",
    "MongoDatabase",
]

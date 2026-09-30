import os

from dotenv import load_dotenv
from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeBase, sessionmaker

# Load environment variables from .env
load_dotenv()

DATABASE_URL = os.getenv("DATABASE_URL")

if not DATABASE_URL:
    raise RuntimeError(
        "DATABASE_URL is not configured. " "Please check your .env file."
    )


class Base(DeclarativeBase):
    """Base class for all SQLAlchemy database models."""

    pass


# Create the SQLAlchemy database engine
engine = create_engine(
    DATABASE_URL,
    pool_pre_ping=True,
    echo=False,
)


# Create a database session factory
SessionLocal = sessionmaker(
    bind=engine,
    autoflush=False,
    autocommit=False,
)


def get_db():
    """
    Create and provide a database session.

    The session is closed automatically after use.
    """

    db = SessionLocal()

    try:
        yield db
    finally:
        db.close()

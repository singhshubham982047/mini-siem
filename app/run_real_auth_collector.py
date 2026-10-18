from sqlalchemy import select

from app.collector.collector_manager import CollectorManager
from app.database.connection import SessionLocal
from app.database.models import LogSource


import os

AUTH_LOG_PATH = os.getenv("REAL_AUTH_LOG_PATH", "/var/log/auth.log")
LOG_SOURCE_NAME = "linux-auth-real"


def get_or_create_log_source(db):
    """
    Get the real Linux authentication log source,
    or create it if it does not exist.
    """

    log_source = db.scalar(
        select(LogSource).where(
            LogSource.name == LOG_SOURCE_NAME
        )
    )

    if log_source:
        return log_source

    log_source = LogSource(
        name=LOG_SOURCE_NAME,
        source_type="linux_auth",
        file_path=AUTH_LOG_PATH,
        enabled=True,
    )

    db.add(log_source)
    db.commit()
    db.refresh(log_source)

    return log_source


def main():
    print("=" * 60)
    print("Mini SIEM - Real Linux Authentication Collector")
    print("=" * 60)

    with SessionLocal() as db:
        log_source = get_or_create_log_source(db)

        print(f"Log source: {log_source.name}")
        print(f"File: {log_source.file_path}")
        print(f"Source ID: {log_source.id}")

        collector = CollectorManager(
            db=db,
            file_path=AUTH_LOG_PATH,
            log_source_id=log_source.id,
        )

        print()
        print("Starting real authentication log monitoring...")
        print("Existing log entries will be skipped.")
        print("Only newly appended entries will be processed.")
        print("Press CTRL+C to stop.")
        print()

        try:
            collector.start()

        except KeyboardInterrupt:
            print("\nStopping real authentication collector...")
            collector.stop()

        finally:
            db.close()


if __name__ == "__main__":
    main()

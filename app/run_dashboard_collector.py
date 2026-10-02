
from pathlib import Path

from app.collector.collector_manager import CollectorManager
from app.database.connection import SessionLocal
from app.database.repository import LogSourceRepository


SOURCE_NAME = "dashboard-auth-demo"
LOG_FILE = Path("sample_logs/dashboard-auth.log")


def main():
    LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
    LOG_FILE.touch(exist_ok=True)

    with SessionLocal() as db:
        source = LogSourceRepository.get_by_name(db, SOURCE_NAME)

        if source is None:
            raise RuntimeError(
                f"Log source '{SOURCE_NAME}' is not registered. "
                "Run the setup command first."
            )

        source_id = source.id

    db = SessionLocal()
    manager = CollectorManager(
        db=db,
        file_path=str(LOG_FILE),
        log_source_id=source_id,
    )

    try:
        print("Mini SIEM dashboard collector")
        print(f"Source: {SOURCE_NAME}")
        print(f"File: {LOG_FILE.resolve()}")
        print("Append SSH log lines to this file in another terminal.")
        print("Press Ctrl+C to stop collecting.")

        manager.start()

    except KeyboardInterrupt:
        print("\nStopping collector...")

    finally:
        manager.stop()
        db.close()
        print("Collector stopped.")


if __name__ == "__main__":
    main()

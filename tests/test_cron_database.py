from app.database.connection import SessionLocal
from app.database.models import LogSource
from app.collector.collector_manager import CollectorManager
from sqlalchemy import select

CRON_OPEN_LOG = (
    "2026-10-05T19:00:01.123456+05:30 "
    "ubuntu-HP-EliteBook-840-G6 "
    "CRON[20001]: pam_unix(cron:session): "
    "session opened for user root(uid=0) by root(uid=0)"
)

CRON_CLOSE_LOG = (
    "2026-10-05T19:00:01.123789+05:30 "
    "ubuntu-HP-EliteBook-840-G6 "
    "CRON[20001]: pam_unix(cron:session): "
    "session closed for user root"
)


LOG_SOURCE_NAME = "linux-cron-test"


def get_or_create_log_source(db):
    log_source = db.scalar(select(LogSource).where(LogSource.name == LOG_SOURCE_NAME))

    if log_source:
        return log_source

    log_source = LogSource(
        name=LOG_SOURCE_NAME,
        source_type="linux_cron",
        file_path="/tmp/test-cron.log",
        enabled=True,
    )

    db.add(log_source)
    db.commit()
    db.refresh(log_source)

    return log_source


def main():
    with SessionLocal() as db:

        log_source = get_or_create_log_source(db)

        print("Log source ID:", log_source.id)

        collector = CollectorManager(
            db=db,
            file_path="/tmp/test-cron.log",
            log_source_id=log_source.id,
        )

        print("\nProcessing CRON session open...")
        collector.process_log_line(f"{CRON_OPEN_LOG}")

        print("\nProcessing CRON session close...")
        collector.process_log_line(f"{CRON_CLOSE_LOG}")

        print("\nCRON database pipeline test completed.")


if __name__ == "__main__":
    main()


import os
import time
import threading
from datetime import datetime
from pathlib import Path

from sqlalchemy import select

from app.collector.collector_manager import CollectorManager
from app.database.connection import SessionLocal
from app.database.models import LogSource


LOG_PATH = Path(
    os.getenv(
        "DEMO_LOG_PATH",
        "/app/demo_logs/docker-demo-auth.log",
    )
)

BURST_COUNT = max(1, int(os.getenv("DEMO_BURST_COUNT", "5")))
BURST_DELAY = max(
    0.1,
    float(os.getenv("DEMO_BURST_DELAY_SECONDS", "0.8")),
)


def append_demo_events():
    """Append synthetic SSH failures after the watcher starts."""
    time.sleep(2)

    print(f"Generating {BURST_COUNT} synthetic SSH failures.")

    for index in range(BURST_COUNT):
        timestamp = datetime.now().astimezone().strftime("%b %d %H:%M:%S")
        port = 53000 + index

        line = (
            f"{timestamp} docker-demo sshd[2000]: "
            f"Failed password for admin from 192.0.2.123 "
            f"port {port} ssh2"
        )

        try:
            with LOG_PATH.open("a", encoding="utf-8") as log_file:
                log_file.write(line + "\n")
                log_file.flush()

            print(f"Appended synthetic event {index + 1}/{BURST_COUNT}")
        except OSError as exc:
            print(f"Could not append demo event: {exc}")
            return

        time.sleep(BURST_DELAY)

    print("Demo event generation completed.")


def main():
    LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
    LOG_PATH.touch(exist_ok=True)

    db = SessionLocal()
    manager = None
    producer = None

    try:
        source = db.scalar(
            select(LogSource).where(
                LogSource.name == "docker-demo-auth"
            )
        )

        if source is None:
            raise RuntimeError(
                "Demo log source is missing. Run app.init_db first."
            )

        if not source.enabled:
            raise RuntimeError("The Docker demo log source is disabled.")

        manager = CollectorManager(
            db=db,
            file_path=str(LOG_PATH),
            log_source_id=source.id,
        )

        producer = threading.Thread(
            target=append_demo_events,
            name="demo-log-producer",
            daemon=True,
        )
        producer.start()

        print("Starting the synthetic Docker demo collector.")
        manager.start()

    except KeyboardInterrupt:
        print("Demo collector interrupted.")
    finally:
        if manager is not None:
            manager.stop()

        if producer is not None:
            producer.join(timeout=5)

        db.close()
        print("Demo collector stopped.")


if __name__ == "__main__":
    main()

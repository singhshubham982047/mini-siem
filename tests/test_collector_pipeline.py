import threading
import time
from pathlib import Path

from app.collector.collector_manager import CollectorManager
from app.database.connection import SessionLocal
from app.database.models import Alert, Event
from app.database.repository import LogSourceRepository

TEST_FILE = Path("sample_logs/test-auth-pipeline.log")


def main():
    db = SessionLocal()

    source_name = "collector-pipeline-test"
    test_ip = "192.168.50.100"

    try:
        # Create test log source
        source = LogSourceRepository.get_by_name(
            db,
            source_name,
        )

        if source is None:
            source = LogSourceRepository.create(
                db=db,
                name=source_name,
                source_type="linux",
                file_path=str(TEST_FILE),
            )

            # Remove previous test data if an earlier run failed
        db.query(Alert).filter(Alert.src_ip == test_ip).delete(
            synchronize_session=False
        )

        db.query(Event).filter(Event.src_ip == test_ip).delete(
            synchronize_session=False
        )

        db.commit()

        # Start with an empty test file
        TEST_FILE.parent.mkdir(
            parents=True,
            exist_ok=True,
        )

        TEST_FILE.write_text(
            "",
            encoding="utf-8",
        )

        manager = CollectorManager(
            db=db,
            file_path=str(TEST_FILE),
            log_source_id=source.id,
        )

        watcher_thread = threading.Thread(
            target=manager.start,
            daemon=True,
        )

        watcher_thread.start()

        time.sleep(0.5)

        print("\nWriting simulated SSH login failures...")

        # Write five failed SSH logins
        with TEST_FILE.open(
            "a",
            encoding="utf-8",
        ) as log_file:

            for i in range(5):
                log_file.write(
                    f"Sep 23 10:00:{10 + i:02d} "
                    f"ubuntu sshd[30{i}]: "
                    f"Failed password for admin "
                    f"from {test_ip} "
                    f"port {52000 + i} ssh2\n"
                )

        # Give the watcher time to process the lines
        time.sleep(2)

        manager.stop()

        # Verify events
        events = db.query(Event).filter(Event.src_ip == test_ip).all()

        print(f"\nEvents stored in PostgreSQL: " f"{len(events)}")

        if len(events) != 5:
            raise RuntimeError(f"Expected 5 events, found {len(events)}")

        # Verify alerts
        alerts = db.query(Alert).filter(Alert.src_ip == test_ip).all()

        print(f"Alerts generated: {len(alerts)}")

        if not alerts:
            raise RuntimeError("Expected a brute-force alert")

        print("\n================================")
        print("FULL SIEM PIPELINE TEST PASSED")
        print("================================")

        print("\nPipeline:")
        print("  Log file")
        print("      ↓")
        print("  File Watcher")
        print("      ↓")
        print("  Auth Parser")
        print("      ↓")
        print("  PostgreSQL")
        print("      ↓")
        print("  Detection Engine")
        print("      ↓")
        print("  Brute Force Alert")

        # Cleanup alerts
        for alert in alerts:
            db.delete(alert)

        # Cleanup events
        for event in events:
            db.delete(event)

        db.commit()

        # Cleanup source
        source_after = LogSourceRepository.get_by_name(
            db,
            source_name,
        )

        if source_after:
            db.delete(source_after)
            db.commit()

        print("\nTest records cleaned up")

    except Exception:
        db.rollback()
        raise

    finally:
        manager.stop()
        db.close()
        TEST_FILE.unlink(missing_ok=True)


if __name__ == "__main__":
    main()

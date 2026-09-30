from datetime import datetime, timezone

from app.database.connection import SessionLocal
from app.database.models import Event, LogSource
from app.database.repository import (
    EventRepository,
    LogSourceRepository,
)


def main():
    db = SessionLocal()

    test_source_name = "test-auth-log"

    try:
        # 1. Create a test log source
        existing_source = LogSourceRepository.get_by_name(
            db,
            test_source_name,
        )

        if existing_source:
            source = existing_source
            print("Using existing test log source")
        else:
            source = LogSourceRepository.create(
                db=db,
                name=test_source_name,
                source_type="linux",
                file_path="/tmp/test-auth.log",
            )
            print(f"Created log source: {source.name}")

        # 2. Insert a sample security event
        event = EventRepository.create(
            db=db,
            timestamp=datetime.now(timezone.utc),
            source="linux",
            event_type="authentication",
            action="login",
            username="testuser",
            src_ip="192.168.1.100",
            status="failure",
            severity="medium",
            message="Failed SSH login for testuser",
            raw_log=("Failed password for testuser " "from 192.168.1.100"),
            log_source_id=source.id,
        )

        print(f"Created event ID: {event.id}")

        # 3. Retrieve recent events
        events = EventRepository.get_recent(
            db=db,
            limit=10,
        )

        print(f"Retrieved {len(events)} recent event(s)")

        # 4. Display the inserted event
        matching_event = next(
            (item for item in events if item.id == event.id),
            None,
        )

        if matching_event:
            print("\nInserted event details:")
            print(f"  ID: {matching_event.id}")
            print(f"  Source: {matching_event.source}")
            print(f"  Event type: {matching_event.event_type}")
            print(f"  Username: {matching_event.username}")
            print(f"  Source IP: {matching_event.src_ip}")
            print(f"  Status: {matching_event.status}")
            print(f"  Severity: {matching_event.severity}")

        print("\nRepository test completed successfully")

        # 5. Clean up test event and source
        db.delete(event)
        db.commit()

        remaining_source = LogSourceRepository.get_by_name(
            db,
            test_source_name,
        )

        if remaining_source:
            db.delete(remaining_source)
            db.commit()

        print("Test records cleaned up successfully")

    except Exception:
        db.rollback()
        raise

    finally:
        db.close()


if __name__ == "__main__":
    main()

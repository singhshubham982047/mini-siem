from app.database.connection import SessionLocal
from app.database.repository import EventRepository, LogSourceRepository
from app.parser.auth_parser import AuthLogParser


def main():
    db = SessionLocal()

    test_source_name = "linux-auth-test"

    try:
        # 1. Create or reuse a test log source
        source = LogSourceRepository.get_by_name(
            db,
            test_source_name,
        )

        if source is None:
            source = LogSourceRepository.create(
                db=db,
                name=test_source_name,
                source_type="linux",
                file_path="/tmp/auth.log",
            )

        print(f"Log source ready: {source.name}")

        # 2. Raw Linux authentication log
        raw_log = (
            "Sep 23 09:30:15 ubuntu sshd[2001]: "
            "Failed password for admin "
            "from 192.168.1.50 port 55221 ssh2"
        )

        print("\nRaw log:")
        print(raw_log)

        # 3. Parse the log
        parsed_event = AuthLogParser.parse(raw_log)

        if parsed_event is None:
            raise RuntimeError("Parser failed to recognize the log")

        print("\nParser result:")
        for field, value in parsed_event.items():
            print(f"  {field}: {value}")

        # 4. Store parsed event in PostgreSQL
        event = EventRepository.create(
            db=db,
            log_source_id=source.id,
            **parsed_event,
        )

        print("\nDatabase result:")
        print(f"  Event ID: {event.id}")
        print(f"  Username: {event.username}")
        print(f"  Source IP: {event.src_ip}")
        print(f"  Status: {event.status}")
        print(f"  Severity: {event.severity}")

        # 5. Verify the event can be retrieved
        found = EventRepository.get_by_id(
            db=db,
            event_id=event.id,
        )

        if found:
            print("\nEvent successfully retrieved from PostgreSQL")
        else:
            raise RuntimeError("Event was inserted but could not be retrieved")

        # 6. Clean up test data
        db.delete(event)
        db.commit()

        print("Test event cleaned up successfully")

        source_after = LogSourceRepository.get_by_name(
            db,
            test_source_name,
        )

        if source_after:
            db.delete(source_after)
            db.commit()

        print("Test log source cleaned up successfully")
        print("\nParser → PostgreSQL integration test passed")

    except Exception:
        db.rollback()
        raise

    finally:
        db.close()


if __name__ == "__main__":
    main()

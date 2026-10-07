from app.parser.auth_parser import AuthLogParser
from app.database.connection import SessionLocal
from app.database.repository import EventRepository


LOG_LINE = (
    "2026-10-06T19:09:55.353168+05:30 "
    "ubuntu-HP-EliteBook-840-G6 gdm-password]: "
    "gkr-pam: unlocked login keyring"
)


def main():
    parser = AuthLogParser()

    print("\nProcessing GDM keyring unlock event...")

    parsed_event = parser.parse(LOG_LINE)

    if parsed_event is None:
        raise RuntimeError("GDM keyring event was not parsed.")

    print("Parsed event:")
    print(f"  Event type: {parsed_event['event_type']}")
    print(f"  Action: {parsed_event['action']}")
    print(f"  Status: {parsed_event['status']}")
    print(f"  Severity: {parsed_event['severity']}")
    print(f"  Message: {parsed_event['message']}")

    with SessionLocal() as db:
        event = EventRepository.create(
            db=db,
            **parsed_event,
        )

        print("\nEvent stored in PostgreSQL:")
        print(f"  Event ID: {event.id}")
        print(f"  Event type: {event.event_type}")
        print(f"  Action: {event.action}")
        print(f"  Status: {event.status}")
        print(f"  Severity: {event.severity}")

        assert event.event_type == "authentication"
        assert event.action == "keyring_unlock"
        assert event.status == "success"
        assert event.severity == "low"

        print("\nGDM keyring database pipeline test passed.")


if __name__ == "__main__":
    main()

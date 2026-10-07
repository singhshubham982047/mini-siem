from app.parser.auth_parser import AuthLogParser
from app.database.connection import SessionLocal
from app.database.repository import EventRepository


LOG_LINE = (
    "2026-10-06T18:52:42.113893+05:30 "
    "ubuntu-HP-EliteBook-840-G6 pkexec: "
    "pam_unix(polkit-1:session): session opened for user "
    "root(uid=0) by ubuntu(uid=1000)"
)


def main():
    parser = AuthLogParser()

    print("\nProcessing pkexec privilege-escalation event...")

    parsed_event = parser.parse(LOG_LINE)

    if parsed_event is None:
        raise RuntimeError("Pkexec event was not parsed.")

    with SessionLocal() as db:
        event = EventRepository.create(
            db=db,
            **parsed_event,
        )

        print(f"Event stored in PostgreSQL: ID={event.id}")
        print(f"Event type: {event.event_type}")
        print(f"Action: {event.action}")
        print(f"Username: {event.username}")
        print(f"Status: {event.status}")
        print(f"Severity: {event.severity}")

        assert event.event_type == "privilege_escalation"
        assert event.action == "pkexec_session_open"
        assert event.username == "ubuntu"
        assert event.status == "success"
        assert event.severity == "medium"

        print("\nPkexec database pipeline test passed.")


if __name__ == "__main__":
    main()

from app.parser.auth_parser import AuthLogParser
from app.database.connection import SessionLocal
from app.database.repository import EventRepository


LOG_LINES = [
    (
        "2026-10-07T00:22:26.861125+05:30 "
        "ubuntu-HP-EliteBook-840-G6 systemd-logind[1541]: "
        "New session 'c1' of user 'gdm-greeter' "
        "with class 'greeter' and type 'wayland'."
    ),
    (
        "2026-10-07T00:22:52.085840+05:30 "
        "ubuntu-HP-EliteBook-840-G6 systemd-logind[1541]: "
        "Removed session 1."
    ),
]


def main():
    parser = AuthLogParser()

    with SessionLocal() as db:
        for log_line in LOG_LINES:
            print("\nProcessing systemd-logind event...")

            parsed_event = parser.parse(log_line)

            if parsed_event is None:
                raise RuntimeError("systemd-logind event was not parsed.")

            print(
                f"Parsed event: "
                f"{parsed_event['event_type']} | "
                f"{parsed_event['action']} | "
                f"user={parsed_event['username']}"
            )

            event = EventRepository.create(
                db=db,
                **parsed_event,
            )

            print(f"Event stored in PostgreSQL: ID={event.id}")

            assert event.event_type == "session"
            assert event.status == "success"
            assert event.severity == "low"

        print("\nSystemd session database pipeline test passed.")


if __name__ == "__main__":
    main()

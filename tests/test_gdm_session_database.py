from app.parser.auth_parser import AuthLogParser
from app.database.connection import SessionLocal
from app.database.repository import EventRepository


LOG_LINES = [
    (
        "2026-10-06T18:52:36.881715+05:30 "
        "ubuntu-HP-EliteBook-840-G6 gdm-password]: "
        "pam_unix(gdm-password:session): session opened for user "
        "ubuntu(uid=1000) by ubuntu(uid=0)"
    ),
    (
        "2026-10-06T18:52:41.762740+05:30 "
        "ubuntu-HP-EliteBook-840-G6 gdm-password]: "
        "pam_unix(gdm-password:session): session closed for user ubuntu"
    ),
]


def main():
    parser = AuthLogParser()

    with SessionLocal() as db:
        for log_line in LOG_LINES:
            print("\nProcessing GDM session log...")

            parsed_event = parser.parse(log_line)

            if parsed_event is None:
                raise RuntimeError("GDM log was not parsed.")

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
            assert event.username == "ubuntu"
            assert event.status == "success"

        print("\nGDM session database pipeline test passed.")


if __name__ == "__main__":
    main()

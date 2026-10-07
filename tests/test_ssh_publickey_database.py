from app.parser.auth_parser import AuthLogParser
from app.database.connection import SessionLocal
from app.database.repository import EventRepository


LOG_LINE = (
    "2026-10-06T10:30:15.123456+05:30 "
    "ubuntu-HP-EliteBook-840-G6 sshd[5678]: "
    "Accepted publickey for ubuntu from 192.168.1.25 port 52234 ssh2: "
    "ED25519 SHA256:example"
)


def main():
    parser = AuthLogParser()

    print("\nParsing SSH public-key login...")
    parsed_event = parser.parse(LOG_LINE)

    if parsed_event is None:
        raise RuntimeError("SSH public-key log was not parsed.")

    print("Parser result:")
    print(f"  Event type: {parsed_event['event_type']}")
    print(f"  Action: {parsed_event['action']}")
    print(f"  Username: {parsed_event['username']}")
    print(f"  Source IP: {parsed_event['src_ip']}")
    print(f"  Source port: {parsed_event['src_port']}")
    print(f"  Status: {parsed_event['status']}")

    with SessionLocal() as db:
        event = EventRepository.create(
            db=db,
            **parsed_event,
        )

        print("\nEvent stored in PostgreSQL:")
        print(f"  Event ID: {event.id}")
        print(f"  Event type: {event.event_type}")
        print(f"  Action: {event.action}")
        print(f"  Username: {event.username}")
        print(f"  Source IP: {event.src_ip}")
        print(f"  Source port: {event.src_port}")
        print(f"  Status: {event.status}")
        print(f"  Severity: {event.severity}")

        assert event.event_type == "authentication"
        assert event.action == "login"
        assert event.username == "ubuntu"
        assert event.src_ip == "192.168.1.25"
        assert event.src_port == 52234
        assert event.status == "success"

        print("\nSSH public-key database pipeline test passed.")


if __name__ == "__main__":
    main()

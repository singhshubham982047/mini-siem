from datetime import datetime, timezone

from app.database.connection import SessionLocal
from app.database.models import Event
from app.detection.engine import DetectionEngine


def main():
    with SessionLocal() as db:

        print("=" * 60)
        print("Testing Suspicious Sudo Command Detection")
        print("=" * 60)

        event = Event(
            timestamp=datetime.now(timezone.utc),
            source="linux",
            event_type="privilege_escalation",
            action="sudo_command",
            username="sudo-test-user",
            src_ip=None,
            dst_ip=None,
            src_port=None,
            dst_port=None,
            status="success",
            severity="medium",
            message="Sudo command executed as root: sudo -i",
            raw_log=(
                "sudo: sudo-test-user : "
                "TTY=/dev/pts/2 ; "
                "PWD=/home/ubuntu ; "
                "USER=root ; "
                "COMMAND=/usr/bin/sudo -i"
            ),
        )

        db.add(event)
        db.commit()
        db.refresh(event)

        print(f"\nCreated event ID={event.id}")
        print(f"Username: {event.username}")
        print(f"Action: {event.action}")
        print(f"Message: {event.message}")

        print("\nRunning Detection Engine...")

        alerts = DetectionEngine.process_event(
            db=db,
            event=event,
        )

        print(f"\nAlerts generated: {len(alerts)}")

        for alert in alerts:
            print("\n🚨 ALERT")
            print(f"Alert ID: {alert.id}")
            print(f"Rule: {alert.rule_name}")
            print(f"Severity: {alert.severity}")
            print(f"Username: {alert.username}")
            print(f"Title: {alert.title}")
            print(f"Status: {alert.status}")

        if not alerts:
            print("\n❌ TEST FAILED")
            print("No suspicious sudo alert was generated.")
            return

        print("\n✅ TEST PASSED")
        print("Suspicious sudo command detection is working.")


if __name__ == "__main__":
    main()

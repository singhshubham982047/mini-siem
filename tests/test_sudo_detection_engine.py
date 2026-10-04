from datetime import datetime, timedelta, timezone

from app.database.connection import SessionLocal
from app.database.models import Event
from app.detection.engine import DetectionEngine


def main():

    with SessionLocal() as db:

        base_time = datetime.now(timezone.utc)

        print("\nCreating 3 failed sudo authentication events...")

        events = []

        for i in range(3):

            event = Event(
                timestamp=base_time + timedelta(seconds=i),
                source="linux",
                event_type="authentication",
                action="sudo_authentication",
                username="engine-sudo-test",
                src_ip=None,
                dst_ip=None,
                src_port=None,
                dst_port=None,
                status="failure",
                severity="medium",
                message="Failed sudo authentication attempt",
                raw_log="test sudo authentication failure",
            )

            db.add(event)
            db.flush()

            events.append(event)

            print(f"Created event ID={event.id}")

        db.commit()

        print("\nRunning Detection Engine...")

        alerts = DetectionEngine.process_event(
            db=db,
            event=events[-1],
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


if __name__ == "__main__":
    main()


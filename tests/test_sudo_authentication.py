from datetime import datetime, timedelta, timezone

from app.database.connection import SessionLocal
from app.database.models import Event
from app.detection.sudo_authentication import SudoAuthenticationDetector


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
                username="sudo-test-user",
                src_ip=None,
                dst_ip=None,
                src_port=None,
                dst_port=None,
                status="failure",
                severity="medium",
                message="Failed sudo authentication attempt",
                raw_log=(
                    "test sudo authentication failure"
                ),
            )

            db.add(event)
            db.flush()

            events.append(event)

            print(
                f"Created event ID={event.id}"
            )

        db.commit()

        print("\nRunning sudo authentication detector...")

        alert = SudoAuthenticationDetector.detect(
            db=db,
            event=events[-1],
            threshold=3,
            window_minutes=5,
        )

        if alert is None:
            print("❌ No alert generated")
            return

        print("\n🚨 ALERT GENERATED")
        print(f"Alert ID: {alert.id}")
        print(f"Rule: {alert.rule_name}")
        print(f"Severity: {alert.severity}")
        print(f"Username: {alert.username}")
        print(f"Title: {alert.title}")
        print(f"Status: {alert.status}")


if __name__ == "__main__":
    main()

from datetime import datetime, timedelta, timezone

from app.database.connection import SessionLocal
from app.database.models import Event
from app.detection.brute_force import BruteForceDetector


def main():
    db = SessionLocal()

    test_ip = "10.10.10.50"

    try:
        now = datetime.now(timezone.utc)

        print("Creating simulated failed SSH login events...")

        # Create 5 failed login attempts
        for i in range(5):
            event = Event(
                timestamp=now - timedelta(seconds=i * 30),
                source="linux",
                event_type="authentication",
                action="login",
                username="admin",
                src_ip=test_ip,
                src_port=50000 + i,
                status="failure",
                severity="medium",
                message="Failed SSH login attempt",
                raw_log=(f"Simulated failed login {i + 1}"),
            )

            db.add(event)

        db.commit()

        print("Created 5 failed login events")

        # Run detection
        alert = BruteForceDetector.detect(
            db=db,
            src_ip=test_ip,
        )

        if alert is None:
            raise RuntimeError("Brute-force detector did not create an alert")

        print("\nBrute-force detection triggered!")
        print(f"  Alert ID: {alert.id}")
        print(f"  Rule: {alert.rule_name}")
        print(f"  Severity: {alert.severity}")
        print(f"  Title: {alert.title}")
        print(f"  Source IP: {alert.src_ip}")
        print(f"  Status: {alert.status}")
        print(f"  Description: {alert.description}")

        print("\nDetection test passed")

        # Cleanup test data
        db.query(Event).filter(Event.src_ip == test_ip).delete(
            synchronize_session=False
        )

        db.query(type(alert)).filter(type(alert).id == alert.id).delete(
            synchronize_session=False
        )

        db.commit()

        print("Test records cleaned up successfully")

    except Exception:
        db.rollback()
        raise

    finally:
        db.close()


if __name__ == "__main__":
    main()

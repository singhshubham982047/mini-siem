from datetime import datetime

from sqlalchemy import delete, select

from app.database.connection import SessionLocal
from app.database.models import Alert, Event
from app.detection.suspicious_login import SuspiciousLoginDetector

TEST_IP = "192.168.70.100"


def cleanup(db):
    alert_ids = db.scalars(select(Alert.id).where(Alert.src_ip == TEST_IP)).all()

    if alert_ids:
        db.execute(delete(Alert).where(Alert.id.in_(alert_ids)))

    db.execute(delete(Event).where(Event.src_ip == TEST_IP))

    db.commit()


def main():
    db = SessionLocal()

    try:
        cleanup(db)

        print("Creating failed login events...")

        failed_events = []

        for i in range(3):
            event = Event(
                timestamp=datetime(
                    2026,
                    9,
                    23,
                    11,
                    0,
                    i + 1,
                ),
                source="linux",
                event_type="authentication",
                action="login",
                username="admin",
                src_ip=TEST_IP,
                src_port=53000 + i,
                status="failure",
                severity="medium",
                message="Failed SSH login attempt",
                raw_log=(f"Failed password for admin " f"from {TEST_IP}"),
            )

            db.add(event)
            failed_events.append(event)

        db.commit()

        print("Created 3 failed login events")

        print("\nCreating successful login event...")

        successful_event = Event(
            timestamp=datetime(
                2026,
                9,
                23,
                11,
                0,
                10,
            ),
            source="linux",
            event_type="authentication",
            action="login",
            username="admin",
            src_ip=TEST_IP,
            src_port=53003,
            status="success",
            severity="low",
            message="Successful SSH login",
            raw_log=(f"Accepted password for admin " f"from {TEST_IP}"),
        )

        db.add(successful_event)
        db.commit()
        db.refresh(successful_event)

        print("Successful login event created")

        print("\nRunning suspicious-login detector...")

        alert = SuspiciousLoginDetector.detect(
            db=db,
            event=successful_event,
        )

        if alert is None:
            raise RuntimeError("Suspicious login detector " "did not generate an alert")

        print("\n🚨 ALERT GENERATED")

        print(f"  ID: {alert.id}")
        print(f"  Rule: {alert.rule_name}")
        print(f"  Severity: {alert.severity}")
        print(f"  Title: {alert.title}")
        print(f"  Source IP: {alert.src_ip}")
        print(f"  Username: {alert.username}")

        assert alert.rule_name == "successful_login_after_failures"

        assert alert.severity == "high"

        assert alert.src_ip == TEST_IP

        assert alert.username == "admin"

        print("\n================================")
        print("SUSPICIOUS LOGIN TEST PASSED")
        print("================================")

    finally:
        cleanup(db)
        db.close()

        print("\nTest records cleaned up")


if __name__ == "__main__":
    main()

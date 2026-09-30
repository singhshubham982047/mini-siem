from datetime import datetime

from sqlalchemy import delete, select

from app.database.connection import SessionLocal
from app.database.models import Alert, AlertEvent, Event, Incident
from app.incident.manager import IncidentManager

TEST_IP = "192.168.60.100"


def cleanup(db):
    alert_ids = db.scalars(select(Alert.id).where(Alert.src_ip == TEST_IP)).all()

    if alert_ids:
        db.execute(delete(AlertEvent).where(AlertEvent.alert_id.in_(alert_ids)))

        db.execute(delete(Incident).where(Incident.alert_id.in_(alert_ids)))

        db.execute(delete(Alert).where(Alert.id.in_(alert_ids)))

    db.execute(delete(Event).where(Event.src_ip == TEST_IP))

    db.commit()


def main():
    db = SessionLocal()

    try:
        cleanup(db)

        print("Creating test authentication events...")

        reference_time = datetime(2026, 9, 23, 10, 0, 14)

        events = []

        for index in range(5):

            event = Event(
                timestamp=datetime(
                    2026,
                    9,
                    23,
                    10,
                    0,
                    10 + index,
                ),
                source="linux",
                event_type="authentication",
                action="login",
                username="admin",
                src_ip=TEST_IP,
                src_port=52000 + index,
                status="failure",
                severity="medium",
                message="Failed SSH login attempt",
                raw_log=(
                    f"Sep 23 10:00:{10 + index:02d} "
                    f"Failed password for admin "
                    f"from {TEST_IP} "
                    f"port {52000 + index} ssh2"
                ),
            )

            db.add(event)
            events.append(event)

        db.commit()

        print(f"Events created: {len(events)}")

        print("\nCreating test alert...")

        alert = Alert(
            rule_name="ssh_brute_force",
            severity="high",
            title="SSH Brute Force Attack Detected",
            description=(
                f"Detected 5 failed SSH login attempts "
                f"from {TEST_IP} within 5 minutes."
            ),
            src_ip=TEST_IP,
            username="admin",
            status="open",
        )

        db.add(alert)
        db.commit()
        db.refresh(alert)

        print(f"Alert created: ID={alert.id}")

        print("\nCreating incident...")

        incident = IncidentManager.create_for_alert(
            db=db,
            alert=alert,
            reference_time=reference_time,
        )

        print(f"Incident created: ID={incident.id}")

        print("\nChecking correlated events...")

        links = db.scalars(
            select(AlertEvent).where(AlertEvent.alert_id == alert.id)
        ).all()

        print(f"Correlated events: {len(links)}")

        # --------------------------------------------------
        # Assertions
        # --------------------------------------------------

        assert incident.alert_id == alert.id
        assert incident.title == alert.title
        assert incident.severity == "high"
        assert incident.status == "open"

        assert len(links) == 5

        event_ids = {link.event_id for link in links}

        assert len(event_ids) == 5

        print("\n================================")
        print("INCIDENT MANAGER TEST PASSED")
        print("================================")

        print("\nIncident:")
        print(f"  ID: {incident.id}")
        print(f"  Alert ID: {incident.alert_id}")
        print(f"  Title: {incident.title}")
        print(f"  Severity: {incident.severity}")
        print(f"  Status: {incident.status}")

        print("\nCorrelation:")
        print(f"  Alert ID: {alert.id}")
        print(f"  Events linked: {len(links)}")

    finally:
        cleanup(db)
        db.close()

        print("\nTest records cleaned up")


if __name__ == "__main__":
    main()

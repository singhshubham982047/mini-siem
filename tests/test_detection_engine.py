from datetime import datetime, timedelta, timezone

from sqlalchemy import delete

from app.database.connection import SessionLocal
from app.database.models import Alert, AlertEvent, Event, Incident
from app.detection.engine import DetectionEngine

TEST_IP = "10.20.30.40"


def cleanup_test_data(db):
    """
    Remove all test data associated with TEST_IP.
    """

    alert_ids = [
        alert.id for alert in db.query(Alert).filter(Alert.src_ip == TEST_IP).all()
    ]

    if alert_ids:
        db.execute(delete(AlertEvent).where(AlertEvent.alert_id.in_(alert_ids)))

        db.execute(delete(Incident).where(Incident.alert_id.in_(alert_ids)))

        db.execute(delete(Alert).where(Alert.id.in_(alert_ids)))

    db.execute(delete(Event).where(Event.src_ip == TEST_IP))

    db.commit()


def main():
    db = SessionLocal()

    try:
        # --------------------------------------------------
        # Clean any data left by previous test runs
        # --------------------------------------------------

        cleanup_test_data(db)

        now = datetime.now(timezone.utc)

        print("Creating simulated authentication events...")

        events = []

        # --------------------------------------------------
        # Create 5 failed SSH login events
        # --------------------------------------------------

        for i in range(5):
            event = Event(
                timestamp=now - timedelta(seconds=i * 30),
                source="linux",
                event_type="authentication",
                action="login",
                username="admin",
                src_ip=TEST_IP,
                src_port=51000 + i,
                status="failure",
                severity="medium",
                message="Failed SSH login attempt",
                raw_log=f"Test failed login {i + 1}",
            )

            db.add(event)
            events.append(event)

        db.commit()

        print("Created 5 failed login events")

        # --------------------------------------------------
        # Process the newest event
        # --------------------------------------------------

        latest_event = events[0]

        alerts = DetectionEngine.process_event(
            db=db,
            event=latest_event,
        )

        print(f"\nDetection engine generated " f"{len(alerts)} alert(s)")

        # --------------------------------------------------
        # Verify alert
        # --------------------------------------------------

        if not alerts:
            raise RuntimeError("Detection engine did not generate an alert")

        if len(alerts) != 1:
            raise RuntimeError(f"Expected 1 alert, but found {len(alerts)}")

        alert = alerts[0]

        print("\nAlert:")
        print(f"  ID: {alert.id}")
        print(f"  Rule: {alert.rule_name}")
        print(f"  Severity: {alert.severity}")
        print(f"  Title: {alert.title}")
        print(f"  Source IP: {alert.src_ip}")
        print(f"  Status: {alert.status}")

        # --------------------------------------------------
        # Verify incident
        # --------------------------------------------------

        incident = db.query(Incident).filter(Incident.alert_id == alert.id).first()

        if incident is None:
            raise RuntimeError(
                "Detection engine generated an alert " "but no incident was created"
            )

        print("\nIncident:")
        print(f"  ID: {incident.id}")
        print(f"  Alert ID: {incident.alert_id}")
        print(f"  Title: {incident.title}")
        print(f"  Severity: {incident.severity}")
        print(f"  Status: {incident.status}")

        # --------------------------------------------------
        # Verify event correlation
        # --------------------------------------------------

        correlated_events = (
            db.query(AlertEvent).filter(AlertEvent.alert_id == alert.id).all()
        )

        print("\nCorrelated events: " f"{len(correlated_events)}")

        if len(correlated_events) != 5:
            raise RuntimeError(
                "Expected 5 correlated events, " f"but found {len(correlated_events)}"
            )

        # --------------------------------------------------
        # Verify unique event IDs
        # --------------------------------------------------

        event_ids = {link.event_id for link in correlated_events}

        if len(event_ids) != 5:
            raise RuntimeError(
                "Expected 5 unique correlated event IDs, " f"but found {len(event_ids)}"
            )

        print("\n================================")
        print("DETECTION ENGINE TEST PASSED")
        print("================================")

        print("\nPipeline verified:")
        print("  5 failed login events")
        print("       ↓")
        print("  Detection Engine")
        print("       ↓")
        print("  1 SSH brute-force alert")
        print("       ↓")
        print("  1 incident")
        print("       ↓")
        print("  5 correlated events")

        # --------------------------------------------------
        # Cleanup
        # --------------------------------------------------

        cleanup_test_data(db)

        print("\nTest records cleaned up successfully")

    except Exception:
        db.rollback()

        try:
            cleanup_test_data(db)
        except Exception:
            db.rollback()

        raise

    finally:
        db.close()


if __name__ == "__main__":
    main()

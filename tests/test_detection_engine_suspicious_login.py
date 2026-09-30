from datetime import datetime, timedelta, timezone

from sqlalchemy import delete

from app.database.connection import SessionLocal
from app.database.models import Alert, AlertEvent, Event, Incident
from app.detection.engine import DetectionEngine

TEST_IP = "192.168.80.100"


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
        cleanup_test_data(db)

        base_time = datetime.now(timezone.utc)

        print("Creating 3 failed login events...")

        failed_events = []

        for i in range(3):
            event = Event(
                timestamp=base_time + timedelta(seconds=i * 30),
                source="linux",
                event_type="authentication",
                action="login",
                username="admin",
                src_ip=TEST_IP,
                src_port=54000 + i,
                status="failure",
                severity="medium",
                message="Failed SSH login attempt",
                raw_log=f"Test failed login {i + 1}",
            )

            db.add(event)
            failed_events.append(event)

        db.commit()

        print("Created 3 failed login events")

        # --------------------------------------------------
        # Create successful login
        # --------------------------------------------------

        successful_event = Event(
            timestamp=base_time + timedelta(seconds=120),
            source="linux",
            event_type="authentication",
            action="login",
            username="admin",
            src_ip=TEST_IP,
            src_port=54003,
            status="success",
            severity="low",
            message="Successful SSH login",
            raw_log="Test successful login",
        )

        db.add(successful_event)
        db.commit()
        db.refresh(successful_event)

        print("Created successful login event")

        # --------------------------------------------------
        # Process successful login through DetectionEngine
        # --------------------------------------------------

        print("\nProcessing successful login through Detection Engine...")

        alerts = DetectionEngine.process_event(
            db=db,
            event=successful_event,
        )

        print(f"\nDetection engine generated " f"{len(alerts)} alert(s)")

        if len(alerts) != 1:
            raise RuntimeError(f"Expected 1 alert, but found {len(alerts)}")

        alert = alerts[0]

        print("\nAlert:")
        print(f"  ID: {alert.id}")
        print(f"  Rule: {alert.rule_name}")
        print(f"  Severity: {alert.severity}")
        print(f"  Title: {alert.title}")
        print(f"  Source IP: {alert.src_ip}")
        print(f"  Username: {alert.username}")

        if alert.rule_name != "successful_login_after_failures":
            raise RuntimeError("Unexpected detection rule generated")

        # --------------------------------------------------
        # Verify incident
        # --------------------------------------------------

        incident = db.query(Incident).filter(Incident.alert_id == alert.id).first()

        if incident is None:
            raise RuntimeError("Alert was generated but no incident exists")

        print("\nIncident:")
        print(f"  ID: {incident.id}")
        print(f"  Alert ID: {incident.alert_id}")
        print(f"  Severity: {incident.severity}")
        print(f"  Status: {incident.status}")

        # --------------------------------------------------
        # Verify event correlation
        # --------------------------------------------------

        correlated_events = (
            db.query(AlertEvent).filter(AlertEvent.alert_id == alert.id).all()
        )

        print("\nCorrelated events: " f"{len(correlated_events)}")

        if len(correlated_events) != 3:
            raise RuntimeError(
                "Expected 3 correlated failed-login events, "
                f"but found {len(correlated_events)}"
            )

        # --------------------------------------------------
        # Verify that the successful login itself is not
        # incorrectly correlated as a failed event
        # --------------------------------------------------

        correlated_event_ids = {link.event_id for link in correlated_events}

        if successful_event.id in correlated_event_ids:
            raise RuntimeError(
                "Successful login was incorrectly " "correlated as a failed event"
            )

        print("\n================================")
        print("SUSPICIOUS LOGIN ENGINE TEST PASSED")
        print("================================")

        print("\nPipeline verified:")
        print("  3 failed login events")
        print("       ↓")
        print("  1 successful login")
        print("       ↓")
        print("  Detection Engine")
        print("       ↓")
        print("  Suspicious Login Alert")
        print("       ↓")
        print("  1 incident")
        print("       ↓")
        print("  3 correlated failed events")

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

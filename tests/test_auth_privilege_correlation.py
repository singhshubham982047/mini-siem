from datetime import datetime, timedelta, timezone

from sqlalchemy import select

from app.database.connection import SessionLocal
from app.database.models import Event, Alert, Incident, AlertEvent
from app.detection.engine import DetectionEngine

TEST_USERNAME = "correlation-test-user"
TEST_IP = None


def create_event(
    db,
    timestamp,
    event_type,
    action,
    status,
    message,
    severity="medium",
):
    event = Event(
        timestamp=timestamp,
        source="test-auth-correlation",
        event_type=event_type,
        action=action,
        username=TEST_USERNAME,
        src_ip=TEST_IP,
        dst_ip=None,
        src_port=None,
        dst_port=None,
        status=status,
        severity=severity,
        message=message,
        raw_log=message,
        log_source_id=None,
    )

    db.add(event)
    db.commit()
    db.refresh(event)

    return event


def main():
    print("=" * 70)
    print("TEST: Authentication → Privilege Escalation Correlation")
    print("=" * 70)

    with SessionLocal() as db:

        # ---------------------------------------------------------
        # BASE TIMESTAMP
        # ---------------------------------------------------------

        base_time = datetime.now(timezone.utc).replace(microsecond=0)

        # ---------------------------------------------------------
        # 1. THREE FAILED AUTHENTICATION ATTEMPTS
        # ---------------------------------------------------------

        failed_events = []

        for i in range(3):
            event = create_event(
                db=db,
                timestamp=base_time + timedelta(seconds=i * 30),
                event_type="authentication",
                action="login",
                status="failure",
                severity="medium",
                message=f"Failed authentication attempt #{i + 1}",
            )

            failed_events.append(event)

            print(f"Failed authentication event created: " f"ID={event.id}")

        # ---------------------------------------------------------
        # 2. SUCCESSFUL AUTHENTICATION
        # ---------------------------------------------------------

        successful_auth = create_event(
            db=db,
            timestamp=base_time + timedelta(seconds=90),
            event_type="authentication",
            action="login",
            status="success",
            severity="low",
            message="Successful authentication",
        )

        print(f"Successful authentication event created: " f"ID={successful_auth.id}")

        # ---------------------------------------------------------
        # 3. PRIVILEGE ESCALATION
        # ---------------------------------------------------------

        privilege_event = create_event(
            db=db,
            timestamp=base_time + timedelta(seconds=120),
            event_type="privilege_escalation",
            action="sudo_command",
            status="success",
            severity="medium",
            message="Sudo command executed as root: sudo systemctl status nginx",
        )

        print(f"Privilege escalation event created: " f"ID={privilege_event.id}")

        # ---------------------------------------------------------
        # 4. RUN DETECTION ENGINE
        # ---------------------------------------------------------

        print()
        print("Running detection engine...")

        alerts = DetectionEngine.process_event(db=db, event=privilege_event)

        print()
        print(f"Alerts generated: {len(alerts)}")

        for alert in alerts:
            print()
            print("🚨 ALERT")
            print(f"  Alert ID: {alert.id}")
            print(f"  Rule: {alert.rule_name}")
            print(f"  Severity: {alert.severity}")
            print(f"  Title: {alert.title}")
            print(f"  Username: {alert.username}")
            print(f"  Status: {alert.status}")

        # ---------------------------------------------------------
        # 5. VERIFY CORRELATION ALERT
        # ---------------------------------------------------------

        correlation_alert = db.scalar(
            select(Alert)
            .where(
                Alert.rule_name == "authentication_privilege_correlation",
                Alert.username == TEST_USERNAME,
            )
            .order_by(Alert.id.desc())
        )

        assert (
            correlation_alert is not None
        ), "Authentication → privilege escalation alert was not created"

        assert correlation_alert.severity == "critical"

        print()
        print("✅ Correlation alert verified")

        # ---------------------------------------------------------
        # 6. VERIFY INCIDENT
        # ---------------------------------------------------------

        incident = db.scalar(
            select(Incident)
            .where(Incident.alert_id == correlation_alert.id)
            .order_by(Incident.id.desc())
        )

        assert incident is not None, "Incident was not created for correlation alert"

        print()
        print("🚨 INCIDENT VERIFIED")
        print(f"  Incident ID: {incident.id}")
        print(f"  Alert ID: {correlation_alert.id}")
        print(f"  Severity: {incident.severity}")
        print(f"  Status: {incident.status}")

        # ---------------------------------------------------------
        # 7. VERIFY CORRELATED EVENTS
        # ---------------------------------------------------------

        correlated_events = list(
            db.scalars(
                select(Event)
                .join(AlertEvent, AlertEvent.event_id == Event.id)
                .where(AlertEvent.alert_id == correlation_alert.id)
                .order_by(Event.timestamp.asc())
            ).all()
        )

        print()
        print("Correlated events:")
        print("-" * 70)

        for event in correlated_events:
            print(
                f"  ID={event.id} | "
                f"{event.event_type} | "
                f"{event.action} | "
                f"{event.status} | "
                f"{event.username}"
            )

        print()
        print(f"Total correlated events: {len(correlated_events)}")

        # We expect the complete attack chain.
        assert len(correlated_events) >= 5, (
            "Expected at least 5 correlated events "
            "(3 failures + successful authentication + privilege escalation)"
        )

        print()
        print("=" * 70)
        print("✅ AUTHENTICATION → PRIVILEGE ESCALATION TEST PASSED")
        print("=" * 70)


if __name__ == "__main__":
    main()

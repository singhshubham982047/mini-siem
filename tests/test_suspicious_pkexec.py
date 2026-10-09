from datetime import datetime, timezone

from app.database.connection import SessionLocal
from app.database.models import Event
from app.detection.engine import DetectionEngine


def main():
    with SessionLocal() as db:

        print("=" * 60)
        print("Testing Suspicious Pkexec Detection")
        print("=" * 60)

        event = Event(
            timestamp=datetime.now(timezone.utc),
            source="linux",
            event_type="privilege_escalation",
            action="pkexec_session_open",
            username="pkexec-test-user",
            src_ip=None,
            dst_ip=None,
            src_port=None,
            dst_port=None,
            status="success",
            severity="medium",
            message="Pkexec session opened as root by pkexec-test-user",
            raw_log=(
                "pkexec: pam_unix(polkit-1:session): "
                "session opened for user root(uid=0) "
                "by pkexec-test-user(uid=1000)"
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

        matching_alerts = [
            alert
            for alert in alerts
            if alert.rule_name == "suspicious_pkexec_activity"
        ]

        if len(matching_alerts) == 1:
            print("\n✅ TEST PASSED")
            print("Suspicious pkexec detection is working.")
        else:
            print("\n❌ TEST FAILED")
            print(
                "Expected exactly one suspicious_pkexec_activity "
                "alert."
            )


if __name__ == "__main__":
    main()

from datetime import datetime, timedelta, timezone

from app.database.connection import SessionLocal
from app.database.models import Event
from app.detection.engine import DetectionEngine


def main():
    with SessionLocal() as db:

        print("=" * 60)
        print("Testing Repeated Privilege Escalation Detection")
        print("=" * 60)

        base_time = datetime.now(timezone.utc)

        events = []

        commands = [
            "Sudo command executed as root: sudo ls /root",
            "Sudo command executed as root: sudo cat /etc/passwd",
            "Sudo command executed as root: sudo systemctl status ssh",
        ]

        for index, message in enumerate(commands):
            event = Event(
                timestamp=base_time + timedelta(seconds=index * 30),
                source="linux",
                event_type="privilege_escalation",
                action="sudo_command",
                username="privilege-test-user",
                src_ip=None,
                dst_ip=None,
                src_port=None,
                dst_port=None,
                status="success",
                severity="medium",
                message=message,
                raw_log=message,
            )

            db.add(event)
            db.flush()
            events.append(event)

            print(
                f"Created event ID={event.id} | "
                f"Action={event.action} | "
                f"User={event.username}"
            )

        db.commit()

        print("\nRunning Detection Engine...")

        all_alerts = []

        for event in events:
            alerts = DetectionEngine.process_event(
                db=db,
                event=event,
            )

            all_alerts.extend(alerts)

        print(f"\nAlerts generated: {len(all_alerts)}")

        for alert in all_alerts:
            print("\n🚨 ALERT")
            print(f"Alert ID: {alert.id}")
            print(f"Rule: {alert.rule_name}")
            print(f"Severity: {alert.severity}")
            print(f"Username: {alert.username}")
            print(f"Title: {alert.title}")
            print(f"Status: {alert.status}")

        matching_alerts = [
            alert
            for alert in all_alerts
            if alert.rule_name == "repeated_privilege_escalation"
        ]

        if len(matching_alerts) == 1:
            print("\n✅ TEST PASSED")
            print(
                "Repeated privilege escalation detection "
                "generated exactly one alert."
            )
        elif len(matching_alerts) > 1:
            print("\n❌ TEST FAILED")
            print(
                f"Expected 1 alert, but received "
                f"{len(matching_alerts)}."
            )
        else:
            print("\n❌ TEST FAILED")
            print("No repeated privilege escalation alert generated.")


if __name__ == "__main__":
    main()

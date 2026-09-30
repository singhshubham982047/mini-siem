from datetime import datetime, timedelta

from app.database.connection import SessionLocal
from app.database.models import Event, LogSource
from app.detection.engine import DetectionEngine


def main():
    db = SessionLocal()

    print("Creating test log source...")

    log_source = LogSource(
        name="Multiple Users Engine Test",
        source_type="linux_auth",
        file_path="sample_logs/test-multiple-users-engine.log",
        enabled=True,
    )

    db.add(log_source)
    db.commit()
    db.refresh(log_source)

    print(f"Log source created: ID={log_source.id}")

    reference_time = datetime.now()

    usernames = [
        "admin",
        "root",
        "test",
        "ubuntu",
    ]

    print("\nCreating multiple-user authentication failures...")

    events = []

    for index, username in enumerate(usernames):

        event = Event(
            timestamp=reference_time - timedelta(
                minutes=3,
                seconds=index * 20,
            ),
            source="sshd",
            event_type="authentication",
            action="login",
            username=username,
            src_ip="192.168.90.100",
            dst_ip=None,
            src_port=54000 + index,
            dst_port=22,
            status="failure",
            severity="medium",
            message=f"Failed password for {username}",
            raw_log=(
                f"Sep 23 10:00:{10 + index} ubuntu "
                f"sshd[500]: Failed password for {username} "
                f"from 192.168.90.100 "
                f"port {54000 + index} ssh2"
            ),
            log_source_id=log_source.id,
        )

        db.add(event)
        events.append(event)

    db.commit()

    print(f"Created {len(events)} failed login events")

    print("\nProcessing events through Detection Engine...")

    generated_alerts = []

    for event in events:

        alerts = DetectionEngine.process_event(
            db=db,
            event=event,
        )

        generated_alerts.extend(alerts)

    print(
        f"\nDetection engine generated "
        f"{len(generated_alerts)} alert(s)"
    )

    # ==================================================
    # VERIFY ALERT
    # ==================================================

    if len(generated_alerts) != 1:
        print("\nTEST FAILED")
        print(
            "Expected exactly 1 alert, "
            f"but received {len(generated_alerts)}."
        )

        db.close()
        raise SystemExit(1)

    alert = generated_alerts[0]

    if alert.rule_name != "multiple_users_same_ip":
        print("\nTEST FAILED")
        print(
            f"Unexpected rule: {alert.rule_name}"
        )

        db.close()
        raise SystemExit(1)

    print("\n🚨 ALERT GENERATED")

    print(f"  ID: {alert.id}")
    print(f"  Rule: {alert.rule_name}")
    print(f"  Severity: {alert.severity}")
    print(f"  Title: {alert.title}")
    print(f"  Source IP: {alert.src_ip}")

    # ==================================================
    # VERIFY INCIDENT
    # ==================================================

    db.refresh(alert)

    incidents = list(alert.incidents)

    if len(incidents) != 1:
        print("\nTEST FAILED")
        print(
            f"Expected exactly 1 incident, "
            f"but found {len(incidents)}."
        )

        db.close()
        raise SystemExit(1)

    incident = incidents[0]

    print("\nIncident:")

    print(f"  ID: {incident.id}")
    print(f"  Alert ID: {incident.alert_id}")
    print(f"  Title: {incident.title}")
    print(f"  Severity: {incident.severity}")
    print(f"  Status: {incident.status}")

    # ==================================================
    # VERIFY CORRELATED EVENTS
    # ==================================================

    db.refresh(alert)

    correlated_events = list(alert.alert_events)

    print(
        f"\nCorrelated events: "
        f"{len(correlated_events)}"
    )

    if len(correlated_events) != 4:
        print("\nTEST FAILED")
        print(
            "Expected 4 correlated failed events."
        )

        db.close()
        raise SystemExit(1)

    # ==================================================
    # VERIFY USERNAMES
    # ==================================================

    correlated_usernames = {
        link.event.username
        for link in correlated_events
    }

    expected_usernames = {
        "admin",
        "root",
        "test",
        "ubuntu",
    }

    if correlated_usernames != expected_usernames:
        print("\nTEST FAILED")
        print(
            "Correlated usernames do not match "
            "the expected usernames."
        )

        print(
            f"Expected: {expected_usernames}"
        )

        print(
            f"Found: {correlated_usernames}"
        )

        db.close()
        raise SystemExit(1)

    print(
        "All 4 targeted usernames "
        "successfully correlated"
    )

    # ==================================================
    # CLEANUP
    # ==================================================

    print("\nCleaning up test records...")

    # Delete alert-event links first.
    for link in list(alert.alert_events):
        db.delete(link)

    db.delete(incident)
    db.delete(alert)

    for event in events:
        db.delete(event)

    db.delete(log_source)

    db.commit()
    db.close()

    print("\n================================")
    print("MULTIPLE USERS ENGINE TEST PASSED")
    print("================================")

    print("\nFull pipeline verified:")
    print("  4 failed login events")
    print("       ↓")
    print("  4 different usernames")
    print("       ↓")
    print("  Detection Engine")
    print("       ↓")
    print("  Multiple Users Alert")
    print("       ↓")
    print("  1 incident")
    print("       ↓")
    print("  4 correlated events")


if __name__ == "__main__":
    main()


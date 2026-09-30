from datetime import datetime, timedelta

from app.database.connection import SessionLocal
from app.database.models import Event, LogSource
from app.detection.multiple_users import MultipleUsersDetector


def main():
    db = SessionLocal()

    print("Creating test log source...")

    log_source = LogSource(
        name="Multiple Users Test",
        source_type="linux_auth",
        file_path="sample_logs/test-multiple-users.log",
        enabled=True,
    )

    db.add(log_source)
    db.commit()
    db.refresh(log_source)

    print(f"Log source created: ID={log_source.id}")

    print("\nCreating authentication failure events...")

    reference_time = datetime.now()

    usernames = [
        "admin",
        "root",
        "test",
        "ubuntu",
    ]

    events = []

    for index, username in enumerate(usernames):

        event = Event(
            timestamp=reference_time - timedelta(minutes=3, seconds=index * 20),
            source="sshd",
            event_type="authentication",
            action="login",
            username=username,
            src_ip="192.168.70.100",
            dst_ip=None,
            src_port=52000 + index,
            dst_port=22,
            status="failure",
            severity="medium",
            message=f"Failed password for {username}",
            raw_log=(
                f"Sep 23 10:00:{10 + index} ubuntu "
                f"sshd[400]: Failed password for {username} "
                f"from 192.168.70.100 port {52000 + index} ssh2"
            ),
            log_source_id=log_source.id,
        )

        db.add(event)
        events.append(event)

    db.commit()

    print(f"Created {len(events)} failed login events")

    print("\nTesting Multiple Users Detector...")

    alert = MultipleUsersDetector.detect(
        db=db,
        src_ip="192.168.70.100",
        reference_time=reference_time,
    )

    if alert is None:
        print("\nTEST FAILED")
        print("Expected a multiple-users alert but none was generated.")

        db.query(Event).filter(Event.log_source_id == log_source.id).delete()

        db.delete(log_source)
        db.commit()
        db.close()

        raise SystemExit(1)

    print("\n🚨 ALERT GENERATED")

    print(f"  ID: {alert.id}")
    print(f"  Rule: {alert.rule_name}")
    print(f"  Severity: {alert.severity}")
    print(f"  Title: {alert.title}")
    print(f"  Source IP: {alert.src_ip}")
    print(f"  Description: {alert.description}")

    print("\nTesting duplicate alert protection...")

    second_alert = MultipleUsersDetector.detect(
        db=db,
        src_ip="192.168.70.100",
        reference_time=reference_time,
    )

    if second_alert is not None:
        print("\nTEST FAILED")
        print("Duplicate alert was generated.")

        db.close()
        raise SystemExit(1)

    print("Duplicate alert protection passed")

    print("\nTesting below-threshold scenario...")

    below_threshold_ip = "192.168.70.200"

    for index, username in enumerate(["admin", "root"]):

        event = Event(
            timestamp=reference_time - timedelta(minutes=1, seconds=index),
            source="sshd",
            event_type="authentication",
            action="login",
            username=username,
            src_ip=below_threshold_ip,
            dst_ip=None,
            src_port=53000 + index,
            dst_port=22,
            status="failure",
            severity="medium",
            message=f"Failed password for {username}",
            raw_log=f"Failed password for {username}",
            log_source_id=log_source.id,
        )

        db.add(event)

    db.commit()

    below_threshold_alert = MultipleUsersDetector.detect(
        db=db,
        src_ip=below_threshold_ip,
        reference_time=reference_time,
    )

    if below_threshold_alert is not None:
        print("\nTEST FAILED")
        print("Alert generated below the username threshold.")

        db.close()
        raise SystemExit(1)

    print("Below-threshold detection passed")

    print("\nCleaning up test records...")

    db.query(Event).filter(Event.log_source_id == log_source.id).delete()

    db.delete(alert)

    db.delete(log_source)

    db.commit()
    db.close()

    print("\n================================")
    print("MULTIPLE USERS DETECTOR TEST PASSED")
    print("================================")

    print("\nDetection verified:")
    print("  4 failed login events")
    print("       ↓")
    print("  4 different usernames")
    print("       ↓")
    print("  Multiple Users Detector")
    print("       ↓")
    print("  1 alert")
    print("       ↓")
    print("  Duplicate protection verified")
    print("       ↓")
    print("  Below-threshold protection verified")


if __name__ == "__main__":
    main()

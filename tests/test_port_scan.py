from datetime import datetime, timedelta

from app.database.connection import SessionLocal
from app.database.models import Event, LogSource
from app.detection.port_scan import PortScanDetector


def main():
    db = SessionLocal()

    print("Creating test log source...")

    log_source = LogSource(
        name="Port Scan Test",
        source_type="network",
        file_path="sample_logs/test-port-scan.log",
        enabled=True,
    )

    db.add(log_source)
    db.commit()
    db.refresh(log_source)

    print(f"Log source created: ID={log_source.id}")

    reference_time = datetime.now()

    # ==================================================
    # CREATE PORT SCAN EVENTS
    # ==================================================

    destination_ports = [
        21,
        22,
        23,
        25,
        80,
        443,
    ]

    print("\nCreating network events...")

    events = []

    for index, destination_port in enumerate(destination_ports):

        event = Event(
            timestamp=reference_time
            - timedelta(
                minutes=3,
                seconds=index * 20,
            ),
            source="network",
            event_type="network_connection",
            action="connection_attempt",
            username=None,
            src_ip="10.50.60.100",
            dst_ip="192.168.1.10",
            src_port=55000 + index,
            dst_port=destination_port,
            status="failure",
            severity="low",
            message=(f"Connection attempt to " f"192.168.1.10:{destination_port}"),
            raw_log=(f"10.50.60.100 -> " f"192.168.1.10:{destination_port}"),
            log_source_id=log_source.id,
        )

        db.add(event)
        events.append(event)

    db.commit()

    print(
        f"Created {len(events)} network events "
        f"across {len(destination_ports)} ports"
    )

    # ==================================================
    # RUN DETECTOR
    # ==================================================

    print("\nTesting Port Scan Detector...")

    alert = PortScanDetector.detect(
        db=db,
        src_ip="10.50.60.100",
        reference_time=reference_time,
    )

    if alert is None:
        print("\nTEST FAILED")
        print("Expected a port scan alert, " "but no alert was generated.")

        db.close()
        raise SystemExit(1)

    print("\n🚨 ALERT GENERATED")

    print(f"  ID: {alert.id}")
    print(f"  Rule: {alert.rule_name}")
    print(f"  Severity: {alert.severity}")
    print(f"  Title: {alert.title}")
    print(f"  Source IP: {alert.src_ip}")
    print(f"  Description: {alert.description}")

    # ==================================================
    # TEST DUPLICATE ALERT PROTECTION
    # ==================================================

    print("\nTesting duplicate alert protection...")

    second_alert = PortScanDetector.detect(
        db=db,
        src_ip="10.50.60.100",
        reference_time=reference_time,
    )

    if second_alert is not None:
        print("\nTEST FAILED")
        print("Duplicate port scan alert was generated.")

        db.close()
        raise SystemExit(1)

    print("Duplicate alert protection passed")

    # ==================================================
    # TEST BELOW-THRESHOLD CASE
    # ==================================================

    print("\nTesting below-threshold scenario...")

    normal_ip = "10.50.60.200"

    normal_ports = [
        22,
        80,
        443,
    ]

    normal_events = []

    for index, destination_port in enumerate(normal_ports):

        event = Event(
            timestamp=reference_time
            - timedelta(
                minutes=1,
                seconds=index,
            ),
            source="network",
            event_type="network_connection",
            action="connection_attempt",
            username=None,
            src_ip=normal_ip,
            dst_ip="192.168.1.20",
            src_port=56000 + index,
            dst_port=destination_port,
            status="failure",
            severity="low",
            message=(f"Connection attempt to " f"192.168.1.20:{destination_port}"),
            raw_log=(f"{normal_ip} -> " f"192.168.1.20:{destination_port}"),
            log_source_id=log_source.id,
        )

        db.add(event)
        normal_events.append(event)

    db.commit()

    below_threshold_alert = PortScanDetector.detect(
        db=db,
        src_ip=normal_ip,
        reference_time=reference_time,
    )

    if below_threshold_alert is not None:
        print("\nTEST FAILED")
        print("Port scan alert generated below " "the configured threshold.")

        db.close()
        raise SystemExit(1)

    print("Below-threshold detection passed")

    # ==================================================
    # CLEANUP
    # ==================================================

    print("\nCleaning up test records...")

    db.delete(alert)

    for event in events:
        db.delete(event)

    for event in normal_events:
        db.delete(event)

    db.delete(log_source)

    db.commit()
    db.close()

    print("\n================================")
    print("PORT SCAN DETECTOR TEST PASSED")
    print("================================")

    print("\nDetection verified:")
    print("  6 network connection events")
    print("       ↓")
    print("  6 different destination ports")
    print("       ↓")
    print("  Port Scan Detector")
    print("       ↓")
    print("  1 port scan alert")
    print("       ↓")
    print("  Duplicate protection verified")
    print("       ↓")
    print("  Below-threshold protection verified")


if __name__ == "__main__":
    main()

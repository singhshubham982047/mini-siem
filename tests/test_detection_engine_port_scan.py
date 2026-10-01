from datetime import datetime, timedelta, timezone

from sqlalchemy import select

from app.database.connection import SessionLocal
from app.database.models import (
    Alert,
    AlertEvent,
    Event,
    Incident,
    LogSource,
)
from app.detection.engine import DetectionEngine

TEST_SOURCE_NAME = "Port Scan Engine Test"
TEST_SOURCE_IP = "10.60.70.100"


def cleanup_previous_test_data(db):
    """Clean up records created by this port-scan test."""

    sources = db.scalars(
        select(LogSource).where(LogSource.name == TEST_SOURCE_NAME)
    ).all()

    source_ids = [source.id for source in sources]

    alerts = db.scalars(
        select(Alert).where(
            Alert.rule_name == "port_scan",
            Alert.src_ip == TEST_SOURCE_IP,
        )
    ).all()

    alert_ids = [alert.id for alert in alerts]

    # Delete incidents first, then alert-event links.
    if alert_ids:
        db.query(Incident).filter(Incident.alert_id.in_(alert_ids)).delete(
            synchronize_session=False
        )

        db.flush()

        db.query(AlertEvent).filter(AlertEvent.alert_id.in_(alert_ids)).delete(
            synchronize_session=False
        )

        db.flush()

        # Expunge loaded alert objects so ORM cascades don't
        # try to delete the already-removed relationship rows.
        for alert in alerts:
            db.expunge(alert)

        db.query(Alert).filter(Alert.id.in_(alert_ids)).delete(
            synchronize_session=False
        )

        db.flush()

    # Delete only events owned by this test's log sources.
    if source_ids:
        db.query(Event).filter(Event.log_source_id.in_(source_ids)).delete(
            synchronize_session=False
        )

        db.flush()

        db.query(LogSource).filter(LogSource.id.in_(source_ids)).delete(
            synchronize_session=False
        )

    db.commit()


def main():
    db = SessionLocal()

    try:
        # Clean leftovers from previous test runs.
        cleanup_previous_test_data(db)

        print("Creating test log source...")

        log_source = LogSource(
            name=TEST_SOURCE_NAME,
            source_type="network",
            file_path="sample_logs/test-port-scan-engine.log",
            enabled=True,
        )

        db.add(log_source)
        db.commit()
        db.refresh(log_source)

        print(f"Log source created: ID={log_source.id}")

        reference_time = datetime.now(timezone.utc)

        destination_ports = [21, 22, 23, 25, 80, 443]

        print("\nCreating network connection events...")

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
                src_ip=TEST_SOURCE_IP,
                dst_ip="192.168.1.10",
                src_port=57000 + index,
                dst_port=destination_port,
                status="failure",
                severity="low",
                message=(f"Connection attempt to " f"192.168.1.10:{destination_port}"),
                raw_log=(f"{TEST_SOURCE_IP} -> " f"192.168.1.10:{destination_port}"),
                log_source_id=log_source.id,
            )

            db.add(event)
            events.append(event)

        db.commit()

        for event in events:
            db.refresh(event)

        print(
            f"Created {len(events)} network events "
            f"across {len(destination_ports)} ports"
        )

        # Process events through the detection engine.
        print("\nProcessing events through Detection Engine...")

        generated_alerts = []

        for event in events:
            alerts = DetectionEngine.process_event(
                db=db,
                event=event,
            )
            generated_alerts.extend(alerts)

        print(f"\nDetection engine generated " f"{len(generated_alerts)} alert(s)")

        # Verify exactly one alert was generated.
        if len(generated_alerts) != 1:
            raise AssertionError(
                f"Expected exactly 1 port scan alert, "
                f"but received {len(generated_alerts)}."
            )

        alert = generated_alerts[0]

        if alert.rule_name != "port_scan":
            raise AssertionError(f"Unexpected detection rule: {alert.rule_name}")

        print("\nALERT GENERATED")
        print(f"  ID: {alert.id}")
        print(f"  Rule: {alert.rule_name}")
        print(f"  Severity: {alert.severity}")
        print(f"  Title: {alert.title}")
        print(f"  Source IP: {alert.src_ip}")
        print(f"  Status: {alert.status}")

        # Verify exactly one incident exists.
        db.refresh(alert)
        incidents = list(alert.incidents)

        if len(incidents) != 1:
            raise AssertionError(f"Expected 1 incident, found {len(incidents)}.")

        incident = incidents[0]

        print("\nIncident:")
        print(f"  ID: {incident.id}")
        print(f"  Alert ID: {incident.alert_id}")
        print(f"  Title: {incident.title}")
        print(f"  Severity: {incident.severity}")
        print(f"  Status: {incident.status}")

        # Verify that all six events are correlated.
        db.refresh(alert)
        correlated_links = list(alert.alert_events)

        actual_event_ids = {link.event_id for link in correlated_links}
        expected_event_ids = {event.id for event in events}

        print(f"\nCorrelated events: {len(correlated_links)}")

        if actual_event_ids != expected_event_ids:
            raise AssertionError(
                f"Expected {len(expected_event_ids)} correlated "
                f"events, found {len(actual_event_ids)}. "
                f"Expected IDs: {sorted(expected_event_ids)}; "
                f"actual IDs: {sorted(actual_event_ids)}."
            )

        print("All six network events were correlated successfully.")

        print("\n================================")
        print("PORT SCAN ENGINE TEST PASSED")
        print("================================")

        print("\nPipeline verified:")
        print("  6 network connection events")
        print("       ↓")
        print("  6 different destination ports")
        print("       ↓")
        print("  Detection Engine")
        print("       ↓")
        print("  Port Scan Alert")
        print("       ↓")
        print("  1 incident")
        print("       ↓")
        print("  6 correlated network events")

    finally:
        # Attempt cleanup even if a test assertion fails.
        try:
            cleanup_previous_test_data(db)
            print("\nTest data cleanup completed.")
        finally:
            db.close()


if __name__ == "__main__":
    main()

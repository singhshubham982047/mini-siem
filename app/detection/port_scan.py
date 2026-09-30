from datetime import timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.database.models import Alert, Event


class PortScanDetector:
    """
    Detect a source IP contacting many different
    destination ports within a short time window.
    """

    THRESHOLD = 5
    WINDOW_MINUTES = 5

    @classmethod
    def detect(
        cls,
        db: Session,
        src_ip: str,
        reference_time=None,
    ) -> Alert | None:
        """
        Detect possible port scanning activity.

        Args:
            db: SQLAlchemy database session.
            src_ip: Source IP address being investigated.
            reference_time: End of the detection window.

        Returns:
            A newly created Alert, or None if no detection occurs.
        """

        if not src_ip:
            return None

        # Use the latest network event when no reference
        # timestamp was explicitly provided.
        if reference_time is None:
            latest_event = db.scalars(
                select(Event)
                .where(
                    Event.src_ip == src_ip,
                    Event.dst_port.is_not(None),
                )
                .order_by(Event.timestamp.desc())
                .limit(1)
            ).first()

            if latest_event is None:
                return None

            reference_time = latest_event.timestamp

        window_start = reference_time - timedelta(minutes=cls.WINDOW_MINUTES)

        # Retrieve network events from the same source IP
        # within the detection window.
        statement = (
            select(Event)
            .where(
                Event.src_ip == src_ip,
                Event.dst_port.is_not(None),
                Event.timestamp >= window_start,
                Event.timestamp <= reference_time,
            )
            .order_by(Event.timestamp.asc())
        )

        network_events = db.scalars(statement).all()

        if not network_events:
            return None

        # Count distinct destination ports.
        destination_ports = {
            event.dst_port for event in network_events if event.dst_port is not None
        }

        if len(destination_ports) < cls.THRESHOLD:
            return None

        # Prevent duplicate open alerts for the same
        # source IP and detection rule.
        existing_alert = db.scalars(
            select(Alert)
            .where(
                Alert.rule_name == "port_scan",
                Alert.src_ip == src_ip,
                Alert.status == "open",
            )
            .limit(1)
        ).first()

        if existing_alert:
            return None

        sorted_ports = sorted(destination_ports)

        port_list = ", ".join(str(port) for port in sorted_ports)

        alert = Alert(
            rule_name="port_scan",
            severity="medium",
            title="Potential Port Scan Detected",
            description=(
                f"Detected connections from {src_ip} "
                f"to {len(destination_ports)} different "
                f"destination ports within "
                f"{cls.WINDOW_MINUTES} minutes. "
                f"Destination ports: {port_list}."
            ),
            src_ip=src_ip,
            username=None,
            status="open",
        )

        db.add(alert)
        db.commit()
        db.refresh(alert)

        return alert

from datetime import timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.database.models import Alert, Event


class BruteForceDetector:
    """
    Detect repeated failed SSH login attempts
    from the same source IP.
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
        Detect SSH brute force activity.

        Creates only one open alert for the same source IP
        while the existing alert remains open.
        """

        if reference_time is None:
            latest_event = db.scalars(
                select(Event)
                .where(
                    Event.src_ip == src_ip,
                    Event.event_type == "authentication",
                    Event.status == "failure",
                )
                .order_by(Event.timestamp.desc())
                .limit(1)
            ).first()

            if latest_event is None:
                return None

            reference_time = latest_event.timestamp

        window_start = reference_time - timedelta(minutes=cls.WINDOW_MINUTES)

        statement = (
            select(Event)
            .where(
                Event.src_ip == src_ip,
                Event.event_type == "authentication",
                Event.status == "failure",
                Event.timestamp >= window_start,
                Event.timestamp <= reference_time,
            )
            .order_by(Event.timestamp.desc())
        )

        failed_events = db.scalars(statement).all()

        if len(failed_events) < cls.THRESHOLD:
            return None

        # Check whether an open alert already exists
        existing_alert = db.scalars(
            select(Alert)
            .where(
                Alert.rule_name == "ssh_brute_force",
                Alert.src_ip == src_ip,
                Alert.status == "open",
            )
            .limit(1)
        ).first()

        if existing_alert:
            return None

        alert = Alert(
            rule_name="ssh_brute_force",
            severity="high",
            title="SSH Brute Force Attack Detected",
            description=(
                f"Detected {len(failed_events)} failed SSH login "
                f"attempts from {src_ip} within "
                f"{cls.WINDOW_MINUTES} minutes."
            ),
            src_ip=src_ip,
            username=failed_events[0].username,
            status="open",
        )

        db.add(alert)
        db.commit()
        db.refresh(alert)

        return alert

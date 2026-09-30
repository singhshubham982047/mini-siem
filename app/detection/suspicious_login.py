from datetime import timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.database.models import Alert, Event


class SuspiciousLoginDetector:
    """
    Detect a successful SSH login that occurs shortly after
    multiple failed login attempts from the same source IP.
    """

    THRESHOLD = 3
    WINDOW_MINUTES = 5

    @classmethod
    def detect(
        cls,
        db: Session,
        event: Event,
    ) -> Alert | None:
        """
        Detect a successful login following multiple
        failed authentication attempts.

        Returns:
            A newly created Alert, or None if no detection occurs.
        """

        # --------------------------------------------------
        # Only successful authentication events are relevant
        # --------------------------------------------------

        if (
            event.event_type != "authentication"
            or event.status != "success"
            or not event.src_ip
        ):
            return None

        window_start = event.timestamp - timedelta(minutes=cls.WINDOW_MINUTES)

        # --------------------------------------------------
        # Find failed logins from the same source IP
        # before the successful login
        # --------------------------------------------------

        statement = (
            select(Event)
            .where(
                Event.src_ip == event.src_ip,
                Event.event_type == "authentication",
                Event.status == "failure",
                Event.timestamp >= window_start,
                Event.timestamp < event.timestamp,
            )
            .order_by(Event.timestamp.desc())
        )

        failed_events = db.scalars(statement).all()

        if len(failed_events) < cls.THRESHOLD:
            return None

        # --------------------------------------------------
        # Prevent duplicate open alerts for the same login
        # --------------------------------------------------

        existing_alert = db.scalars(
            select(Alert)
            .where(
                Alert.rule_name == "successful_login_after_failures",
                Alert.src_ip == event.src_ip,
                Alert.status == "open",
            )
            .limit(1)
        ).first()

        if existing_alert:
            return None

        # --------------------------------------------------
        # Create alert
        # --------------------------------------------------

        alert = Alert(
            rule_name="successful_login_after_failures",
            severity="high",
            title="Successful Login After Multiple Failures",
            description=(
                f"Detected a successful SSH login for "
                f"user '{event.username}' from {event.src_ip} "
                f"after {len(failed_events)} failed login "
                f"attempts within {cls.WINDOW_MINUTES} minutes."
            ),
            src_ip=event.src_ip,
            username=event.username,
            status="open",
        )

        db.add(alert)
        db.commit()
        db.refresh(alert)

        return alert

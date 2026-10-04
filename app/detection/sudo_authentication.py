from datetime import datetime, timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.database.models import Event, Alert


class SudoAuthenticationDetector:

    RULE_NAME = "sudo_authentication_failure"

    @staticmethod
    def detect(
        db: Session,
        event: Event,
        threshold: int = 3,
        window_minutes: int = 5,
    ):
        """
        Detect repeated failed sudo authentication attempts
        from the same user within the configured time window.
        """

        if event.event_type != "authentication":
            return None

        if event.action != "sudo_authentication":
            return None

        if event.status != "failure":
            return None

        if not event.username:
            return None

        window_start = event.timestamp - timedelta(
            minutes=window_minutes
        )

        statement = (
            select(Event)
            .where(
                Event.event_type == "authentication",
                Event.action == "sudo_authentication",
                Event.status == "failure",
                Event.username == event.username,
                Event.timestamp >= window_start,
                Event.timestamp <= event.timestamp,
            )
            .order_by(Event.timestamp.asc())
        )

        matching_events = list(db.scalars(statement).all())

        if len(matching_events) < threshold:
            return None

        existing_alert = db.scalar(
            select(Alert)
            .where(
                Alert.rule_name == SudoAuthenticationDetector.RULE_NAME,
                Alert.username == event.username,
                Alert.status == "open",
            )
        )

        if existing_alert:
            return existing_alert

        alert = Alert(
            rule_name=SudoAuthenticationDetector.RULE_NAME,
            severity="high",
            title="Repeated Sudo Authentication Failures Detected",
            description=(
                f"{len(matching_events)} failed sudo authentication "
                f"attempts detected for user {event.username} "
                f"within {window_minutes} minutes."
            ),
            src_ip=None,
            username=event.username,
            status="open",
        )

        db.add(alert)
        db.commit()
        db.refresh(alert)

        return alert

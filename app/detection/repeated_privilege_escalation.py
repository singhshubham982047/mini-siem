from datetime import timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.database.models import Event, Alert


class RepeatedPrivilegeEscalationDetector:
    RULE_NAME = "repeated_privilege_escalation"

    @staticmethod
    def detect(
        db: Session,
        event: Event,
        threshold: int = 3,
        window_minutes: int = 5,
    ):
        if event.event_type != "privilege_escalation":
            return None

        if event.status != "success":
            return None

        if not event.username:
            return None

        window_start = event.timestamp - timedelta(minutes=window_minutes)

        statement = (
            select(Event)
            .where(
                Event.event_type == "privilege_escalation",
                Event.status == "success",
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
                Alert.rule_name == RepeatedPrivilegeEscalationDetector.RULE_NAME,
                Alert.username == event.username,
                Alert.status == "open",
            )
        )

        if existing_alert:
            return existing_alert

        alert = Alert(
            rule_name=RepeatedPrivilegeEscalationDetector.RULE_NAME,
            severity="high",
            title="Repeated Privilege Escalation Detected",
            description=(
                f"{len(matching_events)} successful privilege-escalation "
                f"events detected for user {event.username} "
                f"within {window_minutes} minutes."
            ),
            src_ip=event.src_ip,
            username=event.username,
            status="open",
        )

        db.add(alert)
        db.commit()
        db.refresh(alert)

        return alert

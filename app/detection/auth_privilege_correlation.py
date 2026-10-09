from datetime import timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.database.models import Event, Alert


class AuthPrivilegeCorrelationDetector:
    RULE_NAME = "authentication_privilege_correlation"

    @staticmethod
    def detect(
        db: Session,
        event: Event,
        failure_threshold: int = 3,
        window_minutes: int = 5,
    ):
        # This rule is triggered by privilege escalation events.
        if event.event_type != "privilege_escalation":
            return None

        if event.status != "success":
            return None

        if not event.username:
            return None

        window_start = event.timestamp - timedelta(
            minutes=window_minutes
        )

        # --------------------------------------------------
        # Find successful authentication before escalation
        # --------------------------------------------------

        successful_auth = db.scalar(
            select(Event)
            .where(
                Event.username == event.username,
                Event.event_type == "authentication",
                Event.status == "success",
                Event.timestamp >= window_start,
                Event.timestamp <= event.timestamp,
            )
            .order_by(Event.timestamp.desc())
        )

        if successful_auth is None:
            return None

        # --------------------------------------------------
        # Find failed authentication attempts before success
        # --------------------------------------------------

        failure_statement = (
            select(Event)
            .where(
                Event.username == event.username,
                Event.event_type == "authentication",
                Event.status == "failure",
                Event.timestamp >= window_start,
                Event.timestamp <= successful_auth.timestamp,
            )
            .order_by(Event.timestamp.asc())
        )

        failed_events = list(
            db.scalars(failure_statement).all()
        )

        if len(failed_events) < failure_threshold:
            return None

        # --------------------------------------------------
        # Prevent duplicate open alerts
        # --------------------------------------------------

        existing_alert = db.scalar(
            select(Alert)
            .where(
                Alert.rule_name == AuthPrivilegeCorrelationDetector.RULE_NAME,
                Alert.username == event.username,
                Alert.status == "open",
            )
        )

        if existing_alert:
            return existing_alert

        # --------------------------------------------------
        # Create correlated alert
        # --------------------------------------------------

        alert = Alert(
            rule_name=AuthPrivilegeCorrelationDetector.RULE_NAME,
            severity="critical",
            title="Authentication to Privilege Escalation Attack Chain",
            description=(
                f"User {event.username} generated "
                f"{len(failed_events)} failed authentication attempts, "
                f"followed by a successful authentication and "
                f"privilege escalation within "
                f"{window_minutes} minutes."
            ),
            src_ip=successful_auth.src_ip,
            username=event.username,
            status="open",
        )

        db.add(alert)
        db.commit()
        db.refresh(alert)

        return alert

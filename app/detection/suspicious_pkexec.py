from sqlalchemy import select
from sqlalchemy.orm import Session

from app.database.models import Event, Alert


class SuspiciousPkexecDetector:
    RULE_NAME = "suspicious_pkexec_activity"

    @staticmethod
    def detect(db: Session, event: Event):

        if event.event_type != "privilege_escalation":
            return None

        if event.action != "pkexec_session_open":
            return None

        if event.status != "success":
            return None

        if not event.username:
            return None

        existing_alert = db.scalar(
            select(Alert)
            .where(
                Alert.rule_name == SuspiciousPkexecDetector.RULE_NAME,
                Alert.username == event.username,
                Alert.status == "open",
            )
        )

        if existing_alert:
            return existing_alert

        alert = Alert(
            rule_name=SuspiciousPkexecDetector.RULE_NAME,
            severity="high",
            title="Suspicious Pkexec Privilege Escalation Detected",
            description=(
                f"Pkexec privilege escalation detected for user "
                f"{event.username}: {event.message}"
            ),
            src_ip=event.src_ip,
            username=event.username,
            status="open",
        )

        db.add(alert)
        db.commit()
        db.refresh(alert)

        return alert

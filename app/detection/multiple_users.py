from datetime import timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.database.models import Alert, Event


class MultipleUsersDetector:
    """
    Detect multiple different usernames being targeted
    from the same source IP within a short time window.

    This can indicate password spraying, account enumeration,
    or other suspicious authentication activity.
    """

    THRESHOLD = 3
    WINDOW_MINUTES = 5

    @classmethod
    def detect(
        cls,
        db: Session,
        src_ip: str,
        reference_time=None,
    ) -> Alert | None:
        """
        Detect authentication failures against multiple
        usernames from the same source IP.

        Args:
            db: SQLAlchemy database session.
            src_ip: Source IP address to investigate.
            reference_time: Timestamp used as the end of
                the detection window.

        Returns:
            A newly created Alert, or None if no detection occurs.
        """

        if not src_ip:
            return None

        # If no reference time was provided, use the latest
        # failed authentication event from this source IP.
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

        # Get failed authentication events from this source
        # IP within the detection window.
        statement = (
            select(Event)
            .where(
                Event.src_ip == src_ip,
                Event.event_type == "authentication",
                Event.status == "failure",
                Event.timestamp >= window_start,
                Event.timestamp <= reference_time,
            )
            .order_by(Event.timestamp.asc())
        )

        failed_events = db.scalars(statement).all()

        if not failed_events:
            return None

        # Extract distinct usernames.
        usernames = {event.username for event in failed_events if event.username}

        # Require multiple distinct usernames.
        if len(usernames) < cls.THRESHOLD:
            return None

        # Prevent duplicate open alerts for the same source IP.
        existing_alert = db.scalars(
            select(Alert)
            .where(
                Alert.rule_name == "multiple_users_same_ip",
                Alert.src_ip == src_ip,
                Alert.status == "open",
            )
            .limit(1)
        ).first()

        if existing_alert:
            return None

        username_list = ", ".join(sorted(usernames))

        alert = Alert(
            rule_name="multiple_users_same_ip",
            severity="high",
            title="Multiple Users Targeted From Same IP",
            description=(
                f"Detected authentication failures against "
                f"{len(usernames)} different usernames from "
                f"{src_ip} within {cls.WINDOW_MINUTES} minutes. "
                f"Targeted usernames: {username_list}."
            ),
            src_ip=src_ip,
            username=None,
            status="open",
        )

        db.add(alert)
        db.commit()
        db.refresh(alert)

        return alert

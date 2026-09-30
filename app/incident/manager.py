from datetime import timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.database.models import Alert, AlertEvent, Event, Incident


class IncidentManager:
    """
    Creates incidents from security alerts and
    correlates related events with those alerts.
    """

    DEFAULT_WINDOW_MINUTES = 5

    @classmethod
    def create_for_alert(
        cls,
        db: Session,
        alert: Alert,
        reference_time=None,
        window_minutes: int = DEFAULT_WINDOW_MINUTES,
    ) -> Incident:
        """
        Create an incident for an alert and correlate
        related events with that alert.

        Only one incident is created for each alert.
        """

        # --------------------------------------------------
        # 1. Check whether an incident already exists
        # --------------------------------------------------

        existing_incident = db.scalars(
            select(Incident).where(Incident.alert_id == alert.id).limit(1)
        ).first()

        if existing_incident:
            return existing_incident

        # --------------------------------------------------
        # 2. Determine the reference time
        # --------------------------------------------------

        if reference_time is None and alert.src_ip:

            # Authentication alerts use failed authentication
            # events to determine the reference timestamp.
            if alert.rule_name in {
                "ssh_brute_force",
                "successful_login_after_failures",
                "multiple_users_same_ip",
            }:
                latest_event = db.scalars(
                    select(Event)
                    .where(
                        Event.src_ip == alert.src_ip,
                        Event.event_type == "authentication",
                        Event.status == "failure",
                    )
                    .order_by(Event.timestamp.desc())
                    .limit(1)
                ).first()

            # Port scan alerts use network connection events.
            elif alert.rule_name == "port_scan":
                latest_event = db.scalars(
                    select(Event)
                    .where(
                        Event.src_ip == alert.src_ip,
                        Event.event_type == "network_connection",
                        Event.dst_port.is_not(None),
                    )
                    .order_by(Event.timestamp.desc())
                    .limit(1)
                ).first()

            else:
                latest_event = None

            if latest_event:
                reference_time = latest_event.timestamp

        # --------------------------------------------------
        # 3. Create the incident
        # --------------------------------------------------

        incident = Incident(
            alert_id=alert.id,
            title=alert.title,
            description=alert.description,
            severity=alert.severity,
            status="open",
        )

        db.add(incident)
        db.flush()

        # --------------------------------------------------
        # 4. Find events related to the alert
        # --------------------------------------------------

        related_events = []

        if reference_time is not None and alert.src_ip:

            window_start = reference_time - timedelta(minutes=window_minutes)

            # ----------------------------------------------
            # Authentication alerts
            # ----------------------------------------------

            if alert.rule_name in {
                "ssh_brute_force",
                "successful_login_after_failures",
                "multiple_users_same_ip",
            }:

                statement = (
                    select(Event)
                    .where(
                        Event.src_ip == alert.src_ip,
                        Event.event_type == "authentication",
                        Event.status == "failure",
                        Event.timestamp >= window_start,
                        Event.timestamp <= reference_time,
                    )
                    .order_by(Event.timestamp.asc())
                )

                related_events = db.scalars(statement).all()

            # ----------------------------------------------
            # Port scan alerts
            # ----------------------------------------------

            elif alert.rule_name == "port_scan":

                statement = (
                    select(Event)
                    .where(
                        Event.src_ip == alert.src_ip,
                        Event.event_type == "network_connection",
                        Event.dst_port.is_not(None),
                        Event.timestamp >= window_start,
                        Event.timestamp <= reference_time,
                    )
                    .order_by(Event.timestamp.asc())
                )

                related_events = db.scalars(statement).all()

        # --------------------------------------------------
        # 5. Link events to the alert
        # --------------------------------------------------

        for event in related_events:

            existing_link = db.scalars(
                select(AlertEvent)
                .where(
                    AlertEvent.alert_id == alert.id,
                    AlertEvent.event_id == event.id,
                )
                .limit(1)
            ).first()

            if existing_link:
                continue

            alert_event = AlertEvent(
                alert_id=alert.id,
                event_id=event.id,
            )

            db.add(alert_event)

        # --------------------------------------------------
        # 6. Save everything
        # --------------------------------------------------

        db.commit()
        db.refresh(incident)

        return incident

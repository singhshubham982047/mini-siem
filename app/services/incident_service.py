from sqlalchemy import select

from app.database.connection import SessionLocal
from app.database.models import Alert, AlertEvent, Event, Incident


def get_incident(incident_id):
    """Return a single incident by ID."""
    with SessionLocal() as db:
        return db.scalar(
            select(Incident).where(
                Incident.id == incident_id
            )
        )


def get_incident_alert(incident_id):
    """Return the alert associated with an incident."""
    with SessionLocal() as db:
        statement = (
            select(Alert)
            .join(
                Incident,
                Incident.alert_id == Alert.id,
            )
            .where(
                Incident.id == incident_id
            )
        )

        return db.scalar(statement)


def get_incident_events(incident_id):
    """
    Return correlated events for the incident through
    its associated alert.
    """
    with SessionLocal() as db:
        statement = (
            select(Event)
            .join(
                AlertEvent,
                AlertEvent.event_id == Event.id,
            )
            .join(
                Incident,
                Incident.alert_id == AlertEvent.alert_id,
            )
            .where(
                Incident.id == incident_id
            )
            .order_by(
                Event.timestamp.asc()
            )
        )

        return list(
            db.scalars(statement).all()
        )


def update_incident_status(
    incident_id,
    status,
):
    """Persist a new incident status."""
    with SessionLocal() as db:
        incident = db.scalar(
            select(Incident).where(
                Incident.id == incident_id
            )
        )

        if incident is None:
            return False, "Incident not found."

        incident.status = status

        try:
            db.commit()
            db.refresh(incident)

            return True, None

        except Exception as exc:
            db.rollback()
            return False, str(exc)

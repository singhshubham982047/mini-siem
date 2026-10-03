from sqlalchemy import select

from app.database.models import Alert, AlertEvent, Event
from app.database.connection import SessionLocal


def get_alert(alert_id):
    """Return a single alert by ID."""
    with SessionLocal() as db:
        return db.scalar(
            select(Alert).where(
                Alert.id == alert_id
            )
        )


def get_alert_events(alert_id):
    """
    Return events correlated with an alert through
    the AlertEvent relationship.
    """
    with SessionLocal() as db:
        statement = (
            select(Event)
            .join(
                AlertEvent,
                AlertEvent.event_id == Event.id,
            )
            .where(
                AlertEvent.alert_id == alert_id
            )
            .order_by(
                Event.timestamp.asc()
            )
        )

        return list(
            db.scalars(statement).all()
        )


def update_alert_status(alert_id, status):
    """Persist a new alert status."""
    with SessionLocal() as db:
        alert = db.scalar(
            select(Alert).where(
                Alert.id == alert_id
            )
        )

        if alert is None:
            return False, "Alert not found."

        alert.status = status

        try:
            db.commit()
            db.refresh(alert)

            return True, None

        except Exception as exc:
            db.rollback()
            return False, str(exc)

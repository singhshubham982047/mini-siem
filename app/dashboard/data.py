from datetime import datetime, timedelta, timezone

import pandas as pd
from sqlalchemy import select

from app.database.connection import SessionLocal
from app.database.models import Alert, Event, Incident, LogSource


def fetch_rows(statement, columns):
    """Execute a read-only query and return a DataFrame."""
    with SessionLocal() as db:
        rows = db.execute(statement).mappings().all()
        return pd.DataFrame(
            [dict(row) for row in rows],
            columns=columns,
        )


def fetch_scalar(statement):
    """Execute a query that returns one scalar value."""
    with SessionLocal() as db:
        return db.scalar(statement) or 0


def get_database_status():
    """Check whether PostgreSQL is reachable."""
    try:
        with SessionLocal() as db:
            db.execute(select(1))

        return True, None

    except Exception as exc:
        return False, str(exc)


def get_time_range(days):
    """Return a UTC time range, using an exclusive end."""
    end = datetime.now(timezone.utc)
    start = end - timedelta(days=days)

    return start, end


def get_events(days, limit=500):
    start, end = get_time_range(days)

    statement = (
        select(
            Event.id.label("ID"),
            Event.timestamp.label("Timestamp"),
            Event.source.label("Source"),
            Event.event_type.label("Event Type"),
            Event.action.label("Action"),
            Event.username.label("Username"),
            Event.src_ip.label("Source IP"),
            Event.dst_ip.label("Destination IP"),
            Event.dst_port.label("Destination Port"),
            Event.status.label("Status"),
            Event.severity.label("Severity"),
            Event.message.label("Message"),
        )
        .where(
            Event.timestamp >= start,
            Event.timestamp < end,
        )
        .order_by(Event.timestamp.desc())
        .limit(limit)
    )

    return fetch_rows(
        statement,
        [
            "ID",
            "Timestamp",
            "Source",
            "Event Type",
            "Action",
            "Username",
            "Source IP",
            "Destination IP",
            "Destination Port",
            "Status",
            "Severity",
            "Message",
        ],
    )


def get_alerts(days, limit=500):
    start, end = get_time_range(days)

    statement = (
        select(
            Alert.id.label("ID"),
            Alert.created_at.label("Created At"),
            Alert.title.label("Title"),
            Alert.rule_name.label("Detection Rule"),
            Alert.severity.label("Severity"),
            Alert.src_ip.label("Source IP"),
            Alert.username.label("Username"),
            Alert.status.label("Status"),
            Alert.description.label("Description"),
        )
        .where(
            Alert.created_at >= start,
            Alert.created_at < end,
        )
        .order_by(Alert.created_at.desc())
        .limit(limit)
    )

    return fetch_rows(
        statement,
        [
            "ID",
            "Created At",
            "Title",
            "Detection Rule",
            "Severity",
            "Source IP",
            "Username",
            "Status",
            "Description",
        ],
    )


def get_incidents(days, limit=500):
    start, end = get_time_range(days)

    statement = (
        select(
            Incident.id.label("ID"),
            Incident.created_at.label("Created At"),
            Incident.updated_at.label("Updated At"),
            Incident.alert_id.label("Alert ID"),
            Incident.title.label("Title"),
            Incident.severity.label("Severity"),
            Incident.status.label("Status"),
            Incident.description.label("Description"),
        )
        .where(
            Incident.created_at >= start,
            Incident.created_at < end,
        )
        .order_by(Incident.created_at.desc())
        .limit(limit)
    )

    return fetch_rows(
        statement,
        [
            "ID",
            "Created At",
            "Updated At",
            "Alert ID",
            "Title",
            "Severity",
            "Status",
            "Description",
        ],
    )


def get_log_sources():
    statement = select(
        LogSource.id.label("ID"),
        LogSource.name.label("Name"),
        LogSource.source_type.label("Type"),
        LogSource.file_path.label("File Path"),
        LogSource.enabled.label("Enabled"),
        LogSource.created_at.label("Created At"),
    ).order_by(LogSource.name.asc())

    return fetch_rows(
        statement,
        [
            "ID",
            "Name",
            "Type",
            "File Path",
            "Enabled",
            "Created At",
        ],
    )

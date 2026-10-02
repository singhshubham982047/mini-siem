from datetime import date, datetime, time, timedelta, timezone

import pandas as pd
import plotly.express as px
import streamlit as st
from sqlalchemy import func, select

from app.database.connection import SessionLocal
from app.database.models import Alert, Event, Incident, LogSource

# ---------------------------------------------------------
# PAGE CONFIGURATION
# ---------------------------------------------------------

st.set_page_config(
    page_title="Mini SIEM | Security Operations",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

st.markdown(
    """
    <style>
    .block-container {
        padding-top: 1.5rem;
        padding-bottom: 2rem;
    }
    div[data-testid="stMetric"] {
        background: rgba(128, 128, 128, 0.08);
        border: 1px solid rgba(128, 128, 128, 0.2);
        padding: 16px;
        border-radius: 12px;
    }
    </style>
    """,
    unsafe_allow_html=True,
)


# ---------------------------------------------------------
# DATABASE HELPERS
# ---------------------------------------------------------


def fetch_rows(statement, columns):
    """Execute a read-only query and return a DataFrame."""
    with SessionLocal() as db:
        rows = db.execute(statement).mappings().all()
        return pd.DataFrame([dict(row) for row in rows], columns=columns)


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
        .where(Event.timestamp >= start, Event.timestamp < end)
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
        ["ID", "Name", "Type", "File Path", "Enabled", "Created At"],
    )


# ---------------------------------------------------------
# SIDEBAR
# ---------------------------------------------------------

st.sidebar.title("🛡️ Mini SIEM")
st.sidebar.caption("Security Operations Dashboard")

page = st.sidebar.radio(
    "Navigation",
    [
        "Overview",
        "Security Events",
        "Alerts",
        "Incidents",
        "Log Sources",
    ],
)

days = st.sidebar.selectbox(
    "Time range",
    options=[1, 3, 7, 14, 30],
    index=2,
    format_func=lambda value: f"Last {value} day(s)",
)

if st.sidebar.button("↻ Refresh dashboard", use_container_width=True):
    st.rerun()

st.sidebar.divider()
st.sidebar.caption("Mini SIEM • Local PostgreSQL")


# ---------------------------------------------------------
# DATABASE HEALTH
# ---------------------------------------------------------

database_ok, database_error = get_database_status()

st.title("🛡️ Mini SIEM Security Dashboard")

if database_ok:
    st.success("PostgreSQL connection: Connected", icon="🟢")
else:
    st.error("Cannot connect to PostgreSQL. Check your .env and database service.")
    with st.expander("Technical details"):
        st.code(database_error or "Unknown database error")
    st.stop()


# ---------------------------------------------------------
# OVERVIEW
# ---------------------------------------------------------

if page == "Overview":
    st.subheader("Security Overview")
    st.caption("Security activity recorded in the selected time range.")

    start, end = get_time_range(days)

    total_events = fetch_scalar(
        select(func.count(Event.id)).where(
            Event.timestamp >= start,
            Event.timestamp < end,
        )
    )

    total_alerts = fetch_scalar(
        select(func.count(Alert.id)).where(
            Alert.created_at >= start,
            Alert.created_at < end,
        )
    )

    open_alerts = fetch_scalar(
        select(func.count(Alert.id)).where(
            Alert.status == "open",
            Alert.created_at >= start,
            Alert.created_at < end,
        )
    )

    open_incidents = fetch_scalar(
        select(func.count(Incident.id)).where(
            Incident.status == "open",
            Incident.created_at >= start,
            Incident.created_at < end,
        )
    )

    enabled_sources = fetch_scalar(
        select(func.count(LogSource.id)).where(LogSource.enabled.is_(True))
    )

    metric1, metric2, metric3, metric4 = st.columns(4)

    metric1.metric("Security Events", f"{total_events:,}")
    metric2.metric("Alerts Generated", f"{total_alerts:,}")
    metric3.metric("Open Alerts", f"{open_alerts:,}")
    metric4.metric("Open Incidents", f"{open_incidents:,}")

    st.caption(f"Enabled log sources: {enabled_sources}")

    events_df = get_events(days)
    alerts_df = get_alerts(days)
    incidents_df = get_incidents(days)

    st.divider()

    left, right = st.columns(2)

    with left:
        st.subheader("Events by Severity")

        if not events_df.empty:
            severity_df = (
                events_df["Severity"]
                .fillna("unknown")
                .value_counts()
                .rename_axis("Severity")
                .reset_index(name="Count")
            )

            fig = px.bar(
                severity_df,
                x="Severity",
                y="Count",
                color="Severity",
                title="Event severity distribution",
            )
            st.plotly_chart(fig, use_container_width=True)
        else:
            st.info("No events found in this time range.")

    with right:
        st.subheader("Alerts by Detection Rule")

        if not alerts_df.empty:
            rule_df = (
                alerts_df["Detection Rule"]
                .fillna("unknown")
                .value_counts()
                .rename_axis("Detection Rule")
                .reset_index(name="Count")
            )

            fig = px.bar(
                rule_df,
                x="Detection Rule",
                y="Count",
                title="Detection rule activity",
            )
            st.plotly_chart(fig, use_container_width=True)
        else:
            st.info("No alerts found in this time range.")

    st.divider()

    st.subheader("Recent Security Alerts")

    if not alerts_df.empty:
        st.dataframe(
            alerts_df.drop(columns=["Description"]),
            use_container_width=True,
            hide_index=True,
        )
    else:
        st.info("No recent alerts.")

    st.subheader("Recent Security Events")

    if not events_df.empty:
        st.dataframe(
            events_df.head(20),
            use_container_width=True,
            hide_index=True,
        )
    else:
        st.info("No recent events.")

    st.subheader("Recent Incidents")

    if not incidents_df.empty:
        st.dataframe(
            incidents_df.drop(columns=["Description"]).head(10),
            use_container_width=True,
            hide_index=True,
        )
    else:
        st.info("No incidents found in this time range.")


# ---------------------------------------------------------
# SECURITY EVENTS
# ---------------------------------------------------------

elif page == "Security Events":
    st.subheader("Security Event Explorer")
    st.caption("Search normalized events stored in PostgreSQL.")

    events_df = get_events(days)

    if events_df.empty:
        st.info("No events found in this time range.")
    else:
        filter1, filter2, filter3 = st.columns(3)

        with filter1:
            severities = sorted(events_df["Severity"].dropna().unique().tolist())
            selected_severities = st.multiselect(
                "Severity",
                severities,
                default=severities,
            )

        with filter2:
            statuses = sorted(events_df["Status"].dropna().unique().tolist())
            selected_statuses = st.multiselect(
                "Event status",
                statuses,
                default=statuses,
            )

        with filter3:
            event_types = sorted(events_df["Event Type"].dropna().unique().tolist())
            selected_types = st.multiselect(
                "Event type",
                event_types,
                default=event_types,
            )

        source_ip = st.text_input("Filter by source IP")
        username = st.text_input("Filter by username")
        search_text = st.text_input("Search event message")

        filtered = events_df[
            events_df["Severity"].isin(selected_severities)
            & events_df["Status"].isin(selected_statuses)
            & events_df["Event Type"].isin(selected_types)
        ].copy()

        if source_ip.strip():
            filtered = filtered[
                filtered["Source IP"]
                .fillna("")
                .str.contains(source_ip.strip(), case=False, regex=False)
            ]

        if username.strip():
            filtered = filtered[
                filtered["Username"]
                .fillna("")
                .str.contains(username.strip(), case=False, regex=False)
            ]

        if search_text.strip():
            filtered = filtered[
                filtered["Message"]
                .fillna("")
                .str.contains(search_text.strip(), case=False, regex=False)
            ]

        st.metric("Matching Events", f"{len(filtered):,}")

        st.dataframe(
            filtered,
            use_container_width=True,
            hide_index=True,
        )

        st.download_button(
            "Download filtered events as CSV",
            data=filtered.to_csv(index=False).encode("utf-8"),
            file_name="mini_siem_events.csv",
            mime="text/csv",
        )


# ---------------------------------------------------------
# ALERTS
# ---------------------------------------------------------

elif page == "Alerts":
    st.subheader("Security Alerts")

    alerts_df = get_alerts(days)

    if alerts_df.empty:
        st.info("No alerts found in this time range.")
    else:
        filter1, filter2 = st.columns(2)

        with filter1:
            alert_statuses = sorted(alerts_df["Status"].dropna().unique().tolist())
            selected_status = st.multiselect(
                "Alert status",
                alert_statuses,
                default=alert_statuses,
            )

        with filter2:
            alert_severities = sorted(alerts_df["Severity"].dropna().unique().tolist())
            selected_severity = st.multiselect(
                "Alert severity",
                alert_severities,
                default=alert_severities,
            )

        filtered = alerts_df[
            alerts_df["Status"].isin(selected_status)
            & alerts_df["Severity"].isin(selected_severity)
        ].copy()

        st.metric("Matching Alerts", f"{len(filtered):,}")

        st.dataframe(
            filtered,
            use_container_width=True,
            hide_index=True,
        )

        st.download_button(
            "Download alerts as CSV",
            data=filtered.to_csv(index=False).encode("utf-8"),
            file_name="mini_siem_alerts.csv",
            mime="text/csv",
        )


# ---------------------------------------------------------
# INCIDENTS
# ---------------------------------------------------------

elif page == "Incidents":
    st.subheader("Incident Management")

    incidents_df = get_incidents(days)

    if incidents_df.empty:
        st.info("No incidents found in this time range.")
    else:
        statuses = sorted(incidents_df["Status"].dropna().unique().tolist())

        selected_status = st.multiselect(
            "Incident status",
            statuses,
            default=statuses,
        )

        filtered = incidents_df[incidents_df["Status"].isin(selected_status)].copy()

        st.metric("Matching Incidents", f"{len(filtered):,}")

        st.dataframe(
            filtered,
            use_container_width=True,
            hide_index=True,
        )

        st.info(
            "This view is read-only. Incident status changes will be "
            "added after the incident workflow is implemented and tested."
        )


# ---------------------------------------------------------
# LOG SOURCES
# ---------------------------------------------------------

elif page == "Log Sources":
    st.subheader("Configured Log Sources")

    sources_df = get_log_sources()

    if sources_df.empty:
        st.info("No log sources are registered yet.")
    else:
        source1, source2 = st.columns(2)

        source1.metric("Registered Sources", len(sources_df))
        source2.metric(
            "Enabled Sources",
            int(sources_df["Enabled"].fillna(False).sum()),
        )

        st.dataframe(
            sources_df,
            use_container_width=True,
            hide_index=True,
        )

        st.caption(
            "Enabled indicates the source's database configuration. "
            "It does not independently confirm that a collector is running."
        )

st.divider()
st.caption(
    "Mini SIEM | Local security analytics | "
    "Data displayed from your PostgreSQL database"
)

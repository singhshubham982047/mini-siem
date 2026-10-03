import pandas as pd
import plotly.express as px
import streamlit as st
from sqlalchemy import func, select

from app.database.models import Alert, Event, Incident, LogSource
from app.dashboard.data import (
    fetch_scalar,
    get_alerts,
    get_events,
    get_incidents,
    get_time_range,
)


def render_overview(days):
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

    metric1.metric(
        "Security Events",
        f"{total_events:,}",
    )

    metric2.metric(
        "Alerts Generated",
        f"{total_alerts:,}",
    )

    metric3.metric(
        "Open Alerts",
        f"{open_alerts:,}",
    )

    metric4.metric(
        "Open Incidents",
        f"{open_incidents:,}",
    )

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

            st.plotly_chart(
                fig,
                width="stretch",
            )

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

            st.plotly_chart(
                fig,
                width="stretch",
            )

        else:
            st.info("No alerts found in this time range.")

    st.divider()

    st.subheader("Recent Security Alerts")

    if not alerts_df.empty:
        st.dataframe(
            alerts_df.drop(columns=["Description"]),
            width="stretch",
            hide_index=True,
        )

    else:
        st.info("No recent alerts.")

    st.subheader("Recent Security Events")

    if not events_df.empty:
        st.dataframe(
            events_df.head(20),
            width="stretch",
            hide_index=True,
        )

    else:
        st.info("No recent events.")

    st.subheader("Recent Incidents")

    if not incidents_df.empty:
        st.dataframe(
            incidents_df.drop(columns=["Description"]).head(10),
            width="stretch",
            hide_index=True,
        )

    else:
        st.info("No incidents found in the selected period.")

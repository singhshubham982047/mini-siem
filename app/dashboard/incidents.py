import pandas as pd
import streamlit as st

from app.dashboard.data import get_incidents
from app.services.incident_service import (
    get_incident,
    get_incident_alert,
    get_incident_events,
    update_incident_status,
)

INCIDENT_STATUSES = [
    "open",
    "acknowledged",
    "resolved",
    "closed",
]


def format_timestamp(value):
    """Format a datetime safely."""
    if value is None:
        return "N/A"

    return value.strftime("%Y-%m-%d %H:%M:%S")


def calculate_attack_duration(events):
    """Calculate duration between first and last correlated event."""

    timestamps = [event.timestamp for event in events if event.timestamp is not None]

    if len(timestamps) < 2:
        return "0 seconds"

    first = min(timestamps)
    last = max(timestamps)

    duration = last - first

    total_seconds = int(duration.total_seconds())

    if total_seconds < 60:
        return f"{total_seconds} seconds"

    minutes, seconds = divmod(total_seconds, 60)

    if minutes < 60:
        return f"{minutes}m {seconds}s"

    hours, minutes = divmod(minutes, 60)

    return f"{hours}h {minutes}m"


def get_unique_values(events, attribute):
    """Return unique non-empty values from events."""

    values = []

    for event in events:
        value = getattr(event, attribute, None)

        if value is not None and str(value).strip():
            values.append(str(value))

    return sorted(set(values))


def render_attack_summary(incident, alert, events):
    """Render SOC-style attack summary."""

    st.markdown("### Attack Summary")

    source_ips = get_unique_values(events, "src_ip")
    usernames = get_unique_values(events, "username")
    event_types = get_unique_values(events, "event_type")

    source_ip = (
        alert.src_ip
        if alert and alert.src_ip
        else ", ".join(source_ips) if source_ips else "N/A"
    )

    username = (
        alert.username
        if alert and alert.username
        else ", ".join(usernames) if usernames else "N/A"
    )

    rule_name = alert.rule_name if alert and alert.rule_name else "N/A"

    first_event = events[0] if events else None
    last_event = events[-1] if events else None

    col1, col2, col3, col4 = st.columns(4)

    with col1:
        st.metric(
            "Source IP",
            source_ip,
        )

    with col2:
        st.metric(
            "Target User",
            username,
        )

    with col3:
        st.metric(
            "Attempts / Events",
            len(events),
        )

    with col4:
        st.metric(
            "Attack Duration",
            calculate_attack_duration(events),
        )

    st.markdown("#### Detection Context")

    context_col1, context_col2, context_col3 = st.columns(3)

    with context_col1:
        st.write("**Detection Rule**")
        st.write(rule_name)

    with context_col2:
        st.write("**Event Types**")
        st.write(", ".join(event_types) if event_types else "N/A")

    with context_col3:
        st.write("**Severity**")
        st.write(incident.severity or "N/A")

    timeline_col1, timeline_col2 = st.columns(2)

    with timeline_col1:
        st.write("**First Event**")
        st.write(format_timestamp(first_event.timestamp if first_event else None))

    with timeline_col2:
        st.write("**Last Event**")
        st.write(format_timestamp(last_event.timestamp if last_event else None))


def render_attack_timeline(events, alert=None):
    """Render chronological SOC investigation timeline."""

    st.markdown("### Attack Timeline")

    if not events:
        st.info("No events available for the timeline.")
        return

    for index, event in enumerate(events, start=1):

        timestamp = format_timestamp(event.timestamp)

        event_title = (
            event.message or event.action or event.event_type or "Security Event"
        )

        severity = event.severity or "unknown"
        status = event.status or "unknown"

        with st.container(border=True):

            col1, col2 = st.columns([1, 5])

            with col1:
                st.markdown(f"### {index}")

                st.caption(timestamp)

            with col2:

                st.markdown(f"**{event_title}**")

                details = []

                if event.src_ip:
                    details.append(f"Source IP: `{event.src_ip}`")

                if event.username:
                    details.append(f"User: `{event.username}`")

                if event.src_port:
                    details.append(f"Source Port: `{event.src_port}`")

                if event.dst_ip:
                    details.append(f"Destination: `{event.dst_ip}`")

                if event.dst_port:
                    details.append(f"Destination Port: `{event.dst_port}`")

                if event.event_type:
                    details.append(f"Type: `{event.event_type}`")

                if details:
                    st.write(" • ".join(details))

                st.caption(
                    f"Severity: {severity} | "
                    f"Status: {status} | "
                    f"Event ID: {event.id}"
                )

    if alert:
        st.markdown("#### Detection Event")

        with st.container(border=True):

            st.markdown(
                f"🚨 **Alert #{alert.id}: " f"{alert.title or 'Security Alert'}**"
            )

            st.write(f"**Rule:** `{alert.rule_name or 'N/A'}`")

            st.write(f"**Severity:** `{alert.severity or 'N/A'}`")

            st.write(f"**Status:** `{alert.status or 'N/A'}`")

            st.write(alert.description or "No alert description available.")


def render_evidence(events):
    """Render detailed evidence for investigation."""

    st.markdown("### Evidence")

    if not events:
        st.info("No evidence available.")
        return

    for event in events:

        with st.expander(
            f"Event #{event.id} — " f"{format_timestamp(event.timestamp)}"
        ):

            col1, col2 = st.columns(2)

            with col1:
                st.write("**Event ID**")
                st.write(event.id)

                st.write("**Source**")
                st.write(event.source or "N/A")

                st.write("**Event Type**")
                st.write(event.event_type or "N/A")

                st.write("**Action**")
                st.write(event.action or "N/A")

                st.write("**Username**")
                st.write(event.username or "N/A")

                st.write("**Status**")
                st.write(event.status or "N/A")

            with col2:
                st.write("**Source IP**")
                st.write(event.src_ip or "N/A")

                st.write("**Source Port**")
                st.write(event.src_port or "N/A")

                st.write("**Destination IP**")
                st.write(event.dst_ip or "N/A")

                st.write("**Destination Port**")
                st.write(event.dst_port or "N/A")

                st.write("**Severity**")
                st.write(event.severity or "N/A")

                st.write("**Timestamp**")
                st.write(format_timestamp(event.timestamp))

            st.write("**Parsed Message**")
            st.info(event.message or "No parsed message available.")

            st.write("**Raw Log Evidence**")

            if event.raw_log:
                st.code(
                    event.raw_log,
                    language="text",
                )
            else:
                st.caption("No raw log data available.")


def render_incident_details(incident_id):
    """Render detailed investigation view for a selected incident."""

    incident = get_incident(incident_id)

    if incident is None:
        st.error("Incident not found.")
        return

    alert = get_incident_alert(incident_id)

    events = get_incident_events(incident_id)

    st.divider()

    st.subheader(f"Incident #{incident.id}")

    # ---------------------------------------------------------
    # Top-level incident metrics
    # ---------------------------------------------------------

    col1, col2, col3, col4 = st.columns(4)

    with col1:
        st.metric(
            "Severity",
            incident.severity or "unknown",
        )

    with col2:
        st.metric(
            "Status",
            incident.status or "unknown",
        )

    with col3:
        st.metric(
            "Correlated Events",
            len(events),
        )

    with col4:
        st.metric(
            "Alert ID",
            incident.alert_id if incident.alert_id else "N/A",
        )

    # ---------------------------------------------------------
    # Incident information
    # ---------------------------------------------------------

    st.markdown("### Incident Details")

    details_col1, details_col2 = st.columns(2)

    with details_col1:

        st.write("**Title**")
        st.write(incident.title or "N/A")

        st.write("**Severity**")
        st.write(incident.severity or "N/A")

        st.write("**Created At**")
        st.write(format_timestamp(incident.created_at))

    with details_col2:

        st.write("**Status**")
        st.write(incident.status or "N/A")

        st.write("**Alert ID**")
        st.write(incident.alert_id or "N/A")

        st.write("**Updated At**")
        st.write(format_timestamp(incident.updated_at))

    st.write("**Description**")

    st.info(incident.description or "No description available.")

    # ---------------------------------------------------------
    # Attack summary
    # ---------------------------------------------------------

    render_attack_summary(
        incident,
        alert,
        events,
    )

    # ---------------------------------------------------------
    # Status management
    # ---------------------------------------------------------

    st.markdown("### Incident Status")

    current_status = incident.status if incident.status in INCIDENT_STATUSES else "open"

    selected_status = st.selectbox(
        "Change incident status",
        INCIDENT_STATUSES,
        index=INCIDENT_STATUSES.index(current_status),
        key=f"incident_status_{incident_id}",
    )

    if st.button(
        "Update Incident Status",
        key=f"update_incident_status_{incident_id}",
        width="stretch",
    ):

        success, error = update_incident_status(
            incident_id,
            selected_status,
        )

        if success:

            st.success(
                f"Incident #{incident_id} status " f"updated to '{selected_status}'."
            )

            st.rerun()

        else:

            st.error(error)

    # ---------------------------------------------------------
    # Associated alert
    # ---------------------------------------------------------

    if alert:

        st.markdown("### Associated Alert")

        alert_col1, alert_col2, alert_col3 = st.columns(3)

        with alert_col1:
            st.metric(
                "Alert ID",
                alert.id,
            )

        with alert_col2:
            st.metric(
                "Detection Rule",
                alert.rule_name or "N/A",
            )

        with alert_col3:
            st.metric(
                "Alert Status",
                alert.status or "N/A",
            )

        st.write("**Alert Title**")

        st.write(alert.title or "N/A")

        st.write("**Source IP**")

        st.write(alert.src_ip or "N/A")

        st.write("**Username**")

        st.write(alert.username or "N/A")

        st.write("**Description**")

        st.write(alert.description or "N/A")

    # ---------------------------------------------------------
    # Attack timeline
    # ---------------------------------------------------------

    render_attack_timeline(
        events,
        alert,
    )

    # ---------------------------------------------------------
    # Evidence
    # ---------------------------------------------------------

    render_evidence(events)

    # ---------------------------------------------------------
    # Correlated events table
    # ---------------------------------------------------------

    st.markdown("### Correlated Events Table")

    if not events:

        st.warning("No correlated events found for this incident.")

        return

    event_rows = []

    for event in events:

        event_rows.append(
            {
                "ID": event.id,
                "Timestamp": event.timestamp,
                "Source": event.source,
                "Event Type": event.event_type,
                "Action": event.action,
                "Username": event.username,
                "Source IP": event.src_ip,
                "Source Port": event.src_port,
                "Destination IP": event.dst_ip,
                "Destination Port": event.dst_port,
                "Status": event.status,
                "Severity": event.severity,
                "Message": event.message,
            }
        )

    events_df = pd.DataFrame(event_rows)

    st.dataframe(
        events_df,
        width="stretch",
        hide_index=True,
    )

    # ---------------------------------------------------------
    # CSV export
    # ---------------------------------------------------------

    csv_data = events_df.to_csv(index=False).encode("utf-8")

    st.download_button(
        label="Download Correlated Events CSV",
        data=csv_data,
        file_name=(f"incident_{incident_id}_events.csv"),
        mime="text/csv",
        width="stretch",
    )


def render_incidents(days):
    """Render the incidents dashboard."""

    st.header("Incidents")

    incidents_df = get_incidents(days)

    if incidents_df.empty:

        st.info("No incidents found for the selected time range.")

        return

    # ---------------------------------------------------------
    # Filters
    # ---------------------------------------------------------

    col1, col2 = st.columns(2)

    with col1:

        statuses = sorted(incidents_df["Status"].dropna().astype(str).unique().tolist())

        selected_statuses = st.multiselect(
            "Status",
            statuses,
            default=statuses,
        )

    with col2:

        severities = sorted(
            incidents_df["Severity"].dropna().astype(str).unique().tolist()
        )

        selected_severities = st.multiselect(
            "Severity",
            severities,
            default=severities,
        )

    filtered_df = incidents_df[
        incidents_df["Status"].isin(selected_statuses)
        & incidents_df["Severity"].isin(selected_severities)
    ].copy()

    # ---------------------------------------------------------
    # Incident queue
    # ---------------------------------------------------------

    st.subheader("Incident Queue")

    st.dataframe(
        filtered_df,
        width="stretch",
        hide_index=True,
    )

    # ---------------------------------------------------------
    # Incident selection
    # ---------------------------------------------------------

    incident_ids = filtered_df["ID"].tolist()

    if not incident_ids:

        st.warning("No incidents match the selected filters.")

        return

    selected_incident_id = st.selectbox(
        "Select an incident to investigate",
        incident_ids,
        format_func=lambda incident_id: f"Incident #{incident_id}",
    )

    if st.button(
        "Investigate Selected Incident",
        width="stretch",
    ):

        st.session_state["investigating_incident_id"] = selected_incident_id

    # ---------------------------------------------------------
    # Investigation view
    # ---------------------------------------------------------

    investigating_id = st.session_state.get("investigating_incident_id")

    if investigating_id:

        render_incident_details(investigating_id)

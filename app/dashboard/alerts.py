import pandas as pd
import streamlit as st

from app.dashboard.data import get_alerts
from app.services.alert_service import (
    get_alert,
    get_alert_events,
    update_alert_status,
)


def render_alert_details(alert_id):
    alert = get_alert(alert_id)

    if alert is None:
        st.error("Alert no longer exists.")
        return

    st.divider()
    st.subheader(f"Alert Investigation #{alert.id}")

    col1, col2, col3, col4 = st.columns(4)

    col1.metric(
        "Severity",
        alert.severity.upper(),
    )

    col2.metric(
        "Status",
        alert.status.upper(),
    )

    col3.metric(
        "Detection Rule",
        alert.rule_name,
    )

    col4.metric(
        "Source IP",
        alert.src_ip or "N/A",
    )

    st.markdown(f"### {alert.title}")

    if alert.description:
        st.info(alert.description)

    detail1, detail2 = st.columns(2)

    with detail1:
        st.write(f"**Alert ID:** {alert.id}")
        st.write(f"**Detection Rule:** {alert.rule_name}")
        st.write(f"**Severity:** {alert.severity}")

    with detail2:
        st.write(f"**Source IP:** " f"{alert.src_ip or 'N/A'}")
        st.write(f"**Username:** " f"{alert.username or 'N/A'}")
        st.write(f"**Created:** " f"{alert.created_at}")

    st.divider()

    st.subheader("Alert Status")

    status_options = [
        "open",
        "acknowledged",
        "resolved",
        "closed",
    ]

    current_status = alert.status if alert.status in status_options else "open"

    selected_status = st.selectbox(
        "Change alert status",
        status_options,
        index=status_options.index(current_status),
        key=f"alert_status_{alert.id}",
    )

    if selected_status != alert.status:
        if st.button(
            "Save Alert Status",
            type="primary",
            key=f"save_alert_{alert.id}",
        ):
            success, error = update_alert_status(
                alert.id,
                selected_status,
            )

            if success:
                st.success(f"Alert status changed to " f"'{selected_status}'.")
                st.rerun()

            else:
                st.error(f"Unable to update alert: {error}")

    st.divider()

    st.subheader("Correlated Security Events")

    events = get_alert_events(alert.id)

    if not events:
        st.info("No correlated events were found " "for this alert.")
        return

    event_rows = []

    for event in events:
        event_rows.append(
            {
                "ID": event.id,
                "Timestamp": event.timestamp,
                "Event Type": event.event_type,
                "Action": event.action,
                "Username": event.username,
                "Source IP": event.src_ip,
                "Destination IP": event.dst_ip,
                "Source Port": event.src_port,
                "Destination Port": event.dst_port,
                "Status": event.status,
                "Severity": event.severity,
                "Message": event.message,
            }
        )

    events_df = pd.DataFrame(event_rows)

    st.metric(
        "Correlated Events",
        len(events_df),
    )

    st.dataframe(
        events_df,
        width="stretch",
        hide_index=True,
    )

    st.download_button(
        "Download correlated events",
        data=events_df.to_csv(index=False).encode("utf-8"),
        file_name=(f"alert_{alert.id}_events.csv"),
        mime="text/csv",
    )


def render_alerts(days):
    st.subheader("Security Alerts")
    st.caption("Monitor, investigate, and manage " "security alerts.")

    alerts_df = get_alerts(days)

    if alerts_df.empty:
        st.info("No alerts found in this time range.")
        return

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

    st.metric(
        "Matching Alerts",
        f"{len(filtered):,}",
    )

    st.dataframe(
        filtered,
        width="stretch",
        hide_index=True,
    )

    st.download_button(
        "Download alerts as CSV",
        data=filtered.to_csv(index=False).encode("utf-8"),
        file_name="mini_siem_alerts.csv",
        mime="text/csv",
    )

    st.divider()

    st.subheader("Investigate Alert")

    alert_ids = filtered["ID"].tolist()

    if not alert_ids:
        st.info("No alerts match the selected filters.")
        return

    selected_alert_id = st.selectbox(
        "Select an alert",
        alert_ids,
        format_func=lambda alert_id: (
            f"Alert #{alert_id} — "
            f"{filtered.loc[filtered['ID'] == alert_id, 'Title'].iloc[0]}"
        ),
    )

    if st.button(
        "Investigate Selected Alert",
        type="primary",
    ):
        st.session_state["investigating_alert_id"] = selected_alert_id

    investigation_id = st.session_state.get("investigating_alert_id")

    if investigation_id:
        render_alert_details(investigation_id)

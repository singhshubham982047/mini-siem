import streamlit as st

from app.dashboard.data import get_alerts


def render_alerts(days):
    st.subheader("Security Alerts")

    alerts_df = get_alerts(days)

    if alerts_df.empty:
        st.info(
            "No alerts found in this time range."
        )

    else:
        filter1, filter2 = st.columns(2)

        with filter1:
            alert_statuses = sorted(
                alerts_df["Status"]
                .dropna()
                .unique()
                .tolist()
            )

            selected_status = st.multiselect(
                "Alert status",
                alert_statuses,
                default=alert_statuses,
            )

        with filter2:
            alert_severities = sorted(
                alerts_df["Severity"]
                .dropna()
                .unique()
                .tolist()
            )

            selected_severity = st.multiselect(
                "Alert severity",
                alert_severities,
                default=alert_severities,
            )

        filtered = alerts_df[
            alerts_df["Status"].isin(
                selected_status
            )
            & alerts_df["Severity"].isin(
                selected_severity
            )
        ].copy()

        st.metric(
            "Matching Alerts",
            f"{len(filtered):,}",
        )

        st.dataframe(
            filtered,
            use_container_width=True,
            hide_index=True,
        )

        st.download_button(
            "Download alerts as CSV",
            data=filtered.to_csv(
                index=False
            ).encode("utf-8"),
            file_name="mini_siem_alerts.csv",
            mime="text/csv",
        )

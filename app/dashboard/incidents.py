import streamlit as st

from app.dashboard.data import get_incidents


def render_incidents(days):
    st.subheader("Incident Management")

    incidents_df = get_incidents(days)

    if incidents_df.empty:
        st.info(
            "No incidents found in this time range."
        )

    else:
        statuses = sorted(
            incidents_df["Status"]
            .dropna()
            .unique()
            .tolist()
        )

        selected_status = st.multiselect(
            "Incident status",
            statuses,
            default=statuses,
        )

        filtered = incidents_df[
            incidents_df["Status"].isin(
                selected_status
            )
        ].copy()

        st.metric(
            "Matching Incidents",
            f"{len(filtered):,}",
        )

        st.dataframe(
            filtered,
            use_container_width=True,
            hide_index=True,
        )

        st.info(
            "This view is read-only. Incident status changes "
            "will be added after the incident workflow is "
            "implemented and tested."
        )

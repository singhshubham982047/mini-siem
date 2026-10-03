import streamlit as st

from app.dashboard.data import get_events


def render_security_events(days):
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
                .str.contains(
                    source_ip.strip(),
                    case=False,
                    regex=False,
                )
            ]

        if username.strip():
            filtered = filtered[
                filtered["Username"]
                .fillna("")
                .str.contains(
                    username.strip(),
                    case=False,
                    regex=False,
                )
            ]

        if search_text.strip():
            filtered = filtered[
                filtered["Message"]
                .fillna("")
                .str.contains(
                    search_text.strip(),
                    case=False,
                    regex=False,
                )
            ]

        st.metric(
            "Matching Events",
            f"{len(filtered):,}",
        )

        st.dataframe(
            filtered,
            width="stretch",
            hide_index=True,
        )

        st.download_button(
            "Download filtered events as CSV",
            data=filtered.to_csv(index=False).encode("utf-8"),
            file_name="mini_siem_events.csv",
            mime="text/csv",
        )

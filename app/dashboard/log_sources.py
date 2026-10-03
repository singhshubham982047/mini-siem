import streamlit as st

from app.dashboard.data import get_log_sources


def render_log_sources():
    st.subheader("Configured Log Sources")

    sources_df = get_log_sources()

    if sources_df.empty:
        st.info("No log sources are registered yet.")

    else:
        source1, source2 = st.columns(2)

        source1.metric(
            "Registered Sources",
            len(sources_df),
        )

        source2.metric(
            "Enabled Sources",
            int(sources_df["Enabled"].fillna(False).sum()),
        )

        st.dataframe(
            sources_df,
            width="stretch",
            hide_index=True,
        )

        st.caption(
            "Enabled indicates the source's database "
            "configuration. It does not independently "
            "confirm that a collector is running."
        )

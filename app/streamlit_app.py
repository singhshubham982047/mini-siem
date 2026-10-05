import streamlit as st

from app.dashboard.data import get_database_status
from app.dashboard.overview import render_overview
from app.dashboard.security_events import render_security_events
from app.dashboard.alerts import render_alerts
from app.dashboard.incidents import render_incidents
from app.dashboard.log_sources import render_log_sources
from app.dashboard.detection_rules import render_detection_rules

# ---------------------------------------------------------
# PAGE CONFIGURATION
# ---------------------------------------------------------

st.set_page_config(
    page_title="SIEM | Security Operations",
    page_icon="🦅",
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
# SIDEBAR
# ---------------------------------------------------------

st.sidebar.title("🦅 EAGLE")
st.sidebar.caption("Security Operations Dashboard")

page = st.sidebar.radio(
    "Navigation",
    [
        "Overview",
        "Security Events",
        "Alerts",
        "Incidents",
        "Log Sources",
        "Detection Rules",
    ],
)

days = st.sidebar.selectbox(
    "Time range",
    options=[1, 3, 7, 14, 30],
    index=2,
    format_func=lambda value: (f"Last {value} day(s)"),
)

if st.sidebar.button(
    "↻ Refresh dashboard",
    width="stretch",
):
    st.rerun()

st.sidebar.divider()
st.sidebar.caption("Mini SIEM • Local PostgreSQL")


# ---------------------------------------------------------
# DATABASE HEALTH
# ---------------------------------------------------------

database_ok, database_error = get_database_status()

st.title("🦅 SIEM Security Dashboard")

if database_ok:
    st.success(
        "PostgreSQL connection: Connected",
        icon="🟢",
    )

else:
    st.error("Cannot connect to PostgreSQL. " "Check your .env and database service.")

    with st.expander("Technical details"):
        st.code(database_error or "Unknown database error")

    st.stop()


# ---------------------------------------------------------
# PAGE ROUTING
# ---------------------------------------------------------

if page == "Overview":
    render_overview(days)

elif page == "Security Events":
    render_security_events(days)

elif page == "Alerts":
    render_alerts(days)

elif page == "Incidents":
    render_incidents(days)

elif page == "Log Sources":
    render_log_sources()

elif page == "Detection Rules":
    render_detection_rules()

# ---------------------------------------------------------
# FOOTER
# ---------------------------------------------------------

st.divider()

st.caption(
    "SIEM | Local security analytics | " "Data displayed from your PostgreSQL database"
)

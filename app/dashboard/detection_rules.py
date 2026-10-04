import streamlit as st
from sqlalchemy import select

from app.database.connection import SessionLocal
from app.database.models import DetectionRule


# ---------------------------------------------------------
# DATA ACCESS
# ---------------------------------------------------------

def get_detection_rules():
    with SessionLocal() as db:
        statement = (
            select(DetectionRule)
            .order_by(DetectionRule.id.asc())
        )

        return list(db.scalars(statement).all())


def update_rule_enabled(rule_id, enabled):
    with SessionLocal() as db:
        rule = db.scalar(
            select(DetectionRule).where(
                DetectionRule.id == rule_id
            )
        )

        if rule is None:
            return False, "Detection rule not found."

        rule.enabled = enabled

        try:
            db.commit()
            return True, None

        except Exception as exc:
            db.rollback()
            return False, str(exc)


# ---------------------------------------------------------
# HELPERS
# ---------------------------------------------------------

def severity_badge(severity):
    severity = (severity or "").lower()

    if severity == "critical":
        return "🔴 Critical"

    if severity == "high":
        return "🟠 High"

    if severity == "medium":
        return "🟡 Medium"

    if severity == "low":
        return "🟢 Low"

    return severity.title()


# ---------------------------------------------------------
# RULE DETAILS
# ---------------------------------------------------------

def render_rule_details(rule):
    st.markdown("### Rule Details")

    col1, col2, col3 = st.columns(3)

    with col1:
        st.metric("Rule ID", rule.id)

    with col2:
        st.metric("Threshold", rule.threshold)

    with col3:
        st.metric("Window", f"{rule.window_minutes} min")

    st.markdown("---")

    st.write(f"**Name:** `{rule.name}`")
    st.write(f"**Type:** `{rule.rule_type}`")
    st.write(f"**Severity:** {severity_badge(rule.severity)}")
    st.write(f"**Enabled:** {'Yes' if rule.enabled else 'No'}")

    if rule.description:
        st.write(f"**Description:** {rule.description}")


# ---------------------------------------------------------
# MAIN PAGE
# ---------------------------------------------------------

def render_detection_rules():
    st.title("Detection Rules")
    st.caption(
        "Manage the detection rules used by the Mini SIEM detection engine."
    )

    rules = get_detection_rules()

    if not rules:
        st.warning("No detection rules configured.")
        return

    # -----------------------------------------------------
    # SUMMARY
    # -----------------------------------------------------

    total_rules = len(rules)
    enabled_rules = sum(1 for rule in rules if rule.enabled)
    disabled_rules = total_rules - enabled_rules

    col1, col2, col3 = st.columns(3)

    with col1:
        st.metric(
            "Total Rules",
            total_rules
        )

    with col2:
        st.metric(
            "Enabled",
            enabled_rules
        )

    with col3:
        st.metric(
            "Disabled",
            disabled_rules
        )

    st.markdown("---")

    # -----------------------------------------------------
    # RULE TABLE
    # -----------------------------------------------------

    st.subheader("Configured Detection Rules")

    for rule in rules:
        with st.container(border=True):

            col1, col2, col3, col4, col5 = st.columns(
                [2.5, 1.2, 1.2, 1.5, 1.2]
            )

            with col1:
                st.markdown(f"**{rule.name}**")
                st.caption(rule.description)

            with col2:
                st.write(
                    f"**Type**\n\n{rule.rule_type}"
                )

            with col3:
                st.write(
                    f"**Severity**\n\n{severity_badge(rule.severity)}"
                )

            with col4:
                st.write(
                    f"**Threshold**\n\n"
                    f"{rule.threshold} events / "
                    f"{rule.window_minutes} min"
                )

            with col5:
                new_enabled = st.toggle(
                    "Enabled",
                    value=rule.enabled,
                    key=f"rule_enabled_{rule.id}"
                )

                if new_enabled != rule.enabled:
                    success, error = update_rule_enabled(
                        rule.id,
                        new_enabled
                    )

                    if success:
                        st.success("Updated")
                        st.rerun()
                    else:
                        st.error(error)

            with st.expander("View rule details"):
                render_rule_details(rule)

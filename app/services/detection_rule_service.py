from sqlalchemy import select

from app.database.connection import SessionLocal
from app.database.models import DetectionRule


def get_detection_rule(rule_name):
    """
    Retrieve a detection rule by name.
    """
    with SessionLocal() as db:
        return db.scalar(
            select(DetectionRule).where(
                DetectionRule.name == rule_name
            )
        )


def is_rule_enabled(rule_name):
    """
    Return True when the requested detection rule exists
    and is enabled.
    """
    rule = get_detection_rule(rule_name)

    if rule is None:
        return False

    return bool(rule.enabled)

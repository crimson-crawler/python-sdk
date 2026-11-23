from enum import StrEnum


class DistroAdvisoryStatus(StrEnum):
    FIXED = "fixed"
    NEEDS_TRIAGE = "needs_triage"
    NOT_AFFECTED = "not_affected"
    OPEN = "open"
    UNAVAILABLE = "unavailable"

    def __str__(self) -> str:
        return str(self.value)

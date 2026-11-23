from enum import StrEnum


class CSAFProductStateStatus(StrEnum):
    FIRST_FIXED = "first_fixed"
    FIXED = "fixed"
    KNOWN_AFFECTED = "known_affected"
    KNOWN_NOT_AFFECTED = "known_not_affected"
    UNDER_INVESTIGATION = "under_investigation"

    def __str__(self) -> str:
        return str(self.value)

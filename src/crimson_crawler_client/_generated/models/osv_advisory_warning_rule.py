from enum import StrEnum


class OSVAdvisoryWarningRule(StrEnum):
    ADVISORY_TOO_LARGE = "advisory_too_large"
    MALFORMED_FIELD = "malformed_field"

    def __str__(self) -> str:
        return str(self.value)

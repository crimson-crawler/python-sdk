from enum import StrEnum


class SSVCDecisionMissionPrevalenceType0(StrEnum):
    ESSENTIAL = "essential"
    MINIMAL = "minimal"
    SUPPORT = "support"

    def __str__(self) -> str:
        return str(self.value)

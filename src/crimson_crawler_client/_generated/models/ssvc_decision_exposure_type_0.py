from enum import StrEnum


class SSVCDecisionExposureType0(StrEnum):
    CONTROLLED = "controlled"
    OPEN = "open"
    SMALL = "small"

    def __str__(self) -> str:
        return str(self.value)

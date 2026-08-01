from enum import Enum


class SSVCDecisionExposureType0(str, Enum):
    CONTROLLED = "controlled"
    OPEN = "open"
    SMALL = "small"

    def __str__(self) -> str:
        return str(self.value)

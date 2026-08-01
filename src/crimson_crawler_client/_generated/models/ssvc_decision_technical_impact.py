from enum import Enum


class SSVCDecisionTechnicalImpact(str, Enum):
    PARTIAL = "partial"
    TOTAL = "total"

    def __str__(self) -> str:
        return str(self.value)

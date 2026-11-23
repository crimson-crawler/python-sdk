from enum import StrEnum


class SSVCDecisionTechnicalImpact(StrEnum):
    PARTIAL = "partial"
    TOTAL = "total"

    def __str__(self) -> str:
        return str(self.value)

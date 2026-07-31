from enum import Enum


class BatchTechniqueItemFramework(str, Enum):
    ENTERPRISE = "enterprise"
    ICS = "ics"
    MOBILE = "mobile"

    def __str__(self) -> str:
        return str(self.value)

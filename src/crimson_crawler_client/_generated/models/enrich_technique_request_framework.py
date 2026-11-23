from enum import StrEnum


class EnrichTechniqueRequestFramework(StrEnum):
    ENTERPRISE = "enterprise"
    ICS = "ics"
    MOBILE = "mobile"

    def __str__(self) -> str:
        return str(self.value)

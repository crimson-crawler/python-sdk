from enum import StrEnum


class BatchCampaignItemFramework(StrEnum):
    ENTERPRISE = "enterprise"
    ICS = "ics"
    MOBILE = "mobile"

    def __str__(self) -> str:
        return str(self.value)

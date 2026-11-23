from enum import StrEnum


class VulnrichmentStatus(StrEnum):
    AUTH_REQUIRED = "auth_required"
    OK = "ok"
    STALE = "stale"
    TERMS_NOT_ACCEPTED = "terms_not_accepted"
    UNAVAILABLE = "unavailable"

    def __str__(self) -> str:
        return str(self.value)

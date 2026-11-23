from enum import StrEnum


class HashlookupRecordStatus(StrEnum):
    AUTH_REQUIRED = "auth_required"
    OK = "ok"
    TERMS_NOT_ACCEPTED = "terms_not_accepted"
    UNAVAILABLE = "unavailable"

    def __str__(self) -> str:
        return str(self.value)

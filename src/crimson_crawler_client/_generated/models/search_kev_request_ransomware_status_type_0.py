from enum import StrEnum


class SearchKEVRequestRansomwareStatusType0(StrEnum):
    KNOWN = "Known"
    UNKNOWN = "Unknown"

    def __str__(self) -> str:
        return str(self.value)

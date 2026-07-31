from enum import Enum


class SearchKEVRequestRansomwareStatusType0(str, Enum):
    KNOWN = "Known"
    UNKNOWN = "Unknown"

    def __str__(self) -> str:
        return str(self.value)

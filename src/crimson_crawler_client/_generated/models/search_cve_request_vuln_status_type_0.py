from enum import Enum


class SearchCVERequestVulnStatusType0(str, Enum):
    ANALYZED = "Analyzed"
    AWAITING_ANALYSIS = "Awaiting Analysis"
    MODIFIED = "Modified"
    RECEIVED = "Received"
    REJECTED = "Rejected"

    def __str__(self) -> str:
        return str(self.value)

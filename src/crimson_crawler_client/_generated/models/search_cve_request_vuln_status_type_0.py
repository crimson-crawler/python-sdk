from enum import StrEnum


class SearchCVERequestVulnStatusType0(StrEnum):
    ANALYZED = "Analyzed"
    AWAITING_ANALYSIS = "Awaiting Analysis"
    DEFERRED = "Deferred"
    MODIFIED = "Modified"
    RECEIVED = "Received"
    REJECTED = "Rejected"
    UNDERGOING_ANALYSIS = "Undergoing Analysis"

    def __str__(self) -> str:
        return str(self.value)

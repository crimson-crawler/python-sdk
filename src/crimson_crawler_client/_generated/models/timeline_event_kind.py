from enum import Enum


class TimelineEventKind(str, Enum):
    DISCLOSED = "disclosed"
    EPSS_INFLECTION = "epss_inflection"
    KEV_ADDED = "kev_added"
    KEV_DUE = "kev_due"
    POC_FIRST_SEEN = "poc_first_seen"

    def __str__(self) -> str:
        return str(self.value)

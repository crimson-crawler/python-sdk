from enum import Enum


class SSVCDecisionDecision(str, Enum):
    ACT = "act"
    ATTEND = "attend"
    DEFER = "defer"
    IMMEDIATE = "immediate"
    OUT_OF_CYCLE = "out_of_cycle"
    SCHEDULED = "scheduled"
    TRACK = "track"
    TRACK_STAR = "track_star"

    def __str__(self) -> str:
        return str(self.value)

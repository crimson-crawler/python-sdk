from enum import Enum


class CoverageGapKind(str, Enum):
    CHAIN_WALK_EMPTY = "chain_walk_empty"
    LOW_CORROBORATION = "low_corroboration"
    NO_EPSS_DATA = "no_epss_data"
    NO_KEV_RECORD = "no_kev_record"
    NO_TECHNIQUE_MAPPING = "no_technique_mapping"

    def __str__(self) -> str:
        return str(self.value)

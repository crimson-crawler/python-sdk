from enum import StrEnum


class SearchCVERequestSortType0(StrEnum):
    CREATED_ASCENDING = "created_ascending"
    CREATED_DESCENDING = "created_descending"
    EPSS_SCORE_DESCENDING = "epss_score_descending"
    MODIFIED_ASCENDING = "modified_ascending"
    MODIFIED_DESCENDING = "modified_descending"
    X_OPENCTI_CVSS_BASE_SCORE_DESCENDING = "x_opencti_cvss_base_score_descending"

    def __str__(self) -> str:
        return str(self.value)

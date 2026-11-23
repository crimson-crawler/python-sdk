from enum import StrEnum


class SearchD3FENDRequestD3FendFormType0(StrEnum):
    ARTIFACT = "artifact"
    MITIGATION = "mitigation"
    SUB_MITIGATION = "sub-mitigation"
    TACTIC = "tactic"

    def __str__(self) -> str:
        return str(self.value)

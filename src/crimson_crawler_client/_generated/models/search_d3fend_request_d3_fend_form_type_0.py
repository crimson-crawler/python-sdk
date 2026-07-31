from enum import Enum


class SearchD3FENDRequestD3FendFormType0(str, Enum):
    ARTIFACT = "artifact"
    MITIGATION = "mitigation"
    SUB_MITIGATION = "sub-mitigation"
    TACTIC = "tactic"

    def __str__(self) -> str:
        return str(self.value)

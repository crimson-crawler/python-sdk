from enum import StrEnum


class EnrichProductResponseMatchKind(StrEnum):
    CPE = "cpe"
    CPE_FUZZY = "cpe_fuzzy"
    NONE = "none"

    def __str__(self) -> str:
        return str(self.value)

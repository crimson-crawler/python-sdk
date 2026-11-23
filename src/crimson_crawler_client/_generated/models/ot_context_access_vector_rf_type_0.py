from enum import StrEnum


class OTContextAccessVectorRfType0(StrEnum):
    ADJACENT = "adjacent"
    NETWORK = "network"

    def __str__(self) -> str:
        return str(self.value)

from enum import Enum


class EnrichCVERequestTechniquesScope(str, Enum):
    ALL = "all"
    SPECIFIC = "specific"

    def __str__(self) -> str:
        return str(self.value)

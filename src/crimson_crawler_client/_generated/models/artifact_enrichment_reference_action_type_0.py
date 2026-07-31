from enum import Enum


class ArtifactEnrichmentReferenceActionType0(str, Enum):
    BLOCK = "BLOCK"
    INFO = "INFO"
    PATCH = "PATCH"
    WATCH = "WATCH"

    def __str__(self) -> str:
        return str(self.value)

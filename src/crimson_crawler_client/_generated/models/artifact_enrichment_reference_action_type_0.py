from enum import StrEnum


class ArtifactEnrichmentReferenceActionType0(StrEnum):
    BLOCK = "BLOCK"
    INFO = "INFO"
    PATCH = "PATCH"
    WATCH = "WATCH"

    def __str__(self) -> str:
        return str(self.value)

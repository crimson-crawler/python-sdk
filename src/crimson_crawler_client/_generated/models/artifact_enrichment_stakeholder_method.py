from enum import Enum


class ArtifactEnrichmentStakeholderMethod(str, Enum):
    CISA_COORDINATOR = "cisa_coordinator"
    DEPLOYER = "deployer"

    def __str__(self) -> str:
        return str(self.value)

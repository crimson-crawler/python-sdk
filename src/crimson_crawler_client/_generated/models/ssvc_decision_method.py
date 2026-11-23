from enum import StrEnum


class SSVCDecisionMethod(StrEnum):
    CISA_COORDINATOR = "cisa_coordinator"
    DEPLOYER = "deployer"

    def __str__(self) -> str:
        return str(self.value)

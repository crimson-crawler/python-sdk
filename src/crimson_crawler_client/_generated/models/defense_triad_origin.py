from enum import StrEnum


class DefenseTriadOrigin(StrEnum):
    DERIVED = "derived"
    OBSERVED = "observed"

    def __str__(self) -> str:
        return str(self.value)

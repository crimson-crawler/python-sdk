from enum import Enum


class DefenseTriadOrigin(str, Enum):
    DERIVED = "derived"
    OBSERVED = "observed"

    def __str__(self) -> str:
        return str(self.value)

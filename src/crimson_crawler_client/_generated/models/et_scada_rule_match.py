from enum import StrEnum


class ETScadaRuleMatch(StrEnum):
    CVE = "cve"
    PROTOCOL = "protocol"

    def __str__(self) -> str:
        return str(self.value)

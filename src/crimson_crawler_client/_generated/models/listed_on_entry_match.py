from enum import StrEnum


class ListedOnEntryMatch(StrEnum):
    ASN = "asn"
    CIDR = "cidr"
    EXACT = "exact"

    def __str__(self) -> str:
        return str(self.value)

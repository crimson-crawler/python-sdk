from enum import StrEnum


class InventoryAssetFindingMatch(StrEnum):
    CPE = "cpe"
    CPE_FUZZY = "cpe_fuzzy"
    NONE = "none"
    PACKAGE = "package"

    def __str__(self) -> str:
        return str(self.value)

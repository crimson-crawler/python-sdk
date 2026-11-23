from enum import StrEnum


class OTVendorAdvisorySource(StrEnum):
    MEDIATEK = "mediatek"
    ROCKWELL = "rockwell"

    def __str__(self) -> str:
        return str(self.value)

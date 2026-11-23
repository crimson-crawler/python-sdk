from enum import StrEnum


class FixAvailabilityState(StrEnum):
    NO_FIX_PUBLISHED = "no_fix_published"
    UNKNOWN = "unknown"
    VENDOR_FIX = "vendor_fix"

    def __str__(self) -> str:
        return str(self.value)

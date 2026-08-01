from enum import Enum


class ArtifactEnrichmentDocRequestFormatsItem(str, Enum):
    CSAF = "csaf"
    CSV = "csv"
    JSON = "json"
    KEV_REMEDIATION = "kev_remediation"
    MISP = "misp"
    NAVIGATOR = "navigator"
    OSCAL_POAM = "oscal_poam"
    REPORT = "report"
    STIX = "stix"
    VEX = "vex"

    def __str__(self) -> str:
        return str(self.value)

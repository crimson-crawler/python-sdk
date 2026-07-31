from enum import Enum


class ArtifactEnrichmentReferenceType(str, Enum):
    ATLAS = "atlas"
    CAMPAIGN = "campaign"
    CAPEC = "capec"
    CVE = "cve"
    CWE = "cwe"
    DISARM = "disarm"
    GROUP = "group"
    IOC = "ioc"
    PACKAGE = "package"
    PRODUCT = "product"
    SOFTWARE = "software"
    TECHNIQUE = "technique"

    def __str__(self) -> str:
        return str(self.value)

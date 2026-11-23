from enum import StrEnum


class ArtifactEnrichmentReferenceType(StrEnum):
    ATLAS = "atlas"
    CAMPAIGN = "campaign"
    CAPEC = "capec"
    CLOAK = "cloak"
    CVE = "cve"
    CWE = "cwe"
    D3FEND = "d3fend"
    DISARM = "disarm"
    F3 = "f3"
    GROUP = "group"
    IOC = "ioc"
    LOCATION = "location"
    PACKAGE = "package"
    PRODUCT = "product"
    SECTOR = "sector"
    SOFTWARE = "software"
    TECHNIQUE = "technique"

    def __str__(self) -> str:
        return str(self.value)

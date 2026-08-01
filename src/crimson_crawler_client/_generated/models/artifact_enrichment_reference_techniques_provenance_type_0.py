from enum import Enum


class ArtifactEnrichmentReferenceTechniquesProvenanceType0(str, Enum):
    CVE_SPECIFIC = "cve_specific"
    CWE_CLASS = "cwe_class"
    HEURISTIC = "heuristic"

    def __str__(self) -> str:
        return str(self.value)

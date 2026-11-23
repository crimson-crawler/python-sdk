from enum import StrEnum


class ArtifactEnrichmentReferenceTechniquesProvenanceType0(StrEnum):
    CVE_SPECIFIC = "cve_specific"
    CWE_CLASS = "cwe_class"
    CWE_CLOSURE = "cwe_closure"
    HEURISTIC = "heuristic"

    def __str__(self) -> str:
        return str(self.value)

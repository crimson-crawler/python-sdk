from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, BinaryIO, Generator, TextIO, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..models.artifact_enrichment_meta_overall_confidence_type_0 import ArtifactEnrichmentMetaOverallConfidenceType0
from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.artifact_enrichment_meta_extractor_versions import ArtifactEnrichmentMetaExtractorVersions
    from ..models.artifact_enrichment_meta_ref_count_by_type import ArtifactEnrichmentMetaRefCountByType
    from ..models.defense_coverage import DefenseCoverage


T = TypeVar("T", bound="ArtifactEnrichmentMeta")


@_attrs_define
class ArtifactEnrichmentMeta:
    """Report metadata.

    Attributes:
        generated_at (str): ISO 8601 timestamp the report was assembled
        defense_coverage (DefenseCoverage | None | Unset): Report-level defense-readiness rollup (0-100 score +
            detection/mitigation/D3FEND coverage) over every ATT&CK technique in the enrichment. Pairs with the per-
            reference attack scores for a Risk-vs-Readiness read. Null when no references mapped to ATT&CK techniques.
        extractor_versions (ArtifactEnrichmentMetaExtractorVersions | Unset): Version map of the extractors that ran
        overall_confidence (ArtifactEnrichmentMetaOverallConfidenceType0 | None | Unset): Overall analytic confidence
            across the report
        ref_count (int | Unset): Total references in the report Default: 0.
        ref_count_by_type (ArtifactEnrichmentMetaRefCountByType | Unset): Reference count keyed by type
        truncated (bool | Unset): True when the extractor hit a cap and dropped references Default: False.
        unique_nist_controls (list[str] | Unset): Sorted dedup'd set of NIST SP 800-53 rev 5 control IDs (e.g. 'AC-02')
            that mitigate the techniques mapped to references in this report. Aggregated across all references for at-a-
            glance compliance read; sourced from MITRE CTID's curated ATT&CK→NIST mapping.
    """

    generated_at: str
    defense_coverage: DefenseCoverage | None | Unset = UNSET
    extractor_versions: ArtifactEnrichmentMetaExtractorVersions | Unset = UNSET
    overall_confidence: ArtifactEnrichmentMetaOverallConfidenceType0 | None | Unset = UNSET
    ref_count: int | Unset = 0
    ref_count_by_type: ArtifactEnrichmentMetaRefCountByType | Unset = UNSET
    truncated: bool | Unset = False
    unique_nist_controls: list[str] | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        from ..models.artifact_enrichment_meta_extractor_versions import ArtifactEnrichmentMetaExtractorVersions
        from ..models.artifact_enrichment_meta_ref_count_by_type import ArtifactEnrichmentMetaRefCountByType
        from ..models.defense_coverage import DefenseCoverage

        generated_at = self.generated_at

        defense_coverage: dict[str, Any] | None | Unset
        if isinstance(self.defense_coverage, Unset):
            defense_coverage = UNSET
        elif isinstance(self.defense_coverage, DefenseCoverage):
            defense_coverage = self.defense_coverage.to_dict()
        else:
            defense_coverage = self.defense_coverage

        extractor_versions: dict[str, Any] | Unset = UNSET
        if not isinstance(self.extractor_versions, Unset):
            extractor_versions = self.extractor_versions.to_dict()

        overall_confidence: None | str | Unset
        if isinstance(self.overall_confidence, Unset):
            overall_confidence = UNSET
        elif isinstance(self.overall_confidence, ArtifactEnrichmentMetaOverallConfidenceType0):
            overall_confidence = self.overall_confidence.value
        else:
            overall_confidence = self.overall_confidence

        ref_count = self.ref_count

        ref_count_by_type: dict[str, Any] | Unset = UNSET
        if not isinstance(self.ref_count_by_type, Unset):
            ref_count_by_type = self.ref_count_by_type.to_dict()

        truncated = self.truncated

        unique_nist_controls: list[str] | Unset = UNSET
        if not isinstance(self.unique_nist_controls, Unset):
            unique_nist_controls = self.unique_nist_controls

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "generated_at": generated_at,
            }
        )
        if defense_coverage is not UNSET:
            field_dict["defense_coverage"] = defense_coverage
        if extractor_versions is not UNSET:
            field_dict["extractor_versions"] = extractor_versions
        if overall_confidence is not UNSET:
            field_dict["overall_confidence"] = overall_confidence
        if ref_count is not UNSET:
            field_dict["ref_count"] = ref_count
        if ref_count_by_type is not UNSET:
            field_dict["ref_count_by_type"] = ref_count_by_type
        if truncated is not UNSET:
            field_dict["truncated"] = truncated
        if unique_nist_controls is not UNSET:
            field_dict["unique_nist_controls"] = unique_nist_controls

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.artifact_enrichment_meta_extractor_versions import ArtifactEnrichmentMetaExtractorVersions
        from ..models.artifact_enrichment_meta_ref_count_by_type import ArtifactEnrichmentMetaRefCountByType
        from ..models.defense_coverage import DefenseCoverage

        d = dict(src_dict)
        generated_at = d.pop("generated_at")

        def _parse_defense_coverage(data: object) -> DefenseCoverage | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, dict):
                    raise TypeError()
                defense_coverage_type_0 = DefenseCoverage.from_dict(data)

                return defense_coverage_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(DefenseCoverage | None | Unset, data)

        defense_coverage = _parse_defense_coverage(d.pop("defense_coverage", UNSET))

        _extractor_versions = d.pop("extractor_versions", UNSET)
        extractor_versions: ArtifactEnrichmentMetaExtractorVersions | Unset
        if isinstance(_extractor_versions, Unset):
            extractor_versions = UNSET
        else:
            extractor_versions = ArtifactEnrichmentMetaExtractorVersions.from_dict(_extractor_versions)

        def _parse_overall_confidence(data: object) -> ArtifactEnrichmentMetaOverallConfidenceType0 | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, str):
                    raise TypeError()
                overall_confidence_type_0 = ArtifactEnrichmentMetaOverallConfidenceType0(data)

                return overall_confidence_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(ArtifactEnrichmentMetaOverallConfidenceType0 | None | Unset, data)

        overall_confidence = _parse_overall_confidence(d.pop("overall_confidence", UNSET))

        ref_count = d.pop("ref_count", UNSET)

        _ref_count_by_type = d.pop("ref_count_by_type", UNSET)
        ref_count_by_type: ArtifactEnrichmentMetaRefCountByType | Unset
        if isinstance(_ref_count_by_type, Unset):
            ref_count_by_type = UNSET
        else:
            ref_count_by_type = ArtifactEnrichmentMetaRefCountByType.from_dict(_ref_count_by_type)

        truncated = d.pop("truncated", UNSET)

        unique_nist_controls = cast(list[str], d.pop("unique_nist_controls", UNSET))

        artifact_enrichment_meta = cls(
            generated_at=generated_at,
            defense_coverage=defense_coverage,
            extractor_versions=extractor_versions,
            overall_confidence=overall_confidence,
            ref_count=ref_count,
            ref_count_by_type=ref_count_by_type,
            truncated=truncated,
            unique_nist_controls=unique_nist_controls,
        )

        artifact_enrichment_meta.additional_properties = d
        return artifact_enrichment_meta

    @property
    def additional_keys(self) -> list[str]:
        return list(self.additional_properties.keys())

    def __getitem__(self, key: str) -> Any:
        return self.additional_properties[key]

    def __setitem__(self, key: str, value: Any) -> None:
        self.additional_properties[key] = value

    def __delitem__(self, key: str) -> None:
        del self.additional_properties[key]

    def __contains__(self, key: str) -> bool:
        return key in self.additional_properties

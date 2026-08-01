from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, BinaryIO, Generator, TextIO, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..models.source_confidence_statement_overall_confidence import SourceConfidenceStatementOverallConfidence
from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.source_confidence_statement_grade_distribution import SourceConfidenceStatementGradeDistribution


T = TypeVar("T", bound="SourceConfidenceStatement")


@_attrs_define
class SourceConfidenceStatement:
    """Aggregate provenance: Admiralty distribution + overall confidence + caveats.

    Attributes:
        overall_confidence (SourceConfidenceStatementOverallConfidence): Overall analytic confidence across the report
        coverage_caveats (list[str] | Unset): Known coverage gaps (e.g. sparse CAPEC→ATT&CK edges)
        deterministic (bool | Unset): Always true; the judgment path is deterministic Default: True.
        grade_distribution (SourceConfidenceStatementGradeDistribution | Unset): Count of references per Admiralty grade
            (e.g. {'A1': 3, 'B2': 5})
    """

    overall_confidence: SourceConfidenceStatementOverallConfidence
    coverage_caveats: list[str] | Unset = UNSET
    deterministic: bool | Unset = True
    grade_distribution: SourceConfidenceStatementGradeDistribution | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        from ..models.source_confidence_statement_grade_distribution import SourceConfidenceStatementGradeDistribution

        overall_confidence = self.overall_confidence.value

        coverage_caveats: list[str] | Unset = UNSET
        if not isinstance(self.coverage_caveats, Unset):
            coverage_caveats = self.coverage_caveats

        deterministic = self.deterministic

        grade_distribution: dict[str, Any] | Unset = UNSET
        if not isinstance(self.grade_distribution, Unset):
            grade_distribution = self.grade_distribution.to_dict()

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "overall_confidence": overall_confidence,
            }
        )
        if coverage_caveats is not UNSET:
            field_dict["coverage_caveats"] = coverage_caveats
        if deterministic is not UNSET:
            field_dict["deterministic"] = deterministic
        if grade_distribution is not UNSET:
            field_dict["grade_distribution"] = grade_distribution

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.source_confidence_statement_grade_distribution import SourceConfidenceStatementGradeDistribution

        d = dict(src_dict)
        overall_confidence = SourceConfidenceStatementOverallConfidence(d.pop("overall_confidence"))

        coverage_caveats = cast(list[str], d.pop("coverage_caveats", UNSET))

        deterministic = d.pop("deterministic", UNSET)

        _grade_distribution = d.pop("grade_distribution", UNSET)
        grade_distribution: SourceConfidenceStatementGradeDistribution | Unset
        if isinstance(_grade_distribution, Unset):
            grade_distribution = UNSET
        else:
            grade_distribution = SourceConfidenceStatementGradeDistribution.from_dict(_grade_distribution)

        source_confidence_statement = cls(
            overall_confidence=overall_confidence,
            coverage_caveats=coverage_caveats,
            deterministic=deterministic,
            grade_distribution=grade_distribution,
        )

        source_confidence_statement.additional_properties = d
        return source_confidence_statement

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

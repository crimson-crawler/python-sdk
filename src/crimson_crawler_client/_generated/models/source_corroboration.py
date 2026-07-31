from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, BinaryIO, Generator, TextIO, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..models.source_corroboration_overall_confidence import SourceCorroborationOverallConfidence
from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.source_contribution import SourceContribution
    from ..models.source_corroboration_grade_distribution import SourceCorroborationGradeDistribution


T = TypeVar("T", bound="SourceCorroboration")


@_attrs_define
class SourceCorroboration:
    """Per-source contribution matrix + analytic-confidence rollup.

    Attributes:
        caveats (list[str] | Unset): Known coverage gaps / corroboration caveats (legacy string form)
        contributions (list[SourceContribution] | Unset): Per-source contribution rows
        grade_distribution (SourceCorroborationGradeDistribution | Unset): Count of references per Admiralty grade
        overall_confidence (SourceCorroborationOverallConfidence | Unset): Aggregate analytic confidence Default:
            SourceCorroborationOverallConfidence.LOW.
    """

    caveats: list[str] | Unset = UNSET
    contributions: list[SourceContribution] | Unset = UNSET
    grade_distribution: SourceCorroborationGradeDistribution | Unset = UNSET
    overall_confidence: SourceCorroborationOverallConfidence | Unset = SourceCorroborationOverallConfidence.LOW
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        from ..models.source_contribution import SourceContribution
        from ..models.source_corroboration_grade_distribution import SourceCorroborationGradeDistribution

        caveats: list[str] | Unset = UNSET
        if not isinstance(self.caveats, Unset):
            caveats = self.caveats

        contributions: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.contributions, Unset):
            contributions = []
            for contributions_item_data in self.contributions:
                contributions_item = contributions_item_data.to_dict()
                contributions.append(contributions_item)

        grade_distribution: dict[str, Any] | Unset = UNSET
        if not isinstance(self.grade_distribution, Unset):
            grade_distribution = self.grade_distribution.to_dict()

        overall_confidence: str | Unset = UNSET
        if not isinstance(self.overall_confidence, Unset):
            overall_confidence = self.overall_confidence.value

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if caveats is not UNSET:
            field_dict["caveats"] = caveats
        if contributions is not UNSET:
            field_dict["contributions"] = contributions
        if grade_distribution is not UNSET:
            field_dict["grade_distribution"] = grade_distribution
        if overall_confidence is not UNSET:
            field_dict["overall_confidence"] = overall_confidence

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.source_contribution import SourceContribution
        from ..models.source_corroboration_grade_distribution import SourceCorroborationGradeDistribution

        d = dict(src_dict)
        caveats = cast(list[str], d.pop("caveats", UNSET))

        _contributions = d.pop("contributions", UNSET)
        contributions: list[SourceContribution] | Unset = UNSET
        if _contributions is not UNSET:
            contributions = []
            for contributions_item_data in _contributions:
                contributions_item = SourceContribution.from_dict(contributions_item_data)

                contributions.append(contributions_item)

        _grade_distribution = d.pop("grade_distribution", UNSET)
        grade_distribution: SourceCorroborationGradeDistribution | Unset
        if isinstance(_grade_distribution, Unset):
            grade_distribution = UNSET
        else:
            grade_distribution = SourceCorroborationGradeDistribution.from_dict(_grade_distribution)

        _overall_confidence = d.pop("overall_confidence", UNSET)
        overall_confidence: SourceCorroborationOverallConfidence | Unset
        if isinstance(_overall_confidence, Unset):
            overall_confidence = UNSET
        else:
            overall_confidence = SourceCorroborationOverallConfidence(_overall_confidence)

        source_corroboration = cls(
            caveats=caveats,
            contributions=contributions,
            grade_distribution=grade_distribution,
            overall_confidence=overall_confidence,
        )

        source_corroboration.additional_properties = d
        return source_corroboration

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

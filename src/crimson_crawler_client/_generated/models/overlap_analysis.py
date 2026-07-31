from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, BinaryIO, Generator, TextIO, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.overlap_analysis_tactic_coverage_per_group import OverlapAnalysisTacticCoveragePerGroup
    from ..models.overlap_analysis_unique_per_group import OverlapAnalysisUniquePerGroup


T = TypeVar("T", bound="OverlapAnalysis")


@_attrs_define
class OverlapAnalysis:
    """Technique and tactic overlap between multiple threat groups.

    Attributes:
        combined_unique (int | Unset): Total unique techniques across all groups Default: 0.
        shared_count (int | Unset): Number of shared techniques Default: 0.
        shared_tactics (list[str] | Unset): ATT&CK tactics shared by all groups
        shared_techniques (list[str] | Unset): Technique IDs shared by all assessed groups
        tactic_coverage_per_group (OverlapAnalysisTacticCoveragePerGroup | Unset): Kill-chain tactics each group covers
        unique_per_group (OverlapAnalysisUniquePerGroup | Unset): Unique technique count per group
    """

    combined_unique: int | Unset = 0
    shared_count: int | Unset = 0
    shared_tactics: list[str] | Unset = UNSET
    shared_techniques: list[str] | Unset = UNSET
    tactic_coverage_per_group: OverlapAnalysisTacticCoveragePerGroup | Unset = UNSET
    unique_per_group: OverlapAnalysisUniquePerGroup | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        from ..models.overlap_analysis_tactic_coverage_per_group import OverlapAnalysisTacticCoveragePerGroup
        from ..models.overlap_analysis_unique_per_group import OverlapAnalysisUniquePerGroup

        combined_unique = self.combined_unique

        shared_count = self.shared_count

        shared_tactics: list[str] | Unset = UNSET
        if not isinstance(self.shared_tactics, Unset):
            shared_tactics = self.shared_tactics

        shared_techniques: list[str] | Unset = UNSET
        if not isinstance(self.shared_techniques, Unset):
            shared_techniques = self.shared_techniques

        tactic_coverage_per_group: dict[str, Any] | Unset = UNSET
        if not isinstance(self.tactic_coverage_per_group, Unset):
            tactic_coverage_per_group = self.tactic_coverage_per_group.to_dict()

        unique_per_group: dict[str, Any] | Unset = UNSET
        if not isinstance(self.unique_per_group, Unset):
            unique_per_group = self.unique_per_group.to_dict()

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if combined_unique is not UNSET:
            field_dict["combined_unique"] = combined_unique
        if shared_count is not UNSET:
            field_dict["shared_count"] = shared_count
        if shared_tactics is not UNSET:
            field_dict["shared_tactics"] = shared_tactics
        if shared_techniques is not UNSET:
            field_dict["shared_techniques"] = shared_techniques
        if tactic_coverage_per_group is not UNSET:
            field_dict["tactic_coverage_per_group"] = tactic_coverage_per_group
        if unique_per_group is not UNSET:
            field_dict["unique_per_group"] = unique_per_group

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.overlap_analysis_tactic_coverage_per_group import OverlapAnalysisTacticCoveragePerGroup
        from ..models.overlap_analysis_unique_per_group import OverlapAnalysisUniquePerGroup

        d = dict(src_dict)
        combined_unique = d.pop("combined_unique", UNSET)

        shared_count = d.pop("shared_count", UNSET)

        shared_tactics = cast(list[str], d.pop("shared_tactics", UNSET))

        shared_techniques = cast(list[str], d.pop("shared_techniques", UNSET))

        _tactic_coverage_per_group = d.pop("tactic_coverage_per_group", UNSET)
        tactic_coverage_per_group: OverlapAnalysisTacticCoveragePerGroup | Unset
        if isinstance(_tactic_coverage_per_group, Unset):
            tactic_coverage_per_group = UNSET
        else:
            tactic_coverage_per_group = OverlapAnalysisTacticCoveragePerGroup.from_dict(_tactic_coverage_per_group)

        _unique_per_group = d.pop("unique_per_group", UNSET)
        unique_per_group: OverlapAnalysisUniquePerGroup | Unset
        if isinstance(_unique_per_group, Unset):
            unique_per_group = UNSET
        else:
            unique_per_group = OverlapAnalysisUniquePerGroup.from_dict(_unique_per_group)

        overlap_analysis = cls(
            combined_unique=combined_unique,
            shared_count=shared_count,
            shared_tactics=shared_tactics,
            shared_techniques=shared_techniques,
            tactic_coverage_per_group=tactic_coverage_per_group,
            unique_per_group=unique_per_group,
        )

        overlap_analysis.additional_properties = d
        return overlap_analysis

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

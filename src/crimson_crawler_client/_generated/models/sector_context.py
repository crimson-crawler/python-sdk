from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, BinaryIO, Generator, TextIO, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="SectorContext")


@_attrs_define
class SectorContext:
    """Evidence-based industry sector detection from threat group targeting patterns.

    Attributes:
        additional_sectors (list[str] | Unset): Other detected sectors beyond the primary
        evidence_score (float | Unset): Evidence strength (0.0-1.0) Default: 0.0.
        relevant_techniques (list[str] | Unset): CVE techniques used by sector-targeting groups
        sector_id (str | Unset): Sector identifier Default: ''.
        sector_name (str | Unset): Sector display name Default: ''.
        targeting_groups (list[str] | Unset): Threat groups that target this sector and use the CVE's techniques
    """

    additional_sectors: list[str] | Unset = UNSET
    evidence_score: float | Unset = 0.0
    relevant_techniques: list[str] | Unset = UNSET
    sector_id: str | Unset = ""
    sector_name: str | Unset = ""
    targeting_groups: list[str] | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        additional_sectors: list[str] | Unset = UNSET
        if not isinstance(self.additional_sectors, Unset):
            additional_sectors = self.additional_sectors

        evidence_score = self.evidence_score

        relevant_techniques: list[str] | Unset = UNSET
        if not isinstance(self.relevant_techniques, Unset):
            relevant_techniques = self.relevant_techniques

        sector_id = self.sector_id

        sector_name = self.sector_name

        targeting_groups: list[str] | Unset = UNSET
        if not isinstance(self.targeting_groups, Unset):
            targeting_groups = self.targeting_groups

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if additional_sectors is not UNSET:
            field_dict["additional_sectors"] = additional_sectors
        if evidence_score is not UNSET:
            field_dict["evidence_score"] = evidence_score
        if relevant_techniques is not UNSET:
            field_dict["relevant_techniques"] = relevant_techniques
        if sector_id is not UNSET:
            field_dict["sector_id"] = sector_id
        if sector_name is not UNSET:
            field_dict["sector_name"] = sector_name
        if targeting_groups is not UNSET:
            field_dict["targeting_groups"] = targeting_groups

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        additional_sectors = cast(list[str], d.pop("additional_sectors", UNSET))

        evidence_score = d.pop("evidence_score", UNSET)

        relevant_techniques = cast(list[str], d.pop("relevant_techniques", UNSET))

        sector_id = d.pop("sector_id", UNSET)

        sector_name = d.pop("sector_name", UNSET)

        targeting_groups = cast(list[str], d.pop("targeting_groups", UNSET))

        sector_context = cls(
            additional_sectors=additional_sectors,
            evidence_score=evidence_score,
            relevant_techniques=relevant_techniques,
            sector_id=sector_id,
            sector_name=sector_name,
            targeting_groups=targeting_groups,
        )

        sector_context.additional_properties = d
        return sector_context

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

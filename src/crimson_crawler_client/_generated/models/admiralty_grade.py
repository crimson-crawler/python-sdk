from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, BinaryIO, Generator, TextIO, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..models.admiralty_grade_credibility import AdmiraltyGradeCredibility
from ..models.admiralty_grade_reliability import AdmiraltyGradeReliability
from ..types import UNSET, Unset

T = TypeVar("T", bound="AdmiraltyGrade")


@_attrs_define
class AdmiraltyGrade:
    """NATO Admiralty / source-reliability grading (STANAG 2511).

    Source reliability (A-F) and information credibility (1-6) follow the NATO Admiralty System.
    Grades are assigned deterministically from the source type.

        Attributes:
            credibility (AdmiraltyGradeCredibility): Information credibility: 1=confirmed … 6=cannot be judged
            reliability (AdmiraltyGradeReliability): Source reliability: A=completely reliable … F=cannot be judged
            rationale (None | str | Unset): Deterministic justification for the grade
    """

    credibility: AdmiraltyGradeCredibility
    reliability: AdmiraltyGradeReliability
    rationale: None | str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        credibility = self.credibility.value

        reliability = self.reliability.value

        rationale: None | str | Unset
        if isinstance(self.rationale, Unset):
            rationale = UNSET
        else:
            rationale = self.rationale

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "credibility": credibility,
                "reliability": reliability,
            }
        )
        if rationale is not UNSET:
            field_dict["rationale"] = rationale

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        credibility = AdmiraltyGradeCredibility(d.pop("credibility"))

        reliability = AdmiraltyGradeReliability(d.pop("reliability"))

        def _parse_rationale(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        rationale = _parse_rationale(d.pop("rationale", UNSET))

        admiralty_grade = cls(
            credibility=credibility,
            reliability=reliability,
            rationale=rationale,
        )

        admiralty_grade.additional_properties = d
        return admiralty_grade

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

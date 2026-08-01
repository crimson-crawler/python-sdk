from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, BinaryIO, Generator, TextIO, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="CoverageScore")


@_attrs_define
class CoverageScore:
    """Technique coverage analysis: what percentage have mitigations and detections.

    Attributes:
        detected_count (int | Unset): Techniques with detections Default: 0.
        detection_pct (float | Unset): Percentage of techniques with at least one detection Default: 0.0.
        mitigated_count (int | Unset): Techniques with mitigations Default: 0.
        mitigation_pct (float | Unset): Percentage of techniques with at least one mitigation Default: 0.0.
        total_techniques (int | Unset): Total techniques assessed Default: 0.
        uncovered_techniques (list[str] | Unset): Technique IDs with neither mitigation nor detection
    """

    detected_count: int | Unset = 0
    detection_pct: float | Unset = 0.0
    mitigated_count: int | Unset = 0
    mitigation_pct: float | Unset = 0.0
    total_techniques: int | Unset = 0
    uncovered_techniques: list[str] | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        detected_count = self.detected_count

        detection_pct = self.detection_pct

        mitigated_count = self.mitigated_count

        mitigation_pct = self.mitigation_pct

        total_techniques = self.total_techniques

        uncovered_techniques: list[str] | Unset = UNSET
        if not isinstance(self.uncovered_techniques, Unset):
            uncovered_techniques = self.uncovered_techniques

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if detected_count is not UNSET:
            field_dict["detected_count"] = detected_count
        if detection_pct is not UNSET:
            field_dict["detection_pct"] = detection_pct
        if mitigated_count is not UNSET:
            field_dict["mitigated_count"] = mitigated_count
        if mitigation_pct is not UNSET:
            field_dict["mitigation_pct"] = mitigation_pct
        if total_techniques is not UNSET:
            field_dict["total_techniques"] = total_techniques
        if uncovered_techniques is not UNSET:
            field_dict["uncovered_techniques"] = uncovered_techniques

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        detected_count = d.pop("detected_count", UNSET)

        detection_pct = d.pop("detection_pct", UNSET)

        mitigated_count = d.pop("mitigated_count", UNSET)

        mitigation_pct = d.pop("mitigation_pct", UNSET)

        total_techniques = d.pop("total_techniques", UNSET)

        uncovered_techniques = cast(list[str], d.pop("uncovered_techniques", UNSET))

        coverage_score = cls(
            detected_count=detected_count,
            detection_pct=detection_pct,
            mitigated_count=mitigated_count,
            mitigation_pct=mitigation_pct,
            total_techniques=total_techniques,
            uncovered_techniques=uncovered_techniques,
        )

        coverage_score.additional_properties = d
        return coverage_score

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

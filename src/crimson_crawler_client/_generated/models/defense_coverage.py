from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, BinaryIO, Generator, TextIO, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="DefenseCoverage")


@_attrs_define
class DefenseCoverage:
    """Report-level defense-readiness rollup over every ATT&CK technique in the enrichment.

    The symmetric counterpart to the attack/weaponization scores. Built on the MITRE
    ATT&CK coverage methodology — per-technique detection / mitigation / D3FEND coverage,
    detection weighted highest. ``score`` is 0-100 (higher = better defended).

        Attributes:
            score (float): 0-100 defense score (0.50·detection + 0.35·mitigation + 0.15·D3FEND)
            d3fend_pct (float | Unset): % of techniques with at least one D3FEND countermeasure Default: 0.0.
            detection_pct (float | Unset): % of techniques with at least one ATT&CK detection Default: 0.0.
            mitigation_pct (float | Unset): % of techniques with at least one ATT&CK mitigation Default: 0.0.
            techniques_covered (int | Unset): Techniques covered by at least one defensive lever Default: 0.
            techniques_total (int | Unset): Distinct ATT&CK techniques across the report Default: 0.
            techniques_truncated (int | Unset): Count of distinct techniques that exceeded the per-enrichment defense-lookup
                cap and have NO defense triad — so the score/percentages above cover only the first N. 0 = full coverage. Non-
                zero means this rollup is partial; surfaced so a high score isn't read as complete. Default: 0.
            uncovered_techniques (list[str] | Unset): Technique IDs with no detection/mitigation/D3FEND
    """

    score: float
    d3fend_pct: float | Unset = 0.0
    detection_pct: float | Unset = 0.0
    mitigation_pct: float | Unset = 0.0
    techniques_covered: int | Unset = 0
    techniques_total: int | Unset = 0
    techniques_truncated: int | Unset = 0
    uncovered_techniques: list[str] | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        score = self.score

        d3fend_pct = self.d3fend_pct

        detection_pct = self.detection_pct

        mitigation_pct = self.mitigation_pct

        techniques_covered = self.techniques_covered

        techniques_total = self.techniques_total

        techniques_truncated = self.techniques_truncated

        uncovered_techniques: list[str] | Unset = UNSET
        if not isinstance(self.uncovered_techniques, Unset):
            uncovered_techniques = self.uncovered_techniques

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "score": score,
            }
        )
        if d3fend_pct is not UNSET:
            field_dict["d3fend_pct"] = d3fend_pct
        if detection_pct is not UNSET:
            field_dict["detection_pct"] = detection_pct
        if mitigation_pct is not UNSET:
            field_dict["mitigation_pct"] = mitigation_pct
        if techniques_covered is not UNSET:
            field_dict["techniques_covered"] = techniques_covered
        if techniques_total is not UNSET:
            field_dict["techniques_total"] = techniques_total
        if techniques_truncated is not UNSET:
            field_dict["techniques_truncated"] = techniques_truncated
        if uncovered_techniques is not UNSET:
            field_dict["uncovered_techniques"] = uncovered_techniques

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        score = d.pop("score")

        d3fend_pct = d.pop("d3fend_pct", UNSET)

        detection_pct = d.pop("detection_pct", UNSET)

        mitigation_pct = d.pop("mitigation_pct", UNSET)

        techniques_covered = d.pop("techniques_covered", UNSET)

        techniques_total = d.pop("techniques_total", UNSET)

        techniques_truncated = d.pop("techniques_truncated", UNSET)

        uncovered_techniques = cast(list[str], d.pop("uncovered_techniques", UNSET))

        defense_coverage = cls(
            score=score,
            d3fend_pct=d3fend_pct,
            detection_pct=detection_pct,
            mitigation_pct=mitigation_pct,
            techniques_covered=techniques_covered,
            techniques_total=techniques_total,
            techniques_truncated=techniques_truncated,
            uncovered_techniques=uncovered_techniques,
        )

        defense_coverage.additional_properties = d
        return defense_coverage

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

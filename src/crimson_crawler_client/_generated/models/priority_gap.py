from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, BinaryIO, Generator, TextIO, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="PriorityGap")


@_attrs_define
class PriorityGap:
    """An uncovered technique ranked by 5-signal composite score.

    Attributes:
        cve_count (int | Unset): Number of linked CVEs Default: 0.
        detection_feasibility (str | Unset): Detection feasibility: easy, moderate, difficult, or unknown Default:
            'unknown'.
        gap_score (float | Unset): Composite priority score Default: 0.0.
        group_count (int | Unset): Number of threat groups using this technique Default: 0.
        group_prevalence (int | Unset): Corpus-wide distinct groups using this technique (applies +0.1×min(count/5, 1)
            boost) Default: 0.
        has_kev_cves (bool | Unset): Linked CVEs include actively exploited entries Default: False.
        in_active_campaign (bool | Unset): True when the technique appears in recent MISP campaign tags (applies ×1.3
            boost) Default: False.
        kev_linked_count (int | Unset): Count of KEV-listed CVEs linked to this technique (log-scaled boost to
            gap_score) Default: 0.
        name (str | Unset): Technique name Default: ''.
        reason (str | Unset): Human-readable explanation of the priority ranking Default: ''.
        technique_id (str | Unset): ATT&CK technique ID Default: ''.
        top_tactic (str | Unset): Highest-severity ATT&CK tactic for this technique Default: ''.
    """

    cve_count: int | Unset = 0
    detection_feasibility: str | Unset = "unknown"
    gap_score: float | Unset = 0.0
    group_count: int | Unset = 0
    group_prevalence: int | Unset = 0
    has_kev_cves: bool | Unset = False
    in_active_campaign: bool | Unset = False
    kev_linked_count: int | Unset = 0
    name: str | Unset = ""
    reason: str | Unset = ""
    technique_id: str | Unset = ""
    top_tactic: str | Unset = ""
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        cve_count = self.cve_count

        detection_feasibility = self.detection_feasibility

        gap_score = self.gap_score

        group_count = self.group_count

        group_prevalence = self.group_prevalence

        has_kev_cves = self.has_kev_cves

        in_active_campaign = self.in_active_campaign

        kev_linked_count = self.kev_linked_count

        name = self.name

        reason = self.reason

        technique_id = self.technique_id

        top_tactic = self.top_tactic

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if cve_count is not UNSET:
            field_dict["cve_count"] = cve_count
        if detection_feasibility is not UNSET:
            field_dict["detection_feasibility"] = detection_feasibility
        if gap_score is not UNSET:
            field_dict["gap_score"] = gap_score
        if group_count is not UNSET:
            field_dict["group_count"] = group_count
        if group_prevalence is not UNSET:
            field_dict["group_prevalence"] = group_prevalence
        if has_kev_cves is not UNSET:
            field_dict["has_kev_cves"] = has_kev_cves
        if in_active_campaign is not UNSET:
            field_dict["in_active_campaign"] = in_active_campaign
        if kev_linked_count is not UNSET:
            field_dict["kev_linked_count"] = kev_linked_count
        if name is not UNSET:
            field_dict["name"] = name
        if reason is not UNSET:
            field_dict["reason"] = reason
        if technique_id is not UNSET:
            field_dict["technique_id"] = technique_id
        if top_tactic is not UNSET:
            field_dict["top_tactic"] = top_tactic

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        cve_count = d.pop("cve_count", UNSET)

        detection_feasibility = d.pop("detection_feasibility", UNSET)

        gap_score = d.pop("gap_score", UNSET)

        group_count = d.pop("group_count", UNSET)

        group_prevalence = d.pop("group_prevalence", UNSET)

        has_kev_cves = d.pop("has_kev_cves", UNSET)

        in_active_campaign = d.pop("in_active_campaign", UNSET)

        kev_linked_count = d.pop("kev_linked_count", UNSET)

        name = d.pop("name", UNSET)

        reason = d.pop("reason", UNSET)

        technique_id = d.pop("technique_id", UNSET)

        top_tactic = d.pop("top_tactic", UNSET)

        priority_gap = cls(
            cve_count=cve_count,
            detection_feasibility=detection_feasibility,
            gap_score=gap_score,
            group_count=group_count,
            group_prevalence=group_prevalence,
            has_kev_cves=has_kev_cves,
            in_active_campaign=in_active_campaign,
            kev_linked_count=kev_linked_count,
            name=name,
            reason=reason,
            technique_id=technique_id,
            top_tactic=top_tactic,
        )

        priority_gap.additional_properties = d
        return priority_gap

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

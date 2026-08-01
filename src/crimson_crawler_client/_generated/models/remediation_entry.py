from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, BinaryIO, Generator, TextIO, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="RemediationEntry")


@_attrs_define
class RemediationEntry:
    """Prioritized CVE remediation entry.

    Attributes:
        cve_id (str): CVE identifier
        active_exploitation_multiplier (float | Unset): Multiplier: 1.0 + 0.5 if KEV + 0.3 if EPSS velocity >50 + 0.2 if
            recent MISP event Default: 1.0.
        adjusted_priority_score (float | Unset): Final priority score after active-exploitation multiplier and
            compensating-controls downrank Default: 0.0.
        effort (str | Unset): Estimated remediation effort: quick_fix, moderate, major_change, or unknown Default:
            'unknown'.
        has_compensating_controls (bool | Unset): True when every linked technique has detection data (applies a ×0.85
            downrank) Default: False.
        priority_rank (int | Unset): Priority order (1=most urgent) Default: 0.
        reason (str | Unset): Why this CVE is prioritized Default: ''.
        weaponization_score (float | Unset): Risk score Default: 0.0.
    """

    cve_id: str
    active_exploitation_multiplier: float | Unset = 1.0
    adjusted_priority_score: float | Unset = 0.0
    effort: str | Unset = "unknown"
    has_compensating_controls: bool | Unset = False
    priority_rank: int | Unset = 0
    reason: str | Unset = ""
    weaponization_score: float | Unset = 0.0
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        cve_id = self.cve_id

        active_exploitation_multiplier = self.active_exploitation_multiplier

        adjusted_priority_score = self.adjusted_priority_score

        effort = self.effort

        has_compensating_controls = self.has_compensating_controls

        priority_rank = self.priority_rank

        reason = self.reason

        weaponization_score = self.weaponization_score

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "cve_id": cve_id,
            }
        )
        if active_exploitation_multiplier is not UNSET:
            field_dict["active_exploitation_multiplier"] = active_exploitation_multiplier
        if adjusted_priority_score is not UNSET:
            field_dict["adjusted_priority_score"] = adjusted_priority_score
        if effort is not UNSET:
            field_dict["effort"] = effort
        if has_compensating_controls is not UNSET:
            field_dict["has_compensating_controls"] = has_compensating_controls
        if priority_rank is not UNSET:
            field_dict["priority_rank"] = priority_rank
        if reason is not UNSET:
            field_dict["reason"] = reason
        if weaponization_score is not UNSET:
            field_dict["weaponization_score"] = weaponization_score

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        cve_id = d.pop("cve_id")

        active_exploitation_multiplier = d.pop("active_exploitation_multiplier", UNSET)

        adjusted_priority_score = d.pop("adjusted_priority_score", UNSET)

        effort = d.pop("effort", UNSET)

        has_compensating_controls = d.pop("has_compensating_controls", UNSET)

        priority_rank = d.pop("priority_rank", UNSET)

        reason = d.pop("reason", UNSET)

        weaponization_score = d.pop("weaponization_score", UNSET)

        remediation_entry = cls(
            cve_id=cve_id,
            active_exploitation_multiplier=active_exploitation_multiplier,
            adjusted_priority_score=adjusted_priority_score,
            effort=effort,
            has_compensating_controls=has_compensating_controls,
            priority_rank=priority_rank,
            reason=reason,
            weaponization_score=weaponization_score,
        )

        remediation_entry.additional_properties = d
        return remediation_entry

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

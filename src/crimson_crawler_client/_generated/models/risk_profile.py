from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, BinaryIO, Generator, TextIO, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="RiskProfile")


@_attrs_define
class RiskProfile:
    """Threat group damage potential based on linked CVEs and technique capabilities.

    Attributes:
        avg_cve_severity (float | None | Unset): Average CVSS score of exploitable CVEs
        avg_weaponization (float | None | Unset): Average weaponization score across exploitable CVEs
        exploitable_cve_count (int | Unset): CVEs exploitable via this group's techniques Default: 0.
        initial_access_techniques (int | Unset): Techniques enabling initial access Default: 0.
        kev_cve_count (int | Unset): Exploitable CVEs in the KEV catalog Default: 0.
        kev_pct (float | Unset): Percentage of exploitable CVEs in KEV Default: 0.0.
        lateral_movement_techniques (int | Unset): Techniques enabling lateral movement Default: 0.
        max_weaponization (float | None | Unset): Highest weaponization score among exploitable CVEs
        privilege_escalation_techniques (int | Unset): Techniques enabling privilege escalation Default: 0.
    """

    avg_cve_severity: float | None | Unset = UNSET
    avg_weaponization: float | None | Unset = UNSET
    exploitable_cve_count: int | Unset = 0
    initial_access_techniques: int | Unset = 0
    kev_cve_count: int | Unset = 0
    kev_pct: float | Unset = 0.0
    lateral_movement_techniques: int | Unset = 0
    max_weaponization: float | None | Unset = UNSET
    privilege_escalation_techniques: int | Unset = 0
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        avg_cve_severity: float | None | Unset
        if isinstance(self.avg_cve_severity, Unset):
            avg_cve_severity = UNSET
        else:
            avg_cve_severity = self.avg_cve_severity

        avg_weaponization: float | None | Unset
        if isinstance(self.avg_weaponization, Unset):
            avg_weaponization = UNSET
        else:
            avg_weaponization = self.avg_weaponization

        exploitable_cve_count = self.exploitable_cve_count

        initial_access_techniques = self.initial_access_techniques

        kev_cve_count = self.kev_cve_count

        kev_pct = self.kev_pct

        lateral_movement_techniques = self.lateral_movement_techniques

        max_weaponization: float | None | Unset
        if isinstance(self.max_weaponization, Unset):
            max_weaponization = UNSET
        else:
            max_weaponization = self.max_weaponization

        privilege_escalation_techniques = self.privilege_escalation_techniques

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if avg_cve_severity is not UNSET:
            field_dict["avg_cve_severity"] = avg_cve_severity
        if avg_weaponization is not UNSET:
            field_dict["avg_weaponization"] = avg_weaponization
        if exploitable_cve_count is not UNSET:
            field_dict["exploitable_cve_count"] = exploitable_cve_count
        if initial_access_techniques is not UNSET:
            field_dict["initial_access_techniques"] = initial_access_techniques
        if kev_cve_count is not UNSET:
            field_dict["kev_cve_count"] = kev_cve_count
        if kev_pct is not UNSET:
            field_dict["kev_pct"] = kev_pct
        if lateral_movement_techniques is not UNSET:
            field_dict["lateral_movement_techniques"] = lateral_movement_techniques
        if max_weaponization is not UNSET:
            field_dict["max_weaponization"] = max_weaponization
        if privilege_escalation_techniques is not UNSET:
            field_dict["privilege_escalation_techniques"] = privilege_escalation_techniques

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)

        def _parse_avg_cve_severity(data: object) -> float | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(float | None | Unset, data)

        avg_cve_severity = _parse_avg_cve_severity(d.pop("avg_cve_severity", UNSET))

        def _parse_avg_weaponization(data: object) -> float | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(float | None | Unset, data)

        avg_weaponization = _parse_avg_weaponization(d.pop("avg_weaponization", UNSET))

        exploitable_cve_count = d.pop("exploitable_cve_count", UNSET)

        initial_access_techniques = d.pop("initial_access_techniques", UNSET)

        kev_cve_count = d.pop("kev_cve_count", UNSET)

        kev_pct = d.pop("kev_pct", UNSET)

        lateral_movement_techniques = d.pop("lateral_movement_techniques", UNSET)

        def _parse_max_weaponization(data: object) -> float | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(float | None | Unset, data)

        max_weaponization = _parse_max_weaponization(d.pop("max_weaponization", UNSET))

        privilege_escalation_techniques = d.pop("privilege_escalation_techniques", UNSET)

        risk_profile = cls(
            avg_cve_severity=avg_cve_severity,
            avg_weaponization=avg_weaponization,
            exploitable_cve_count=exploitable_cve_count,
            initial_access_techniques=initial_access_techniques,
            kev_cve_count=kev_cve_count,
            kev_pct=kev_pct,
            lateral_movement_techniques=lateral_movement_techniques,
            max_weaponization=max_weaponization,
            privilege_escalation_techniques=privilege_escalation_techniques,
        )

        risk_profile.additional_properties = d
        return risk_profile

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

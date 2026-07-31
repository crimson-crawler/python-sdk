from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, BinaryIO, Generator, TextIO, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.risk_summary_top_cwes_item import RiskSummaryTopCwesItem
    from ..models.risk_summary_top_techniques_item import RiskSummaryTopTechniquesItem


T = TypeVar("T", bound="RiskSummary")


@_attrs_define
class RiskSummary:
    """Aggregate risk statistics across multiple CVEs.

    Attributes:
        avg_weaponization (float | None | Unset): Average weaponization score
        critical (int | Unset): Critical severity count Default: 0.
        high (int | Unset): High severity count Default: 0.
        in_kev_count (int | Unset): CVEs in KEV catalog Default: 0.
        in_kev_pct (float | Unset): Percentage in KEV Default: 0.0.
        low (int | Unset): Low severity count Default: 0.
        max_weaponization (float | None | Unset): Maximum weaponization score
        medium (int | Unset): Medium severity count Default: 0.
        none (int | Unset): No severity count Default: 0.
        top_cwes (list[RiskSummaryTopCwesItem] | Unset): Most common weaknesses across CVEs
        top_techniques (list[RiskSummaryTopTechniquesItem] | Unset): Most common techniques across CVEs
        total_cves (int | Unset): Total CVE count Default: 0.
    """

    avg_weaponization: float | None | Unset = UNSET
    critical: int | Unset = 0
    high: int | Unset = 0
    in_kev_count: int | Unset = 0
    in_kev_pct: float | Unset = 0.0
    low: int | Unset = 0
    max_weaponization: float | None | Unset = UNSET
    medium: int | Unset = 0
    none: int | Unset = 0
    top_cwes: list[RiskSummaryTopCwesItem] | Unset = UNSET
    top_techniques: list[RiskSummaryTopTechniquesItem] | Unset = UNSET
    total_cves: int | Unset = 0
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        from ..models.risk_summary_top_cwes_item import RiskSummaryTopCwesItem
        from ..models.risk_summary_top_techniques_item import RiskSummaryTopTechniquesItem

        avg_weaponization: float | None | Unset
        if isinstance(self.avg_weaponization, Unset):
            avg_weaponization = UNSET
        else:
            avg_weaponization = self.avg_weaponization

        critical = self.critical

        high = self.high

        in_kev_count = self.in_kev_count

        in_kev_pct = self.in_kev_pct

        low = self.low

        max_weaponization: float | None | Unset
        if isinstance(self.max_weaponization, Unset):
            max_weaponization = UNSET
        else:
            max_weaponization = self.max_weaponization

        medium = self.medium

        none = self.none

        top_cwes: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.top_cwes, Unset):
            top_cwes = []
            for top_cwes_item_data in self.top_cwes:
                top_cwes_item = top_cwes_item_data.to_dict()
                top_cwes.append(top_cwes_item)

        top_techniques: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.top_techniques, Unset):
            top_techniques = []
            for top_techniques_item_data in self.top_techniques:
                top_techniques_item = top_techniques_item_data.to_dict()
                top_techniques.append(top_techniques_item)

        total_cves = self.total_cves

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if avg_weaponization is not UNSET:
            field_dict["avg_weaponization"] = avg_weaponization
        if critical is not UNSET:
            field_dict["critical"] = critical
        if high is not UNSET:
            field_dict["high"] = high
        if in_kev_count is not UNSET:
            field_dict["in_kev_count"] = in_kev_count
        if in_kev_pct is not UNSET:
            field_dict["in_kev_pct"] = in_kev_pct
        if low is not UNSET:
            field_dict["low"] = low
        if max_weaponization is not UNSET:
            field_dict["max_weaponization"] = max_weaponization
        if medium is not UNSET:
            field_dict["medium"] = medium
        if none is not UNSET:
            field_dict["none"] = none
        if top_cwes is not UNSET:
            field_dict["top_cwes"] = top_cwes
        if top_techniques is not UNSET:
            field_dict["top_techniques"] = top_techniques
        if total_cves is not UNSET:
            field_dict["total_cves"] = total_cves

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.risk_summary_top_cwes_item import RiskSummaryTopCwesItem
        from ..models.risk_summary_top_techniques_item import RiskSummaryTopTechniquesItem

        d = dict(src_dict)

        def _parse_avg_weaponization(data: object) -> float | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(float | None | Unset, data)

        avg_weaponization = _parse_avg_weaponization(d.pop("avg_weaponization", UNSET))

        critical = d.pop("critical", UNSET)

        high = d.pop("high", UNSET)

        in_kev_count = d.pop("in_kev_count", UNSET)

        in_kev_pct = d.pop("in_kev_pct", UNSET)

        low = d.pop("low", UNSET)

        def _parse_max_weaponization(data: object) -> float | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(float | None | Unset, data)

        max_weaponization = _parse_max_weaponization(d.pop("max_weaponization", UNSET))

        medium = d.pop("medium", UNSET)

        none = d.pop("none", UNSET)

        _top_cwes = d.pop("top_cwes", UNSET)
        top_cwes: list[RiskSummaryTopCwesItem] | Unset = UNSET
        if _top_cwes is not UNSET:
            top_cwes = []
            for top_cwes_item_data in _top_cwes:
                top_cwes_item = RiskSummaryTopCwesItem.from_dict(top_cwes_item_data)

                top_cwes.append(top_cwes_item)

        _top_techniques = d.pop("top_techniques", UNSET)
        top_techniques: list[RiskSummaryTopTechniquesItem] | Unset = UNSET
        if _top_techniques is not UNSET:
            top_techniques = []
            for top_techniques_item_data in _top_techniques:
                top_techniques_item = RiskSummaryTopTechniquesItem.from_dict(top_techniques_item_data)

                top_techniques.append(top_techniques_item)

        total_cves = d.pop("total_cves", UNSET)

        risk_summary = cls(
            avg_weaponization=avg_weaponization,
            critical=critical,
            high=high,
            in_kev_count=in_kev_count,
            in_kev_pct=in_kev_pct,
            low=low,
            max_weaponization=max_weaponization,
            medium=medium,
            none=none,
            top_cwes=top_cwes,
            top_techniques=top_techniques,
            total_cves=total_cves,
        )

        risk_summary.additional_properties = d
        return risk_summary

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

from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, BinaryIO, Generator, TextIO, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.inventory_rollup_criticality_counts import InventoryRollupCriticalityCounts


T = TypeVar("T", bound="InventoryRollup")


@_attrs_define
class InventoryRollup:
    """Aggregate rollup across the whole assessed inventory.

    Attributes:
        asset_count (int | Unset): Number of assets assessed Default: 0.
        assets_with_fix_available (int | Unset): Assets with a recommended upgrade target (a published fix clears ≥1 of
            their CVEs) Default: 0.
        criticality_counts (InventoryRollupCriticalityCounts | Unset): Asset count by criticality
        max_weaponization (float | None | Unset): Highest weaponization score across the inventory
        top_kev_cves (list[str] | Unset): Distinct KEV-listed CVE IDs across the inventory (≤25)
        total_advisories (int | Unset): Sum of per-asset non-CVE OSV advisory counts (GHSA/PYSEC/…) Default: 0.
        total_cves (int | Unset): Sum of per-asset distinct CVE counts Default: 0.
        total_kev (int | Unset): Sum of per-asset KEV counts Default: 0.
    """

    asset_count: int | Unset = 0
    assets_with_fix_available: int | Unset = 0
    criticality_counts: InventoryRollupCriticalityCounts | Unset = UNSET
    max_weaponization: float | None | Unset = UNSET
    top_kev_cves: list[str] | Unset = UNSET
    total_advisories: int | Unset = 0
    total_cves: int | Unset = 0
    total_kev: int | Unset = 0
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        from ..models.inventory_rollup_criticality_counts import InventoryRollupCriticalityCounts

        asset_count = self.asset_count

        assets_with_fix_available = self.assets_with_fix_available

        criticality_counts: dict[str, Any] | Unset = UNSET
        if not isinstance(self.criticality_counts, Unset):
            criticality_counts = self.criticality_counts.to_dict()

        max_weaponization: float | None | Unset
        if isinstance(self.max_weaponization, Unset):
            max_weaponization = UNSET
        else:
            max_weaponization = self.max_weaponization

        top_kev_cves: list[str] | Unset = UNSET
        if not isinstance(self.top_kev_cves, Unset):
            top_kev_cves = self.top_kev_cves

        total_advisories = self.total_advisories

        total_cves = self.total_cves

        total_kev = self.total_kev

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if asset_count is not UNSET:
            field_dict["asset_count"] = asset_count
        if assets_with_fix_available is not UNSET:
            field_dict["assets_with_fix_available"] = assets_with_fix_available
        if criticality_counts is not UNSET:
            field_dict["criticality_counts"] = criticality_counts
        if max_weaponization is not UNSET:
            field_dict["max_weaponization"] = max_weaponization
        if top_kev_cves is not UNSET:
            field_dict["top_kev_cves"] = top_kev_cves
        if total_advisories is not UNSET:
            field_dict["total_advisories"] = total_advisories
        if total_cves is not UNSET:
            field_dict["total_cves"] = total_cves
        if total_kev is not UNSET:
            field_dict["total_kev"] = total_kev

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.inventory_rollup_criticality_counts import InventoryRollupCriticalityCounts

        d = dict(src_dict)
        asset_count = d.pop("asset_count", UNSET)

        assets_with_fix_available = d.pop("assets_with_fix_available", UNSET)

        _criticality_counts = d.pop("criticality_counts", UNSET)
        criticality_counts: InventoryRollupCriticalityCounts | Unset
        if isinstance(_criticality_counts, Unset):
            criticality_counts = UNSET
        else:
            criticality_counts = InventoryRollupCriticalityCounts.from_dict(_criticality_counts)

        def _parse_max_weaponization(data: object) -> float | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(float | None | Unset, data)

        max_weaponization = _parse_max_weaponization(d.pop("max_weaponization", UNSET))

        top_kev_cves = cast(list[str], d.pop("top_kev_cves", UNSET))

        total_advisories = d.pop("total_advisories", UNSET)

        total_cves = d.pop("total_cves", UNSET)

        total_kev = d.pop("total_kev", UNSET)

        inventory_rollup = cls(
            asset_count=asset_count,
            assets_with_fix_available=assets_with_fix_available,
            criticality_counts=criticality_counts,
            max_weaponization=max_weaponization,
            top_kev_cves=top_kev_cves,
            total_advisories=total_advisories,
            total_cves=total_cves,
            total_kev=total_kev,
        )

        inventory_rollup.additional_properties = d
        return inventory_rollup

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

from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, BinaryIO, Generator, TextIO, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="RelatedAssetClass")


@_attrs_define
class RelatedAssetClass:
    """An ICS asset class MITRE lists as related to another one.

    `x_mitre_related_assets` entries are objects carrying their own description and sectors, not
    bare names (18-asset corpus: 15 assets carry entries, each with `description` +
    `related_asset_sectors`).

        Attributes:
            description (str | Unset): MITRE's description of that asset class Default: ''.
            name (str | Unset): Related asset class name (e.g. 'Operator Workstation (OWS)') Default: ''.
            sectors (list[str] | Unset): Sectors that related asset appears in (related_asset_sectors)
    """

    description: str | Unset = ""
    name: str | Unset = ""
    sectors: list[str] | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        description = self.description

        name = self.name

        sectors: list[str] | Unset = UNSET
        if not isinstance(self.sectors, Unset):
            sectors = self.sectors

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if description is not UNSET:
            field_dict["description"] = description
        if name is not UNSET:
            field_dict["name"] = name
        if sectors is not UNSET:
            field_dict["sectors"] = sectors

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        description = d.pop("description", UNSET)

        name = d.pop("name", UNSET)

        sectors = cast(list[str], d.pop("sectors", UNSET))

        related_asset_class = cls(
            description=description,
            name=name,
            sectors=sectors,
        )

        related_asset_class.additional_properties = d
        return related_asset_class

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

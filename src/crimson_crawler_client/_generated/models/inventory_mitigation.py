from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, BinaryIO, Generator, TextIO, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="InventoryMitigation")


@_attrs_define
class InventoryMitigation:
    """A linked ATT&CK mitigation (course of action) on an inventory CVE.

    Attributes:
        description (str | Unset): Mitigation guidance (truncated) Default: ''.
        id (str | Unset): ATT&CK mitigation id (e.g. M1048) Default: ''.
        name (str | Unset): Mitigation name Default: ''.
        url (str | Unset): Mitigation reference URL Default: ''.
    """

    description: str | Unset = ""
    id: str | Unset = ""
    name: str | Unset = ""
    url: str | Unset = ""
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        description = self.description

        id = self.id

        name = self.name

        url = self.url

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if description is not UNSET:
            field_dict["description"] = description
        if id is not UNSET:
            field_dict["id"] = id
        if name is not UNSET:
            field_dict["name"] = name
        if url is not UNSET:
            field_dict["url"] = url

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        description = d.pop("description", UNSET)

        id = d.pop("id", UNSET)

        name = d.pop("name", UNSET)

        url = d.pop("url", UNSET)

        inventory_mitigation = cls(
            description=description,
            id=id,
            name=name,
            url=url,
        )

        inventory_mitigation.additional_properties = d
        return inventory_mitigation

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

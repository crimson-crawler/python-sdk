from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, BinaryIO, Generator, TextIO, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="HierarchyRef")


@_attrs_define
class HierarchyRef:
    """One node of a location / sector hierarchy (a parent region or parent sector).

    Attributes:
        id (str | Unset): Identifier of the related node (e.g. 'americas', 'technologies') Default: ''.
        name (str | Unset): Node name (e.g. 'Americas', 'Technologies') Default: ''.
        type_ (str | Unset): Node type (location type or STIX identity_class) Default: ''.
        url (str | Unset): Reference URL Default: ''.
    """

    id: str | Unset = ""
    name: str | Unset = ""
    type_: str | Unset = ""
    url: str | Unset = ""
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        id = self.id

        name = self.name

        type_ = self.type_

        url = self.url

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if id is not UNSET:
            field_dict["id"] = id
        if name is not UNSET:
            field_dict["name"] = name
        if type_ is not UNSET:
            field_dict["type"] = type_
        if url is not UNSET:
            field_dict["url"] = url

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        id = d.pop("id", UNSET)

        name = d.pop("name", UNSET)

        type_ = d.pop("type", UNSET)

        url = d.pop("url", UNSET)

        hierarchy_ref = cls(
            id=id,
            name=name,
            type_=type_,
            url=url,
        )

        hierarchy_ref.additional_properties = d
        return hierarchy_ref

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

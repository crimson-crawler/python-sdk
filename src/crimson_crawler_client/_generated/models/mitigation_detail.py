from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, BinaryIO, Generator, TextIO, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="MitigationDetail")


@_attrs_define
class MitigationDetail:
    """ATT&CK mitigation - a course of action to prevent or detect a technique.

    Attributes:
        description (str | Unset): How this mitigation addresses the technique Default: ''.
        mitigation_id (str | Unset): ATT&CK mitigation ID (e.g. M1036) Default: ''.
        name (str | Unset): Mitigation name Default: ''.
        stix_id (str | Unset): Unique object identifier for cross-referencing Default: ''.
        url (str | Unset): Reference URL Default: ''.
    """

    description: str | Unset = ""
    mitigation_id: str | Unset = ""
    name: str | Unset = ""
    stix_id: str | Unset = ""
    url: str | Unset = ""
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        description = self.description

        mitigation_id = self.mitigation_id

        name = self.name

        stix_id = self.stix_id

        url = self.url

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if description is not UNSET:
            field_dict["description"] = description
        if mitigation_id is not UNSET:
            field_dict["mitigation_id"] = mitigation_id
        if name is not UNSET:
            field_dict["name"] = name
        if stix_id is not UNSET:
            field_dict["stix_id"] = stix_id
        if url is not UNSET:
            field_dict["url"] = url

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        description = d.pop("description", UNSET)

        mitigation_id = d.pop("mitigation_id", UNSET)

        name = d.pop("name", UNSET)

        stix_id = d.pop("stix_id", UNSET)

        url = d.pop("url", UNSET)

        mitigation_detail = cls(
            description=description,
            mitigation_id=mitigation_id,
            name=name,
            stix_id=stix_id,
            url=url,
        )

        mitigation_detail.additional_properties = d
        return mitigation_detail

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

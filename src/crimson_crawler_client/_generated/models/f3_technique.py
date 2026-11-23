from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, BinaryIO, Generator, TextIO, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="F3Technique")


@_attrs_define
class F3Technique:
    """A MITRE F3 (Fight Fraud Framework) technique that shares an ATT&CK technique's own id.

    Attributes:
        name (str | Unset): F3 technique name Default: ''.
        object_id (str | Unset): F3 framework id (e.g. 'F1031') Default: ''.
        url (str | Unset): F3 reference URL Default: ''.
    """

    name: str | Unset = ""
    object_id: str | Unset = ""
    url: str | Unset = ""
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        name = self.name

        object_id = self.object_id

        url = self.url

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if name is not UNSET:
            field_dict["name"] = name
        if object_id is not UNSET:
            field_dict["object_id"] = object_id
        if url is not UNSET:
            field_dict["url"] = url

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        name = d.pop("name", UNSET)

        object_id = d.pop("object_id", UNSET)

        url = d.pop("url", UNSET)

        f3_technique = cls(
            name=name,
            object_id=object_id,
            url=url,
        )

        f3_technique.additional_properties = d
        return f3_technique

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

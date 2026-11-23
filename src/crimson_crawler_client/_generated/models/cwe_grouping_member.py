from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, BinaryIO, Generator, TextIO, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="CWEGroupingMember")


@_attrs_define
class CWEGroupingMember:
    """One member of a CWE Category/View, in the grouping's own declared order.

    Attributes:
        cwe_id (str | Unset): CWE id of the member (e.g. 'CWE-79') Default: ''.
        kind (str | Unset): What the member is in the catalogue: weakness, category, or view Default: ''.
        name (str | Unset): Member title Default: ''.
    """

    cwe_id: str | Unset = ""
    kind: str | Unset = ""
    name: str | Unset = ""
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        cwe_id = self.cwe_id

        kind = self.kind

        name = self.name

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if cwe_id is not UNSET:
            field_dict["cwe_id"] = cwe_id
        if kind is not UNSET:
            field_dict["kind"] = kind
        if name is not UNSET:
            field_dict["name"] = name

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        cwe_id = d.pop("cwe_id", UNSET)

        kind = d.pop("kind", UNSET)

        name = d.pop("name", UNSET)

        cwe_grouping_member = cls(
            cwe_id=cwe_id,
            kind=kind,
            name=name,
        )

        cwe_grouping_member.additional_properties = d
        return cwe_grouping_member

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

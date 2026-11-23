from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, BinaryIO, Generator, TextIO, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="CWEGrouping")


@_attrs_define
class CWEGrouping:
    """A CWE Category or View a weakness belongs to (MITRE's own grouping layer).

    Attributes:
        description (None | str | Unset): Grouping description, when the catalogue carries one
        grouping_id (str | Unset): Grouping CWE id (e.g. 'CWE-1396' for a Category, 'CWE-699' for a View) Default: ''.
        name (str | Unset): Grouping title (e.g. 'Comprehensive Categorization: Access Control') Default: ''.
    """

    description: None | str | Unset = UNSET
    grouping_id: str | Unset = ""
    name: str | Unset = ""
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        description: None | str | Unset
        if isinstance(self.description, Unset):
            description = UNSET
        else:
            description = self.description

        grouping_id = self.grouping_id

        name = self.name

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if description is not UNSET:
            field_dict["description"] = description
        if grouping_id is not UNSET:
            field_dict["grouping_id"] = grouping_id
        if name is not UNSET:
            field_dict["name"] = name

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)

        def _parse_description(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        description = _parse_description(d.pop("description", UNSET))

        grouping_id = d.pop("grouping_id", UNSET)

        name = d.pop("name", UNSET)

        cwe_grouping = cls(
            description=description,
            grouping_id=grouping_id,
            name=name,
        )

        cwe_grouping.additional_properties = d
        return cwe_grouping

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

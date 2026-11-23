from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, BinaryIO, Generator, TextIO, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="MISPTag")


@_attrs_define
class MISPTag:
    """A tag attached to a MISP event, with the parts `tag_names` cannot carry.

    `MISPEvent.tag_names` / `MISPAttribute.tags` list just the names; this carries the metadata
    that changes how a tag behaves — whether it points at a galaxy cluster, its weight in scoring
    taxonomies, and the relationship it expresses to the object.

        Attributes:
            colour (str | Unset): MISP's display colour for this tag (hex, e.g. '#ffffff') Default: ''.
            exportable (bool | Unset): Whether the tag is shared when the object is exported Default: False.
            is_galaxy (bool | Unset): Whether this tag refers to a galaxy cluster Default: False.
            local (bool | Unset): Whether the tag is local to this instance Default: False.
            name (str | Unset): Tag name (e.g. 'tlp:white') Default: ''.
            numerical_value (int | None | Unset): Numeric weight used by scoring taxonomies
            relationship_type (str | Unset): Relationship this tag expresses to the tagged object Default: ''.
    """

    colour: str | Unset = ""
    exportable: bool | Unset = False
    is_galaxy: bool | Unset = False
    local: bool | Unset = False
    name: str | Unset = ""
    numerical_value: int | None | Unset = UNSET
    relationship_type: str | Unset = ""
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        colour = self.colour

        exportable = self.exportable

        is_galaxy = self.is_galaxy

        local = self.local

        name = self.name

        numerical_value: int | None | Unset
        if isinstance(self.numerical_value, Unset):
            numerical_value = UNSET
        else:
            numerical_value = self.numerical_value

        relationship_type = self.relationship_type

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if colour is not UNSET:
            field_dict["colour"] = colour
        if exportable is not UNSET:
            field_dict["exportable"] = exportable
        if is_galaxy is not UNSET:
            field_dict["is_galaxy"] = is_galaxy
        if local is not UNSET:
            field_dict["local"] = local
        if name is not UNSET:
            field_dict["name"] = name
        if numerical_value is not UNSET:
            field_dict["numerical_value"] = numerical_value
        if relationship_type is not UNSET:
            field_dict["relationship_type"] = relationship_type

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        colour = d.pop("colour", UNSET)

        exportable = d.pop("exportable", UNSET)

        is_galaxy = d.pop("is_galaxy", UNSET)

        local = d.pop("local", UNSET)

        name = d.pop("name", UNSET)

        def _parse_numerical_value(data: object) -> int | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(int | None | Unset, data)

        numerical_value = _parse_numerical_value(d.pop("numerical_value", UNSET))

        relationship_type = d.pop("relationship_type", UNSET)

        misp_tag = cls(
            colour=colour,
            exportable=exportable,
            is_galaxy=is_galaxy,
            local=local,
            name=name,
            numerical_value=numerical_value,
            relationship_type=relationship_type,
        )

        misp_tag.additional_properties = d
        return misp_tag

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

from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, BinaryIO, Generator, TextIO, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="MISPSighting")


@_attrs_define
class MISPSighting:
    """One MISP sighting record for an attribute (observation, false-positive, or expiration).

    Attributes:
        attribute_id (str | Unset): Attribute this sighting is on Default: ''.
        date_sighting (str | Unset): Sighting timestamp (Unix or ISO) Default: ''.
        event_id (str | Unset): Parent event ID Default: ''.
        id (str | Unset): Sighting ID Default: ''.
        org (str | Unset): Organization that reported the sighting Default: ''.
        source (str | Unset): Sighting source label Default: ''.
        type_ (str | Unset): Sighting type: 0=sighting, 1=false-positive, 2=expiration Default: ''.
    """

    attribute_id: str | Unset = ""
    date_sighting: str | Unset = ""
    event_id: str | Unset = ""
    id: str | Unset = ""
    org: str | Unset = ""
    source: str | Unset = ""
    type_: str | Unset = ""
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        attribute_id = self.attribute_id

        date_sighting = self.date_sighting

        event_id = self.event_id

        id = self.id

        org = self.org

        source = self.source

        type_ = self.type_

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if attribute_id is not UNSET:
            field_dict["attribute_id"] = attribute_id
        if date_sighting is not UNSET:
            field_dict["date_sighting"] = date_sighting
        if event_id is not UNSET:
            field_dict["event_id"] = event_id
        if id is not UNSET:
            field_dict["id"] = id
        if org is not UNSET:
            field_dict["org"] = org
        if source is not UNSET:
            field_dict["source"] = source
        if type_ is not UNSET:
            field_dict["type"] = type_

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        attribute_id = d.pop("attribute_id", UNSET)

        date_sighting = d.pop("date_sighting", UNSET)

        event_id = d.pop("event_id", UNSET)

        id = d.pop("id", UNSET)

        org = d.pop("org", UNSET)

        source = d.pop("source", UNSET)

        type_ = d.pop("type", UNSET)

        misp_sighting = cls(
            attribute_id=attribute_id,
            date_sighting=date_sighting,
            event_id=event_id,
            id=id,
            org=org,
            source=source,
            type_=type_,
        )

        misp_sighting.additional_properties = d
        return misp_sighting

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

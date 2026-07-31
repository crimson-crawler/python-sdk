from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, BinaryIO, Generator, TextIO, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="MISPRelatedAttribute")


@_attrs_define
class MISPRelatedAttribute:
    """Cross-event occurrence of the same indicator value, with parent-event context.

    Attributes:
        attribute_id (str | Unset): MISP attribute ID of the correlated match Default: ''.
        category (str | Unset): Attribute category Default: ''.
        event_id (str | Unset): Event ID containing the correlated match Default: ''.
        event_info (str | Unset): Event title of the correlated match Default: ''.
        type_ (str | Unset): Attribute type Default: ''.
        uuid (str | Unset): Attribute UUID Default: ''.
        value (str | Unset): Correlated attribute value Default: ''.
    """

    attribute_id: str | Unset = ""
    category: str | Unset = ""
    event_id: str | Unset = ""
    event_info: str | Unset = ""
    type_: str | Unset = ""
    uuid: str | Unset = ""
    value: str | Unset = ""
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        attribute_id = self.attribute_id

        category = self.category

        event_id = self.event_id

        event_info = self.event_info

        type_ = self.type_

        uuid = self.uuid

        value = self.value

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if attribute_id is not UNSET:
            field_dict["attribute_id"] = attribute_id
        if category is not UNSET:
            field_dict["category"] = category
        if event_id is not UNSET:
            field_dict["event_id"] = event_id
        if event_info is not UNSET:
            field_dict["event_info"] = event_info
        if type_ is not UNSET:
            field_dict["type"] = type_
        if uuid is not UNSET:
            field_dict["uuid"] = uuid
        if value is not UNSET:
            field_dict["value"] = value

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        attribute_id = d.pop("attribute_id", UNSET)

        category = d.pop("category", UNSET)

        event_id = d.pop("event_id", UNSET)

        event_info = d.pop("event_info", UNSET)

        type_ = d.pop("type", UNSET)

        uuid = d.pop("uuid", UNSET)

        value = d.pop("value", UNSET)

        misp_related_attribute = cls(
            attribute_id=attribute_id,
            category=category,
            event_id=event_id,
            event_info=event_info,
            type_=type_,
            uuid=uuid,
            value=value,
        )

        misp_related_attribute.additional_properties = d
        return misp_related_attribute

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

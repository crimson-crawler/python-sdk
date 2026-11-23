from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, BinaryIO, Generator, TextIO, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="MISPObjectReferenceTarget")


@_attrs_define
class MISPObjectReferenceTarget:
    """The thing an object reference points AT — resolved in-payload or by one bounded read.

    `kind` is the discriminator: fields a kind does not carry stay empty rather than absent, so a
    consumer reads one shape for both. `target_state` on the reference says whether this block is
    present because MISP stated it or because a lookup confirmed it.

        Attributes:
            category (str | Unset): Attribute targets: attribute category Default: ''.
            kind (str | Unset): 'object' or 'attribute' — which id space `uuid` lives in Default: ''.
            meta_category (str | Unset): Object targets: meta-category Default: ''.
            name (str | Unset): Object targets: the object's name Default: ''.
            type_ (str | Unset): Attribute targets: attribute type Default: ''.
            uuid (str | Unset): Target UUID Default: ''.
            value (str | Unset): Attribute targets: the attribute value Default: ''.
    """

    category: str | Unset = ""
    kind: str | Unset = ""
    meta_category: str | Unset = ""
    name: str | Unset = ""
    type_: str | Unset = ""
    uuid: str | Unset = ""
    value: str | Unset = ""
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        category = self.category

        kind = self.kind

        meta_category = self.meta_category

        name = self.name

        type_ = self.type_

        uuid = self.uuid

        value = self.value

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if category is not UNSET:
            field_dict["category"] = category
        if kind is not UNSET:
            field_dict["kind"] = kind
        if meta_category is not UNSET:
            field_dict["meta_category"] = meta_category
        if name is not UNSET:
            field_dict["name"] = name
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
        category = d.pop("category", UNSET)

        kind = d.pop("kind", UNSET)

        meta_category = d.pop("meta_category", UNSET)

        name = d.pop("name", UNSET)

        type_ = d.pop("type", UNSET)

        uuid = d.pop("uuid", UNSET)

        value = d.pop("value", UNSET)

        misp_object_reference_target = cls(
            category=category,
            kind=kind,
            meta_category=meta_category,
            name=name,
            type_=type_,
            uuid=uuid,
            value=value,
        )

        misp_object_reference_target.additional_properties = d
        return misp_object_reference_target

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

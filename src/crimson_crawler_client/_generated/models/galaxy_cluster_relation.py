from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, BinaryIO, Generator, TextIO, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="GalaxyClusterRelation")


@_attrs_define
class GalaxyClusterRelation:
    """One MISP Galaxy cluster relation — typed pointer to a related cluster.

    Attributes:
        target_uuid (str | Unset): Referenced cluster UUID Default: ''.
        type_ (str | Unset): Relation type / referenced cluster type Default: ''.
    """

    target_uuid: str | Unset = ""
    type_: str | Unset = ""
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        target_uuid = self.target_uuid

        type_ = self.type_

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if target_uuid is not UNSET:
            field_dict["target_uuid"] = target_uuid
        if type_ is not UNSET:
            field_dict["type"] = type_

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        target_uuid = d.pop("target_uuid", UNSET)

        type_ = d.pop("type", UNSET)

        galaxy_cluster_relation = cls(
            target_uuid=target_uuid,
            type_=type_,
        )

        galaxy_cluster_relation.additional_properties = d
        return galaxy_cluster_relation

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

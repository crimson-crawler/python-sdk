from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, BinaryIO, Generator, TextIO, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="GalaxyClusterRelation")


@_attrs_define
class GalaxyClusterRelation:
    """One MISP Galaxy cluster relation — a typed pointer to a related cluster.

    MISP publishes the same edge from both ends and names the OTHER end in each list, so the
    direction is readable from which end is populated: a `relations` row is outbound (this cluster
    → `target_uuid`), an `inbound_relations` row is inbound (`source_uuid` → this cluster). The
    raw inbound row echoes THIS cluster's uuid in its `referenced_galaxy_cluster_*` keys, so the
    two lists are not interchangeable and neither end can be read off the other's fields.

        Attributes:
            source_id (str | Unset): `inbound_relations` rows: that source cluster's numeric id in this instance Default:
                ''.
            source_uuid (str | Unset): `inbound_relations` rows: uuid of the cluster that points at this one Default: ''.
            target_uuid (str | Unset): `relations` rows: uuid of the cluster this one points at Default: ''.
            type_ (str | Unset): Relation type (e.g. 'similar', 'variant-of', 'targets') Default: ''.
    """

    source_id: str | Unset = ""
    source_uuid: str | Unset = ""
    target_uuid: str | Unset = ""
    type_: str | Unset = ""
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        source_id = self.source_id

        source_uuid = self.source_uuid

        target_uuid = self.target_uuid

        type_ = self.type_

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if source_id is not UNSET:
            field_dict["source_id"] = source_id
        if source_uuid is not UNSET:
            field_dict["source_uuid"] = source_uuid
        if target_uuid is not UNSET:
            field_dict["target_uuid"] = target_uuid
        if type_ is not UNSET:
            field_dict["type"] = type_

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        source_id = d.pop("source_id", UNSET)

        source_uuid = d.pop("source_uuid", UNSET)

        target_uuid = d.pop("target_uuid", UNSET)

        type_ = d.pop("type", UNSET)

        galaxy_cluster_relation = cls(
            source_id=source_id,
            source_uuid=source_uuid,
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

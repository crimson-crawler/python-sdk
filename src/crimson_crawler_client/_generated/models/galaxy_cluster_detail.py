from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, BinaryIO, Generator, TextIO, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.galaxy_cluster_detail_meta import GalaxyClusterDetailMeta
    from ..models.galaxy_cluster_relation import GalaxyClusterRelation


T = TypeVar("T", bound="GalaxyClusterDetail")


@_attrs_define
class GalaxyClusterDetail:
    """Standalone MISP Galaxy cluster (threat-actor / malware / tool / technique).

    Attributes:
        description (str | Unset): Cluster description Default: ''.
        id (str | Unset): Cluster numeric ID Default: ''.
        meta (GalaxyClusterDetailMeta | Unset): Raw cluster metadata (refs, sectors, country, etc.)
        relations (list[GalaxyClusterRelation] | Unset): Relations to other galaxy clusters
        source (str | Unset): Cluster source Default: ''.
        synonyms (list[str] | Unset): Known aliases for this cluster value
        tag_name (str | Unset): MISP tag string identifying this cluster Default: ''.
        type_ (str | Unset): Cluster type (e.g. 'threat-actor', 'malware', 'mitre-attack') Default: ''.
        uuid (str | Unset): Cluster UUID Default: ''.
        value (str | Unset): Cluster value (e.g. 'APT28', 'Emotet') Default: ''.
    """

    description: str | Unset = ""
    id: str | Unset = ""
    meta: GalaxyClusterDetailMeta | Unset = UNSET
    relations: list[GalaxyClusterRelation] | Unset = UNSET
    source: str | Unset = ""
    synonyms: list[str] | Unset = UNSET
    tag_name: str | Unset = ""
    type_: str | Unset = ""
    uuid: str | Unset = ""
    value: str | Unset = ""
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        from ..models.galaxy_cluster_detail_meta import GalaxyClusterDetailMeta
        from ..models.galaxy_cluster_relation import GalaxyClusterRelation

        description = self.description

        id = self.id

        meta: dict[str, Any] | Unset = UNSET
        if not isinstance(self.meta, Unset):
            meta = self.meta.to_dict()

        relations: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.relations, Unset):
            relations = []
            for relations_item_data in self.relations:
                relations_item = relations_item_data.to_dict()
                relations.append(relations_item)

        source = self.source

        synonyms: list[str] | Unset = UNSET
        if not isinstance(self.synonyms, Unset):
            synonyms = self.synonyms

        tag_name = self.tag_name

        type_ = self.type_

        uuid = self.uuid

        value = self.value

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if description is not UNSET:
            field_dict["description"] = description
        if id is not UNSET:
            field_dict["id"] = id
        if meta is not UNSET:
            field_dict["meta"] = meta
        if relations is not UNSET:
            field_dict["relations"] = relations
        if source is not UNSET:
            field_dict["source"] = source
        if synonyms is not UNSET:
            field_dict["synonyms"] = synonyms
        if tag_name is not UNSET:
            field_dict["tag_name"] = tag_name
        if type_ is not UNSET:
            field_dict["type"] = type_
        if uuid is not UNSET:
            field_dict["uuid"] = uuid
        if value is not UNSET:
            field_dict["value"] = value

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.galaxy_cluster_detail_meta import GalaxyClusterDetailMeta
        from ..models.galaxy_cluster_relation import GalaxyClusterRelation

        d = dict(src_dict)
        description = d.pop("description", UNSET)

        id = d.pop("id", UNSET)

        _meta = d.pop("meta", UNSET)
        meta: GalaxyClusterDetailMeta | Unset
        if isinstance(_meta, Unset):
            meta = UNSET
        else:
            meta = GalaxyClusterDetailMeta.from_dict(_meta)

        _relations = d.pop("relations", UNSET)
        relations: list[GalaxyClusterRelation] | Unset = UNSET
        if _relations is not UNSET:
            relations = []
            for relations_item_data in _relations:
                relations_item = GalaxyClusterRelation.from_dict(relations_item_data)

                relations.append(relations_item)

        source = d.pop("source", UNSET)

        synonyms = cast(list[str], d.pop("synonyms", UNSET))

        tag_name = d.pop("tag_name", UNSET)

        type_ = d.pop("type", UNSET)

        uuid = d.pop("uuid", UNSET)

        value = d.pop("value", UNSET)

        galaxy_cluster_detail = cls(
            description=description,
            id=id,
            meta=meta,
            relations=relations,
            source=source,
            synonyms=synonyms,
            tag_name=tag_name,
            type_=type_,
            uuid=uuid,
            value=value,
        )

        galaxy_cluster_detail.additional_properties = d
        return galaxy_cluster_detail

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

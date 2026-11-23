from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, BinaryIO, Generator, TextIO, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.galaxy_cluster_detail_meta import GalaxyClusterDetailMeta
    from ..models.galaxy_cluster_relation import GalaxyClusterRelation
    from ..models.galaxy_parent import GalaxyParent


T = TypeVar("T", bound="GalaxyClusterDetail")


@_attrs_define
class GalaxyClusterDetail:
    """Standalone MISP Galaxy cluster (threat-actor / malware / tool / technique).

    Attributes:
        authors (list[str] | Unset): Cluster authors
        description (str | Unset): Cluster description Default: ''.
        galaxy (GalaxyParent | Unset): The Galaxy a cluster belongs to — its name, namespace and kill-chain ordering.
        id (str | Unset): Cluster numeric ID Default: ''.
        inbound_relations (list[GalaxyClusterRelation] | Unset): Relations pointing AT this cluster, from the other side
            of the same edge (`TargetingClusterRelation`) — reading only the outbound list published half the graph
        meta (GalaxyClusterDetailMeta | Unset): Raw cluster metadata (refs, sectors, country, etc.)
        relations (list[GalaxyClusterRelation] | Unset): Relations to other galaxy clusters
        source (str | Unset): Cluster source Default: ''.
        synonyms (list[str] | Unset): Known aliases for this cluster value
        tag_att_count (int | None | Unset): How many attributes carry the cluster's tag
        tag_count (int | None | Unset): How many tags in this instance carry the cluster
        tag_name (str | Unset): MISP tag string identifying this cluster Default: ''.
        type_ (str | Unset): Cluster type (e.g. 'threat-actor', 'malware', 'mitre-attack') Default: ''.
        uuid (str | Unset): Cluster UUID Default: ''.
        value (str | Unset): Cluster value (e.g. 'APT28', 'Emotet') Default: ''.
    """

    authors: list[str] | Unset = UNSET
    description: str | Unset = ""
    galaxy: GalaxyParent | Unset = UNSET
    id: str | Unset = ""
    inbound_relations: list[GalaxyClusterRelation] | Unset = UNSET
    meta: GalaxyClusterDetailMeta | Unset = UNSET
    relations: list[GalaxyClusterRelation] | Unset = UNSET
    source: str | Unset = ""
    synonyms: list[str] | Unset = UNSET
    tag_att_count: int | None | Unset = UNSET
    tag_count: int | None | Unset = UNSET
    tag_name: str | Unset = ""
    type_: str | Unset = ""
    uuid: str | Unset = ""
    value: str | Unset = ""
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        from ..models.galaxy_cluster_detail_meta import GalaxyClusterDetailMeta  # noqa: PLC0415
        from ..models.galaxy_cluster_relation import GalaxyClusterRelation  # noqa: PLC0415
        from ..models.galaxy_parent import GalaxyParent  # noqa: PLC0415

        authors: list[str] | Unset = UNSET
        if not isinstance(self.authors, Unset):
            authors = self.authors

        description = self.description

        galaxy: dict[str, Any] | Unset = UNSET
        if not isinstance(self.galaxy, Unset):
            galaxy = self.galaxy.to_dict()

        id = self.id

        inbound_relations: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.inbound_relations, Unset):
            inbound_relations = []
            for inbound_relations_item_data in self.inbound_relations:
                inbound_relations_item = inbound_relations_item_data.to_dict()
                inbound_relations.append(inbound_relations_item)

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

        tag_att_count: int | None | Unset
        if isinstance(self.tag_att_count, Unset):
            tag_att_count = UNSET
        else:
            tag_att_count = self.tag_att_count

        tag_count: int | None | Unset
        if isinstance(self.tag_count, Unset):
            tag_count = UNSET
        else:
            tag_count = self.tag_count

        tag_name = self.tag_name

        type_ = self.type_

        uuid = self.uuid

        value = self.value

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if authors is not UNSET:
            field_dict["authors"] = authors
        if description is not UNSET:
            field_dict["description"] = description
        if galaxy is not UNSET:
            field_dict["galaxy"] = galaxy
        if id is not UNSET:
            field_dict["id"] = id
        if inbound_relations is not UNSET:
            field_dict["inbound_relations"] = inbound_relations
        if meta is not UNSET:
            field_dict["meta"] = meta
        if relations is not UNSET:
            field_dict["relations"] = relations
        if source is not UNSET:
            field_dict["source"] = source
        if synonyms is not UNSET:
            field_dict["synonyms"] = synonyms
        if tag_att_count is not UNSET:
            field_dict["tag_att_count"] = tag_att_count
        if tag_count is not UNSET:
            field_dict["tag_count"] = tag_count
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
        from ..models.galaxy_cluster_detail_meta import GalaxyClusterDetailMeta  # noqa: PLC0415
        from ..models.galaxy_cluster_relation import GalaxyClusterRelation  # noqa: PLC0415
        from ..models.galaxy_parent import GalaxyParent  # noqa: PLC0415

        d = dict(src_dict)
        authors = cast(list[str], d.pop("authors", UNSET))

        description = d.pop("description", UNSET)

        _galaxy = d.pop("galaxy", UNSET)
        galaxy: GalaxyParent | Unset
        if isinstance(_galaxy, Unset):
            galaxy = UNSET
        else:
            galaxy = GalaxyParent.from_dict(_galaxy)

        id = d.pop("id", UNSET)

        _inbound_relations = d.pop("inbound_relations", UNSET)
        inbound_relations: list[GalaxyClusterRelation] | Unset = UNSET
        if _inbound_relations is not UNSET:
            inbound_relations = []
            for inbound_relations_item_data in _inbound_relations:
                inbound_relations_item = GalaxyClusterRelation.from_dict(inbound_relations_item_data)

                inbound_relations.append(inbound_relations_item)

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

        def _parse_tag_att_count(data: object) -> int | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(int | None | Unset, data)

        tag_att_count = _parse_tag_att_count(d.pop("tag_att_count", UNSET))

        def _parse_tag_count(data: object) -> int | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(int | None | Unset, data)

        tag_count = _parse_tag_count(d.pop("tag_count", UNSET))

        tag_name = d.pop("tag_name", UNSET)

        type_ = d.pop("type", UNSET)

        uuid = d.pop("uuid", UNSET)

        value = d.pop("value", UNSET)

        galaxy_cluster_detail = cls(
            authors=authors,
            description=description,
            galaxy=galaxy,
            id=id,
            inbound_relations=inbound_relations,
            meta=meta,
            relations=relations,
            source=source,
            synonyms=synonyms,
            tag_att_count=tag_att_count,
            tag_count=tag_count,
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

from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, BinaryIO, Generator, TextIO, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.misp_attribute import MISPAttribute
    from ..models.misp_object_reference import MISPObjectReference


T = TypeVar("T", bound="MISPObject")


@_attrs_define
class MISPObject:
    """A composite MISP object — a named grouping of attributes that only mean something together.

    `MISPAttribute.object_id` is the flat pointer; this is the grouping it points into. Composite
    objects are how MISP represents structured records (a file with its hashes and filenames, a
    domain with its resolution IP), so a flat attribute list loses the relations between them.

        Attributes:
            attributes (list[MISPAttribute] | Unset): Attributes belonging to this object
            comment (str | Unset): Analyst comment on the object Default: ''.
            description (str | Unset): Object description Default: ''.
            event_id (str | Unset): Parent event ID Default: ''.
            id (str | Unset): MISP object ID Default: ''.
            meta_category (str | Unset): Object meta-category Default: ''.
            name (str | Unset): Object name (e.g. 'file', 'domain-ip') Default: ''.
            references (list[MISPObjectReference] | Unset): Named links between this object's attributes
            template_uuid (str | Unset): UUID of the object template this follows Default: ''.
            template_version (None | str | Unset): Revision of that template (e.g. '12') — what the attribute roles are
                defined against
            timestamp (str | Unset): Object creation timestamp Default: ''.
            uuid (str | Unset): MISP object UUID Default: ''.
    """

    attributes: list[MISPAttribute] | Unset = UNSET
    comment: str | Unset = ""
    description: str | Unset = ""
    event_id: str | Unset = ""
    id: str | Unset = ""
    meta_category: str | Unset = ""
    name: str | Unset = ""
    references: list[MISPObjectReference] | Unset = UNSET
    template_uuid: str | Unset = ""
    template_version: None | str | Unset = UNSET
    timestamp: str | Unset = ""
    uuid: str | Unset = ""
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        from ..models.misp_attribute import MISPAttribute  # noqa: PLC0415
        from ..models.misp_object_reference import MISPObjectReference  # noqa: PLC0415

        attributes: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.attributes, Unset):
            attributes = []
            for attributes_item_data in self.attributes:
                attributes_item = attributes_item_data.to_dict()
                attributes.append(attributes_item)

        comment = self.comment

        description = self.description

        event_id = self.event_id

        id = self.id

        meta_category = self.meta_category

        name = self.name

        references: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.references, Unset):
            references = []
            for references_item_data in self.references:
                references_item = references_item_data.to_dict()
                references.append(references_item)

        template_uuid = self.template_uuid

        template_version: None | str | Unset
        if isinstance(self.template_version, Unset):
            template_version = UNSET
        else:
            template_version = self.template_version

        timestamp = self.timestamp

        uuid = self.uuid

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if attributes is not UNSET:
            field_dict["attributes"] = attributes
        if comment is not UNSET:
            field_dict["comment"] = comment
        if description is not UNSET:
            field_dict["description"] = description
        if event_id is not UNSET:
            field_dict["event_id"] = event_id
        if id is not UNSET:
            field_dict["id"] = id
        if meta_category is not UNSET:
            field_dict["meta_category"] = meta_category
        if name is not UNSET:
            field_dict["name"] = name
        if references is not UNSET:
            field_dict["references"] = references
        if template_uuid is not UNSET:
            field_dict["template_uuid"] = template_uuid
        if template_version is not UNSET:
            field_dict["template_version"] = template_version
        if timestamp is not UNSET:
            field_dict["timestamp"] = timestamp
        if uuid is not UNSET:
            field_dict["uuid"] = uuid

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.misp_attribute import MISPAttribute  # noqa: PLC0415
        from ..models.misp_object_reference import MISPObjectReference  # noqa: PLC0415

        d = dict(src_dict)
        _attributes = d.pop("attributes", UNSET)
        attributes: list[MISPAttribute] | Unset = UNSET
        if _attributes is not UNSET:
            attributes = []
            for attributes_item_data in _attributes:
                attributes_item = MISPAttribute.from_dict(attributes_item_data)

                attributes.append(attributes_item)

        comment = d.pop("comment", UNSET)

        description = d.pop("description", UNSET)

        event_id = d.pop("event_id", UNSET)

        id = d.pop("id", UNSET)

        meta_category = d.pop("meta_category", UNSET)

        name = d.pop("name", UNSET)

        _references = d.pop("references", UNSET)
        references: list[MISPObjectReference] | Unset = UNSET
        if _references is not UNSET:
            references = []
            for references_item_data in _references:
                references_item = MISPObjectReference.from_dict(references_item_data)

                references.append(references_item)

        template_uuid = d.pop("template_uuid", UNSET)

        def _parse_template_version(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        template_version = _parse_template_version(d.pop("template_version", UNSET))

        timestamp = d.pop("timestamp", UNSET)

        uuid = d.pop("uuid", UNSET)

        misp_object = cls(
            attributes=attributes,
            comment=comment,
            description=description,
            event_id=event_id,
            id=id,
            meta_category=meta_category,
            name=name,
            references=references,
            template_uuid=template_uuid,
            template_version=template_version,
            timestamp=timestamp,
            uuid=uuid,
        )

        misp_object.additional_properties = d
        return misp_object

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

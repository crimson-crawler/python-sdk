from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, BinaryIO, Generator, TextIO, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.misp_event_attribute_stats import MISPEventAttributeStats
    from ..models.misp_event_object_stats import MISPEventObjectStats


T = TypeVar("T", bound="MISPEventStats")


@_attrs_define
class MISPEventStats:
    """An event's composition from `/events/viewEventStats` — `MISPEvent.attribute_count` is only a size.

    Attributes:
        attachments (int | Unset): Attachment count Default: 0.
        attributes (MISPEventAttributeStats | Unset): What an event's attributes are MADE of, beyond their count.
        objects (MISPEventObjectStats | Unset): What an event's composite objects are MADE of.
        reports (int | Unset): Analyst report count Default: 0.
    """

    attachments: int | Unset = 0
    attributes: MISPEventAttributeStats | Unset = UNSET
    objects: MISPEventObjectStats | Unset = UNSET
    reports: int | Unset = 0
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        from ..models.misp_event_attribute_stats import MISPEventAttributeStats  # noqa: PLC0415
        from ..models.misp_event_object_stats import MISPEventObjectStats  # noqa: PLC0415

        attachments = self.attachments

        attributes: dict[str, Any] | Unset = UNSET
        if not isinstance(self.attributes, Unset):
            attributes = self.attributes.to_dict()

        objects: dict[str, Any] | Unset = UNSET
        if not isinstance(self.objects, Unset):
            objects = self.objects.to_dict()

        reports = self.reports

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if attachments is not UNSET:
            field_dict["attachments"] = attachments
        if attributes is not UNSET:
            field_dict["attributes"] = attributes
        if objects is not UNSET:
            field_dict["objects"] = objects
        if reports is not UNSET:
            field_dict["reports"] = reports

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.misp_event_attribute_stats import MISPEventAttributeStats  # noqa: PLC0415
        from ..models.misp_event_object_stats import MISPEventObjectStats  # noqa: PLC0415

        d = dict(src_dict)
        attachments = d.pop("attachments", UNSET)

        _attributes = d.pop("attributes", UNSET)
        attributes: MISPEventAttributeStats | Unset
        if isinstance(_attributes, Unset):
            attributes = UNSET
        else:
            attributes = MISPEventAttributeStats.from_dict(_attributes)

        _objects = d.pop("objects", UNSET)
        objects: MISPEventObjectStats | Unset
        if isinstance(_objects, Unset):
            objects = UNSET
        else:
            objects = MISPEventObjectStats.from_dict(_objects)

        reports = d.pop("reports", UNSET)

        misp_event_stats = cls(
            attachments=attachments,
            attributes=attributes,
            objects=objects,
            reports=reports,
        )

        misp_event_stats.additional_properties = d
        return misp_event_stats

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

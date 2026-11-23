from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, BinaryIO, Generator, TextIO, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="MISPEventReport")


@_attrs_define
class MISPEventReport:
    """An analyst-written markdown report MISP attaches to an event.

    Attributes:
        content (str | Unset): Report body (markdown; may be large) Default: ''.
        event_id (str | Unset): Event the report belongs to Default: ''.
        id (str | Unset): Report id Default: ''.
        name (str | Unset): Report title Default: ''.
        timestamp (str | Unset): Last-modified unix timestamp Default: ''.
        uuid (str | Unset): Report UUID Default: ''.
    """

    content: str | Unset = ""
    event_id: str | Unset = ""
    id: str | Unset = ""
    name: str | Unset = ""
    timestamp: str | Unset = ""
    uuid: str | Unset = ""
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        content = self.content

        event_id = self.event_id

        id = self.id

        name = self.name

        timestamp = self.timestamp

        uuid = self.uuid

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if content is not UNSET:
            field_dict["content"] = content
        if event_id is not UNSET:
            field_dict["event_id"] = event_id
        if id is not UNSET:
            field_dict["id"] = id
        if name is not UNSET:
            field_dict["name"] = name
        if timestamp is not UNSET:
            field_dict["timestamp"] = timestamp
        if uuid is not UNSET:
            field_dict["uuid"] = uuid

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        content = d.pop("content", UNSET)

        event_id = d.pop("event_id", UNSET)

        id = d.pop("id", UNSET)

        name = d.pop("name", UNSET)

        timestamp = d.pop("timestamp", UNSET)

        uuid = d.pop("uuid", UNSET)

        misp_event_report = cls(
            content=content,
            event_id=event_id,
            id=id,
            name=name,
            timestamp=timestamp,
            uuid=uuid,
        )

        misp_event_report.additional_properties = d
        return misp_event_report

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

from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, BinaryIO, Generator, TextIO, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.misp_tag import MISPTag


T = TypeVar("T", bound="MISPFeedPreviewEvent")


@_attrs_define
class MISPFeedPreviewEvent:
    """One event a feed would import (its index entry, not the event body).

    Attributes:
        analysis (str | Unset): Analysis state Default: ''.
        date (str | Unset): Event date Default: ''.
        info (str | Unset): Event title Default: ''.
        org (str | Unset): Creating organisation name Default: ''.
        org_uuid (str | Unset): Creating organisation UUID Default: ''.
        tag_names (list[str] | Unset): Those tags' names
        tags (list[MISPTag] | Unset): Tags the feed index carries for the event
        threat_level_id (str | Unset): Threat level Default: ''.
        timestamp (str | Unset): Last-modified timestamp Default: ''.
        uuid (str | Unset): Event UUID — the key, and `preview_feed_event`'s second argument Default: ''.
    """

    analysis: str | Unset = ""
    date: str | Unset = ""
    info: str | Unset = ""
    org: str | Unset = ""
    org_uuid: str | Unset = ""
    tag_names: list[str] | Unset = UNSET
    tags: list[MISPTag] | Unset = UNSET
    threat_level_id: str | Unset = ""
    timestamp: str | Unset = ""
    uuid: str | Unset = ""
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        from ..models.misp_tag import MISPTag  # noqa: PLC0415

        analysis = self.analysis

        date = self.date

        info = self.info

        org = self.org

        org_uuid = self.org_uuid

        tag_names: list[str] | Unset = UNSET
        if not isinstance(self.tag_names, Unset):
            tag_names = self.tag_names

        tags: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.tags, Unset):
            tags = []
            for tags_item_data in self.tags:
                tags_item = tags_item_data.to_dict()
                tags.append(tags_item)

        threat_level_id = self.threat_level_id

        timestamp = self.timestamp

        uuid = self.uuid

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if analysis is not UNSET:
            field_dict["analysis"] = analysis
        if date is not UNSET:
            field_dict["date"] = date
        if info is not UNSET:
            field_dict["info"] = info
        if org is not UNSET:
            field_dict["org"] = org
        if org_uuid is not UNSET:
            field_dict["org_uuid"] = org_uuid
        if tag_names is not UNSET:
            field_dict["tag_names"] = tag_names
        if tags is not UNSET:
            field_dict["tags"] = tags
        if threat_level_id is not UNSET:
            field_dict["threat_level_id"] = threat_level_id
        if timestamp is not UNSET:
            field_dict["timestamp"] = timestamp
        if uuid is not UNSET:
            field_dict["uuid"] = uuid

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.misp_tag import MISPTag  # noqa: PLC0415

        d = dict(src_dict)
        analysis = d.pop("analysis", UNSET)

        date = d.pop("date", UNSET)

        info = d.pop("info", UNSET)

        org = d.pop("org", UNSET)

        org_uuid = d.pop("org_uuid", UNSET)

        tag_names = cast(list[str], d.pop("tag_names", UNSET))

        _tags = d.pop("tags", UNSET)
        tags: list[MISPTag] | Unset = UNSET
        if _tags is not UNSET:
            tags = []
            for tags_item_data in _tags:
                tags_item = MISPTag.from_dict(tags_item_data)

                tags.append(tags_item)

        threat_level_id = d.pop("threat_level_id", UNSET)

        timestamp = d.pop("timestamp", UNSET)

        uuid = d.pop("uuid", UNSET)

        misp_feed_preview_event = cls(
            analysis=analysis,
            date=date,
            info=info,
            org=org,
            org_uuid=org_uuid,
            tag_names=tag_names,
            tags=tags,
            threat_level_id=threat_level_id,
            timestamp=timestamp,
            uuid=uuid,
        )

        misp_feed_preview_event.additional_properties = d
        return misp_feed_preview_event

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

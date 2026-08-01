from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, BinaryIO, Generator, TextIO, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="SearchMISPRequest")


@_attrs_define
class SearchMISPRequest:
    """Search your threat intelligence feed by indicator value, event info, or event ID.

    Attributes:
        category (None | str | Unset): MISP attribute category (e.g. 'Network activity', 'Payload delivery')
        date_from (None | str | Unset): Earliest event date (YYYY-MM-DD)
        date_to (None | str | Unset): Latest event date (YYYY-MM-DD)
        event_id (None | str | Unset): Direct event ID lookup
        eventinfo (None | str | Unset): Search events by title/description text
        limit (int | Unset): Maximum number of results to return (1-100) Default: 50.
        page (int | Unset): Page number for pagination (1-indexed, max 100) Default: 1.
        published (bool | None | Unset): If true, restrict to events published by their owning org (filters out analyst
            drafts)
        tags (list[str] | None | Unset): Filter by MISP tag(s) (any match). Supports tlp: prefixes, galaxy cluster
            names.
        threat_level_id (None | str | Unset): Filter by event threat level: '1' (high), '2' (medium), '3' (low), '4'
            (undefined)
        to_ids (bool | None | Unset): If true, return only attributes flagged for IDS detection (high-confidence IOCs)
        type_attribute (None | str | Unset): Filter attributes by type (e.g. ip-dst, md5, domain)
        value (None | str | Unset): Indicator value to search (IP, hash, domain, etc.)
    """

    category: None | str | Unset = UNSET
    date_from: None | str | Unset = UNSET
    date_to: None | str | Unset = UNSET
    event_id: None | str | Unset = UNSET
    eventinfo: None | str | Unset = UNSET
    limit: int | Unset = 50
    page: int | Unset = 1
    published: bool | None | Unset = UNSET
    tags: list[str] | None | Unset = UNSET
    threat_level_id: None | str | Unset = UNSET
    to_ids: bool | None | Unset = UNSET
    type_attribute: None | str | Unset = UNSET
    value: None | str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        category: None | str | Unset
        if isinstance(self.category, Unset):
            category = UNSET
        else:
            category = self.category

        date_from: None | str | Unset
        if isinstance(self.date_from, Unset):
            date_from = UNSET
        else:
            date_from = self.date_from

        date_to: None | str | Unset
        if isinstance(self.date_to, Unset):
            date_to = UNSET
        else:
            date_to = self.date_to

        event_id: None | str | Unset
        if isinstance(self.event_id, Unset):
            event_id = UNSET
        else:
            event_id = self.event_id

        eventinfo: None | str | Unset
        if isinstance(self.eventinfo, Unset):
            eventinfo = UNSET
        else:
            eventinfo = self.eventinfo

        limit = self.limit

        page = self.page

        published: bool | None | Unset
        if isinstance(self.published, Unset):
            published = UNSET
        else:
            published = self.published

        tags: list[str] | None | Unset
        if isinstance(self.tags, Unset):
            tags = UNSET
        elif isinstance(self.tags, list):
            tags = self.tags

        else:
            tags = self.tags

        threat_level_id: None | str | Unset
        if isinstance(self.threat_level_id, Unset):
            threat_level_id = UNSET
        else:
            threat_level_id = self.threat_level_id

        to_ids: bool | None | Unset
        if isinstance(self.to_ids, Unset):
            to_ids = UNSET
        else:
            to_ids = self.to_ids

        type_attribute: None | str | Unset
        if isinstance(self.type_attribute, Unset):
            type_attribute = UNSET
        else:
            type_attribute = self.type_attribute

        value: None | str | Unset
        if isinstance(self.value, Unset):
            value = UNSET
        else:
            value = self.value

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if category is not UNSET:
            field_dict["category"] = category
        if date_from is not UNSET:
            field_dict["date_from"] = date_from
        if date_to is not UNSET:
            field_dict["date_to"] = date_to
        if event_id is not UNSET:
            field_dict["event_id"] = event_id
        if eventinfo is not UNSET:
            field_dict["eventinfo"] = eventinfo
        if limit is not UNSET:
            field_dict["limit"] = limit
        if page is not UNSET:
            field_dict["page"] = page
        if published is not UNSET:
            field_dict["published"] = published
        if tags is not UNSET:
            field_dict["tags"] = tags
        if threat_level_id is not UNSET:
            field_dict["threat_level_id"] = threat_level_id
        if to_ids is not UNSET:
            field_dict["to_ids"] = to_ids
        if type_attribute is not UNSET:
            field_dict["type_attribute"] = type_attribute
        if value is not UNSET:
            field_dict["value"] = value

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)

        def _parse_category(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        category = _parse_category(d.pop("category", UNSET))

        def _parse_date_from(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        date_from = _parse_date_from(d.pop("date_from", UNSET))

        def _parse_date_to(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        date_to = _parse_date_to(d.pop("date_to", UNSET))

        def _parse_event_id(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        event_id = _parse_event_id(d.pop("event_id", UNSET))

        def _parse_eventinfo(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        eventinfo = _parse_eventinfo(d.pop("eventinfo", UNSET))

        limit = d.pop("limit", UNSET)

        page = d.pop("page", UNSET)

        def _parse_published(data: object) -> bool | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(bool | None | Unset, data)

        published = _parse_published(d.pop("published", UNSET))

        def _parse_tags(data: object) -> list[str] | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, list):
                    raise TypeError()
                tags_type_0 = cast(list[str], data)

                return tags_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(list[str] | None | Unset, data)

        tags = _parse_tags(d.pop("tags", UNSET))

        def _parse_threat_level_id(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        threat_level_id = _parse_threat_level_id(d.pop("threat_level_id", UNSET))

        def _parse_to_ids(data: object) -> bool | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(bool | None | Unset, data)

        to_ids = _parse_to_ids(d.pop("to_ids", UNSET))

        def _parse_type_attribute(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        type_attribute = _parse_type_attribute(d.pop("type_attribute", UNSET))

        def _parse_value(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        value = _parse_value(d.pop("value", UNSET))

        search_misp_request = cls(
            category=category,
            date_from=date_from,
            date_to=date_to,
            event_id=event_id,
            eventinfo=eventinfo,
            limit=limit,
            page=page,
            published=published,
            tags=tags,
            threat_level_id=threat_level_id,
            to_ids=to_ids,
            type_attribute=type_attribute,
            value=value,
        )

        search_misp_request.additional_properties = d
        return search_misp_request

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

from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, BinaryIO, Generator, TextIO, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.misp_feed_hit import MISPFeedHit


T = TypeVar("T", bound="MISPFeedPreviewValue")


@_attrs_define
class MISPFeedPreviewValue:
    """One indicator value a value-format feed would import.

    Attributes:
        category (str | Unset): Attribute category Default: ''.
        correlated_event_ids (list[str] | Unset): Local events this value already correlates with
        correlation_count (int | Unset): How many such correlations there are Default: 0.
        default_type (str | Unset): The type the feed defaults to Default: ''.
        feed_hits (list[MISPFeedHit] | Unset): Other feeds already carrying this value
        to_ids (bool | Unset): Whether the feed flags it for IDS Default: False.
        types (list[str] | Unset): Attribute types the value could be imported as
        value (str | Unset): The indicator value Default: ''.
    """

    category: str | Unset = ""
    correlated_event_ids: list[str] | Unset = UNSET
    correlation_count: int | Unset = 0
    default_type: str | Unset = ""
    feed_hits: list[MISPFeedHit] | Unset = UNSET
    to_ids: bool | Unset = False
    types: list[str] | Unset = UNSET
    value: str | Unset = ""
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        from ..models.misp_feed_hit import MISPFeedHit  # noqa: PLC0415

        category = self.category

        correlated_event_ids: list[str] | Unset = UNSET
        if not isinstance(self.correlated_event_ids, Unset):
            correlated_event_ids = self.correlated_event_ids

        correlation_count = self.correlation_count

        default_type = self.default_type

        feed_hits: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.feed_hits, Unset):
            feed_hits = []
            for feed_hits_item_data in self.feed_hits:
                feed_hits_item = feed_hits_item_data.to_dict()
                feed_hits.append(feed_hits_item)

        to_ids = self.to_ids

        types: list[str] | Unset = UNSET
        if not isinstance(self.types, Unset):
            types = self.types

        value = self.value

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if category is not UNSET:
            field_dict["category"] = category
        if correlated_event_ids is not UNSET:
            field_dict["correlated_event_ids"] = correlated_event_ids
        if correlation_count is not UNSET:
            field_dict["correlation_count"] = correlation_count
        if default_type is not UNSET:
            field_dict["default_type"] = default_type
        if feed_hits is not UNSET:
            field_dict["feed_hits"] = feed_hits
        if to_ids is not UNSET:
            field_dict["to_ids"] = to_ids
        if types is not UNSET:
            field_dict["types"] = types
        if value is not UNSET:
            field_dict["value"] = value

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.misp_feed_hit import MISPFeedHit  # noqa: PLC0415

        d = dict(src_dict)
        category = d.pop("category", UNSET)

        correlated_event_ids = cast(list[str], d.pop("correlated_event_ids", UNSET))

        correlation_count = d.pop("correlation_count", UNSET)

        default_type = d.pop("default_type", UNSET)

        _feed_hits = d.pop("feed_hits", UNSET)
        feed_hits: list[MISPFeedHit] | Unset = UNSET
        if _feed_hits is not UNSET:
            feed_hits = []
            for feed_hits_item_data in _feed_hits:
                feed_hits_item = MISPFeedHit.from_dict(feed_hits_item_data)

                feed_hits.append(feed_hits_item)

        to_ids = d.pop("to_ids", UNSET)

        types = cast(list[str], d.pop("types", UNSET))

        value = d.pop("value", UNSET)

        misp_feed_preview_value = cls(
            category=category,
            correlated_event_ids=correlated_event_ids,
            correlation_count=correlation_count,
            default_type=default_type,
            feed_hits=feed_hits,
            to_ids=to_ids,
            types=types,
            value=value,
        )

        misp_feed_preview_value.additional_properties = d
        return misp_feed_preview_value

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

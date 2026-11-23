from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, BinaryIO, Generator, TextIO, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.misp_feed_preview_event import MISPFeedPreviewEvent
    from ..models.misp_feed_preview_value import MISPFeedPreviewValue


T = TypeVar("T", bound="MISPFeedPreview")


@_attrs_define
class MISPFeedPreview:
    """What one MISP feed would import — no import, no write, just the index.

    `kind` is a total answer: `event_index` / `value_index` say the read succeeded and which shape the
    feed produced (an EMPTY event index is still `event_index`), and `missing` says MISP answered 404
    for that feed id. A failed read is never published here — it raises and lands in `errors[]`.

        Attributes:
            event_count (int | Unset): How many event rows the feed index holds, before truncation Default: 0.
            events (list[MISPFeedPreviewEvent] | Unset): Event rows (event_index feeds only)
            feed_id (str | Unset): The feed this preview is for Default: ''.
            kind (str | Unset): event_index | value_index | missing Default: ''.
            truncated (bool | Unset): True when the feed index held more rows than this response carries — `events`/`values`
                are then a bounded prefix, and `event_count`/`value_count` give the true size. Never silent: a feed index can
                hold millions of values. Default: False.
            value_count (int | Unset): How many value rows the feed index holds, before truncation Default: 0.
            values (list[MISPFeedPreviewValue] | Unset): Value rows (value_index feeds only)
    """

    event_count: int | Unset = 0
    events: list[MISPFeedPreviewEvent] | Unset = UNSET
    feed_id: str | Unset = ""
    kind: str | Unset = ""
    truncated: bool | Unset = False
    value_count: int | Unset = 0
    values: list[MISPFeedPreviewValue] | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        from ..models.misp_feed_preview_event import MISPFeedPreviewEvent  # noqa: PLC0415
        from ..models.misp_feed_preview_value import MISPFeedPreviewValue  # noqa: PLC0415

        event_count = self.event_count

        events: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.events, Unset):
            events = []
            for events_item_data in self.events:
                events_item = events_item_data.to_dict()
                events.append(events_item)

        feed_id = self.feed_id

        kind = self.kind

        truncated = self.truncated

        value_count = self.value_count

        values: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.values, Unset):
            values = []
            for values_item_data in self.values:
                values_item = values_item_data.to_dict()
                values.append(values_item)

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if event_count is not UNSET:
            field_dict["event_count"] = event_count
        if events is not UNSET:
            field_dict["events"] = events
        if feed_id is not UNSET:
            field_dict["feed_id"] = feed_id
        if kind is not UNSET:
            field_dict["kind"] = kind
        if truncated is not UNSET:
            field_dict["truncated"] = truncated
        if value_count is not UNSET:
            field_dict["value_count"] = value_count
        if values is not UNSET:
            field_dict["values"] = values

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.misp_feed_preview_event import MISPFeedPreviewEvent  # noqa: PLC0415
        from ..models.misp_feed_preview_value import MISPFeedPreviewValue  # noqa: PLC0415

        d = dict(src_dict)
        event_count = d.pop("event_count", UNSET)

        _events = d.pop("events", UNSET)
        events: list[MISPFeedPreviewEvent] | Unset = UNSET
        if _events is not UNSET:
            events = []
            for events_item_data in _events:
                events_item = MISPFeedPreviewEvent.from_dict(events_item_data)

                events.append(events_item)

        feed_id = d.pop("feed_id", UNSET)

        kind = d.pop("kind", UNSET)

        truncated = d.pop("truncated", UNSET)

        value_count = d.pop("value_count", UNSET)

        _values = d.pop("values", UNSET)
        values: list[MISPFeedPreviewValue] | Unset = UNSET
        if _values is not UNSET:
            values = []
            for values_item_data in _values:
                values_item = MISPFeedPreviewValue.from_dict(values_item_data)

                values.append(values_item)

        misp_feed_preview = cls(
            event_count=event_count,
            events=events,
            feed_id=feed_id,
            kind=kind,
            truncated=truncated,
            value_count=value_count,
            values=values,
        )

        misp_feed_preview.additional_properties = d
        return misp_feed_preview

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

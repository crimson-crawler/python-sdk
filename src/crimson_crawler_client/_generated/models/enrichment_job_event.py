from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, BinaryIO, Generator, TextIO, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..models.enrichment_job_event_level import EnrichmentJobEventLevel
from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.enrichment_job_event_meta_type_0 import EnrichmentJobEventMetaType0


T = TypeVar("T", bound="EnrichmentJobEvent")


@_attrs_define
class EnrichmentJobEvent:
    """One entry from an asynchronous enrichment's rolling event feed.

    Attributes:
        level (EnrichmentJobEventLevel): Event severity
        message (str): Human-readable event message
        progress (float): Overall job completion when the event was emitted
        stage (str): Stage identifier associated with the event
        ts (str): UTC ISO 8601 event timestamp
        meta (EnrichmentJobEventMetaType0 | None | Unset): Optional structured event details
    """

    level: EnrichmentJobEventLevel
    message: str
    progress: float
    stage: str
    ts: str
    meta: EnrichmentJobEventMetaType0 | None | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        from ..models.enrichment_job_event_meta_type_0 import EnrichmentJobEventMetaType0

        level = self.level.value

        message = self.message

        progress = self.progress

        stage = self.stage

        ts = self.ts

        meta: dict[str, Any] | None | Unset
        if isinstance(self.meta, Unset):
            meta = UNSET
        elif isinstance(self.meta, EnrichmentJobEventMetaType0):
            meta = self.meta.to_dict()
        else:
            meta = self.meta

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "level": level,
                "message": message,
                "progress": progress,
                "stage": stage,
                "ts": ts,
            }
        )
        if meta is not UNSET:
            field_dict["meta"] = meta

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.enrichment_job_event_meta_type_0 import EnrichmentJobEventMetaType0

        d = dict(src_dict)
        level = EnrichmentJobEventLevel(d.pop("level"))

        message = d.pop("message")

        progress = d.pop("progress")

        stage = d.pop("stage")

        ts = d.pop("ts")

        def _parse_meta(data: object) -> EnrichmentJobEventMetaType0 | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, dict):
                    raise TypeError()
                meta_type_0 = EnrichmentJobEventMetaType0.from_dict(data)

                return meta_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(EnrichmentJobEventMetaType0 | None | Unset, data)

        meta = _parse_meta(d.pop("meta", UNSET))

        enrichment_job_event = cls(
            level=level,
            message=message,
            progress=progress,
            stage=stage,
            ts=ts,
            meta=meta,
        )

        enrichment_job_event.additional_properties = d
        return enrichment_job_event

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

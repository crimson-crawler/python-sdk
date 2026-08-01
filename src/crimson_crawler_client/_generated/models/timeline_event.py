from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, BinaryIO, Generator, TextIO, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..models.timeline_event_kind import TimelineEventKind
from ..types import UNSET, Unset

T = TypeVar("T", bound="TimelineEvent")


@_attrs_define
class TimelineEvent:
    """One dated event in a reference's narrative timeline. Pure derivation from existing data —
    disclosure dates, KEV catalog dates, first PoC publication date, EPSS-trajectory inflection.
    Surfaced on ``ArtifactEnrichmentReference.timeline`` so analysts can read the "story" of each finding
    chronologically without hunting through nested enrichment.

        Attributes:
            date (str): Event date (YYYY-MM-DD; ISO 8601)
            kind (TimelineEventKind): Event category
            label (str): One-sentence analyst-facing description of what happened
    """

    date: str
    kind: TimelineEventKind
    label: str
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        date = self.date

        kind = self.kind.value

        label = self.label

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "date": date,
                "kind": kind,
                "label": label,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        date = d.pop("date")

        kind = TimelineEventKind(d.pop("kind"))

        label = d.pop("label")

        timeline_event = cls(
            date=date,
            kind=kind,
            label=label,
        )

        timeline_event.additional_properties = d
        return timeline_event

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

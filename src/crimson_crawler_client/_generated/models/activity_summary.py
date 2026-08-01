from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, BinaryIO, Generator, TextIO, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="ActivitySummary")


@_attrs_define
class ActivitySummary:
    """Threat group temporal activity with recency and frequency metrics.

    Attributes:
        active (bool | Unset): Active within the last 12 months Default: False.
        campaign_count (int | Unset): Total campaigns attributed Default: 0.
        days_since_last_seen (int | None | Unset): Days since most recent activity
        events_last_90d (int | Unset): Threat events from the last 90 days Default: 0.
        first_seen (None | str | Unset): Earliest known activity date
        last_seen (None | str | Unset): Most recent known activity date
        technique_count (int | Unset): Total techniques attributed Default: 0.
    """

    active: bool | Unset = False
    campaign_count: int | Unset = 0
    days_since_last_seen: int | None | Unset = UNSET
    events_last_90d: int | Unset = 0
    first_seen: None | str | Unset = UNSET
    last_seen: None | str | Unset = UNSET
    technique_count: int | Unset = 0
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        active = self.active

        campaign_count = self.campaign_count

        days_since_last_seen: int | None | Unset
        if isinstance(self.days_since_last_seen, Unset):
            days_since_last_seen = UNSET
        else:
            days_since_last_seen = self.days_since_last_seen

        events_last_90d = self.events_last_90d

        first_seen: None | str | Unset
        if isinstance(self.first_seen, Unset):
            first_seen = UNSET
        else:
            first_seen = self.first_seen

        last_seen: None | str | Unset
        if isinstance(self.last_seen, Unset):
            last_seen = UNSET
        else:
            last_seen = self.last_seen

        technique_count = self.technique_count

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if active is not UNSET:
            field_dict["active"] = active
        if campaign_count is not UNSET:
            field_dict["campaign_count"] = campaign_count
        if days_since_last_seen is not UNSET:
            field_dict["days_since_last_seen"] = days_since_last_seen
        if events_last_90d is not UNSET:
            field_dict["events_last_90d"] = events_last_90d
        if first_seen is not UNSET:
            field_dict["first_seen"] = first_seen
        if last_seen is not UNSET:
            field_dict["last_seen"] = last_seen
        if technique_count is not UNSET:
            field_dict["technique_count"] = technique_count

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        active = d.pop("active", UNSET)

        campaign_count = d.pop("campaign_count", UNSET)

        def _parse_days_since_last_seen(data: object) -> int | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(int | None | Unset, data)

        days_since_last_seen = _parse_days_since_last_seen(d.pop("days_since_last_seen", UNSET))

        events_last_90d = d.pop("events_last_90d", UNSET)

        def _parse_first_seen(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        first_seen = _parse_first_seen(d.pop("first_seen", UNSET))

        def _parse_last_seen(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        last_seen = _parse_last_seen(d.pop("last_seen", UNSET))

        technique_count = d.pop("technique_count", UNSET)

        activity_summary = cls(
            active=active,
            campaign_count=campaign_count,
            days_since_last_seen=days_since_last_seen,
            events_last_90d=events_last_90d,
            first_seen=first_seen,
            last_seen=last_seen,
            technique_count=technique_count,
        )

        activity_summary.additional_properties = d
        return activity_summary

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

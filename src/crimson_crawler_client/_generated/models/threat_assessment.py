from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, BinaryIO, Generator, TextIO, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="ThreatAssessment")


@_attrs_define
class ThreatAssessment:
    """IOC threat verdict computed from 5 weighted signals.

    Attributes:
        confidence (float | Unset): Verdict confidence (0.0-1.0) Default: 0.0.
        cross_feed_count (int | Unset): Distinct MISP events referencing this IOC (>3 adds a +0.10 corroboration bonus
            to threat_score) Default: 0.
        event_count (int | Unset): Linked threat events Default: 0.
        on_warninglist (bool | Unset): Matches a known-benign warning list Default: False.
        recency_days (int | None | Unset): Days since most recent attribute
        sighting_count (int | Unset): Confirmed sightings across events Default: 0.
        technique_count (int | Unset): Linked ATT&CK techniques Default: 0.
        threat_score (float | Unset): Raw threat score (0.0-1.0) Default: 0.0.
        to_ids_ratio (float | Unset): Ratio of attributes flagged for detection Default: 0.0.
        verdict (str | Unset): Threat verdict: high_threat, medium_threat, low_threat, or informational Default:
            'informational'.
    """

    confidence: float | Unset = 0.0
    cross_feed_count: int | Unset = 0
    event_count: int | Unset = 0
    on_warninglist: bool | Unset = False
    recency_days: int | None | Unset = UNSET
    sighting_count: int | Unset = 0
    technique_count: int | Unset = 0
    threat_score: float | Unset = 0.0
    to_ids_ratio: float | Unset = 0.0
    verdict: str | Unset = "informational"
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        confidence = self.confidence

        cross_feed_count = self.cross_feed_count

        event_count = self.event_count

        on_warninglist = self.on_warninglist

        recency_days: int | None | Unset
        if isinstance(self.recency_days, Unset):
            recency_days = UNSET
        else:
            recency_days = self.recency_days

        sighting_count = self.sighting_count

        technique_count = self.technique_count

        threat_score = self.threat_score

        to_ids_ratio = self.to_ids_ratio

        verdict = self.verdict

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if confidence is not UNSET:
            field_dict["confidence"] = confidence
        if cross_feed_count is not UNSET:
            field_dict["cross_feed_count"] = cross_feed_count
        if event_count is not UNSET:
            field_dict["event_count"] = event_count
        if on_warninglist is not UNSET:
            field_dict["on_warninglist"] = on_warninglist
        if recency_days is not UNSET:
            field_dict["recency_days"] = recency_days
        if sighting_count is not UNSET:
            field_dict["sighting_count"] = sighting_count
        if technique_count is not UNSET:
            field_dict["technique_count"] = technique_count
        if threat_score is not UNSET:
            field_dict["threat_score"] = threat_score
        if to_ids_ratio is not UNSET:
            field_dict["to_ids_ratio"] = to_ids_ratio
        if verdict is not UNSET:
            field_dict["verdict"] = verdict

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        confidence = d.pop("confidence", UNSET)

        cross_feed_count = d.pop("cross_feed_count", UNSET)

        event_count = d.pop("event_count", UNSET)

        on_warninglist = d.pop("on_warninglist", UNSET)

        def _parse_recency_days(data: object) -> int | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(int | None | Unset, data)

        recency_days = _parse_recency_days(d.pop("recency_days", UNSET))

        sighting_count = d.pop("sighting_count", UNSET)

        technique_count = d.pop("technique_count", UNSET)

        threat_score = d.pop("threat_score", UNSET)

        to_ids_ratio = d.pop("to_ids_ratio", UNSET)

        verdict = d.pop("verdict", UNSET)

        threat_assessment = cls(
            confidence=confidence,
            cross_feed_count=cross_feed_count,
            event_count=event_count,
            on_warninglist=on_warninglist,
            recency_days=recency_days,
            sighting_count=sighting_count,
            technique_count=technique_count,
            threat_score=threat_score,
            to_ids_ratio=to_ids_ratio,
            verdict=verdict,
        )

        threat_assessment.additional_properties = d
        return threat_assessment

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

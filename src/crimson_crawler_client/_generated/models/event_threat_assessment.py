from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, BinaryIO, Generator, TextIO, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..models.event_threat_assessment_verdict import EventThreatAssessmentVerdict
from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.event_threat_assessment_counts_by_type import EventThreatAssessmentCountsByType


T = TypeVar("T", bound="EventThreatAssessment")


@_attrs_define
class EventThreatAssessment:
    """Aggregate threat verdict across all of an event's indicators.

    Attributes:
        counts_by_type (EventThreatAssessmentCountsByType | Unset): Indicator count by reference type
        indicator_count (int | Unset): Indicators enriched Default: 0.
        kev_count (int | Unset): CVE indicators that are CISA-KEV-listed Default: 0.
        max_weaponization (float | None | Unset): Highest CVE weaponization score across the event (0–100)
        score (float | None | Unset): Highest normalized IOC score driving the verdict (0–1). **Null for a CVE-only
            event** — CVE strength lives in `max_weaponization` (0–100). Read `verdict` for the grade.
        verdict (EventThreatAssessmentVerdict | Unset): Overall event verdict — the worst indicator severity Default:
            EventThreatAssessmentVerdict.INFO.
        weaponized_count (int | Unset): CVE indicators with a Metasploit module Default: 0.
    """

    counts_by_type: EventThreatAssessmentCountsByType | Unset = UNSET
    indicator_count: int | Unset = 0
    kev_count: int | Unset = 0
    max_weaponization: float | None | Unset = UNSET
    score: float | None | Unset = UNSET
    verdict: EventThreatAssessmentVerdict | Unset = EventThreatAssessmentVerdict.INFO
    weaponized_count: int | Unset = 0
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        from ..models.event_threat_assessment_counts_by_type import EventThreatAssessmentCountsByType  # noqa: PLC0415

        counts_by_type: dict[str, Any] | Unset = UNSET
        if not isinstance(self.counts_by_type, Unset):
            counts_by_type = self.counts_by_type.to_dict()

        indicator_count = self.indicator_count

        kev_count = self.kev_count

        max_weaponization: float | None | Unset
        if isinstance(self.max_weaponization, Unset):
            max_weaponization = UNSET
        else:
            max_weaponization = self.max_weaponization

        score: float | None | Unset
        if isinstance(self.score, Unset):
            score = UNSET
        else:
            score = self.score

        verdict: str | Unset = UNSET
        if not isinstance(self.verdict, Unset):
            verdict = self.verdict.value

        weaponized_count = self.weaponized_count

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if counts_by_type is not UNSET:
            field_dict["counts_by_type"] = counts_by_type
        if indicator_count is not UNSET:
            field_dict["indicator_count"] = indicator_count
        if kev_count is not UNSET:
            field_dict["kev_count"] = kev_count
        if max_weaponization is not UNSET:
            field_dict["max_weaponization"] = max_weaponization
        if score is not UNSET:
            field_dict["score"] = score
        if verdict is not UNSET:
            field_dict["verdict"] = verdict
        if weaponized_count is not UNSET:
            field_dict["weaponized_count"] = weaponized_count

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.event_threat_assessment_counts_by_type import EventThreatAssessmentCountsByType  # noqa: PLC0415

        d = dict(src_dict)
        _counts_by_type = d.pop("counts_by_type", UNSET)
        counts_by_type: EventThreatAssessmentCountsByType | Unset
        if isinstance(_counts_by_type, Unset):
            counts_by_type = UNSET
        else:
            counts_by_type = EventThreatAssessmentCountsByType.from_dict(_counts_by_type)

        indicator_count = d.pop("indicator_count", UNSET)

        kev_count = d.pop("kev_count", UNSET)

        def _parse_max_weaponization(data: object) -> float | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(float | None | Unset, data)

        max_weaponization = _parse_max_weaponization(d.pop("max_weaponization", UNSET))

        def _parse_score(data: object) -> float | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(float | None | Unset, data)

        score = _parse_score(d.pop("score", UNSET))

        _verdict = d.pop("verdict", UNSET)
        verdict: EventThreatAssessmentVerdict | Unset
        if isinstance(_verdict, Unset):
            verdict = UNSET
        else:
            verdict = EventThreatAssessmentVerdict(_verdict)

        weaponized_count = d.pop("weaponized_count", UNSET)

        event_threat_assessment = cls(
            counts_by_type=counts_by_type,
            indicator_count=indicator_count,
            kev_count=kev_count,
            max_weaponization=max_weaponization,
            score=score,
            verdict=verdict,
            weaponized_count=weaponized_count,
        )

        event_threat_assessment.additional_properties = d
        return event_threat_assessment

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

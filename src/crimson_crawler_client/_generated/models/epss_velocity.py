from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, BinaryIO, Generator, TextIO, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="EPSSVelocity")


@_attrs_define
class EPSSVelocity:
    """EPSS score change rate over time.

    Attributes:
        acceleration (float | None | Unset): Rate of velocity change (positive = speeding up)
        change_30d (float | None | Unset): Score change over last 30 days
        change_7d (float | None | Unset): Score change over last 7 days
        cohort_percentile (float | None | Unset): Optional cohort baseline percentile when the caller provides EPSS
            cohort context; None when no cohort data is available
        current_score (float | Unset): Current EPSS score Default: 0.0.
        inflection (bool | Unset): True when 30d delta ≥0.2 is concentrated (≥80%) in the last 7d — signals a new
            exploit detail dropped Default: False.
        trend (str | Unset): Trend direction: accelerating, rising, stable, falling, or decelerating Default: 'stable'.
    """

    acceleration: float | None | Unset = UNSET
    change_30d: float | None | Unset = UNSET
    change_7d: float | None | Unset = UNSET
    cohort_percentile: float | None | Unset = UNSET
    current_score: float | Unset = 0.0
    inflection: bool | Unset = False
    trend: str | Unset = "stable"
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        acceleration: float | None | Unset
        if isinstance(self.acceleration, Unset):
            acceleration = UNSET
        else:
            acceleration = self.acceleration

        change_30d: float | None | Unset
        if isinstance(self.change_30d, Unset):
            change_30d = UNSET
        else:
            change_30d = self.change_30d

        change_7d: float | None | Unset
        if isinstance(self.change_7d, Unset):
            change_7d = UNSET
        else:
            change_7d = self.change_7d

        cohort_percentile: float | None | Unset
        if isinstance(self.cohort_percentile, Unset):
            cohort_percentile = UNSET
        else:
            cohort_percentile = self.cohort_percentile

        current_score = self.current_score

        inflection = self.inflection

        trend = self.trend

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if acceleration is not UNSET:
            field_dict["acceleration"] = acceleration
        if change_30d is not UNSET:
            field_dict["change_30d"] = change_30d
        if change_7d is not UNSET:
            field_dict["change_7d"] = change_7d
        if cohort_percentile is not UNSET:
            field_dict["cohort_percentile"] = cohort_percentile
        if current_score is not UNSET:
            field_dict["current_score"] = current_score
        if inflection is not UNSET:
            field_dict["inflection"] = inflection
        if trend is not UNSET:
            field_dict["trend"] = trend

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)

        def _parse_acceleration(data: object) -> float | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(float | None | Unset, data)

        acceleration = _parse_acceleration(d.pop("acceleration", UNSET))

        def _parse_change_30d(data: object) -> float | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(float | None | Unset, data)

        change_30d = _parse_change_30d(d.pop("change_30d", UNSET))

        def _parse_change_7d(data: object) -> float | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(float | None | Unset, data)

        change_7d = _parse_change_7d(d.pop("change_7d", UNSET))

        def _parse_cohort_percentile(data: object) -> float | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(float | None | Unset, data)

        cohort_percentile = _parse_cohort_percentile(d.pop("cohort_percentile", UNSET))

        current_score = d.pop("current_score", UNSET)

        inflection = d.pop("inflection", UNSET)

        trend = d.pop("trend", UNSET)

        epss_velocity = cls(
            acceleration=acceleration,
            change_30d=change_30d,
            change_7d=change_7d,
            cohort_percentile=cohort_percentile,
            current_score=current_score,
            inflection=inflection,
            trend=trend,
        )

        epss_velocity.additional_properties = d
        return epss_velocity

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

from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, BinaryIO, Generator, TextIO, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="EPSSScore")


@_attrs_define
class EPSSScore:
    """Exploit Prediction Scoring System - probability that a CVE will be exploited in the wild.

    Attributes:
        cve_id (str): CVE identifier
        date (None | str | Unset): Score calculation date (ISO 8601)
        epss (float | None | Unset): Exploitation probability (0.0-1.0). Higher = more likely to be exploited
        percentile (float | None | Unset): Percentile rank among all scored CVEs (0.0-1.0)
    """

    cve_id: str
    date: None | str | Unset = UNSET
    epss: float | None | Unset = UNSET
    percentile: float | None | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        cve_id = self.cve_id

        date: None | str | Unset
        if isinstance(self.date, Unset):
            date = UNSET
        else:
            date = self.date

        epss: float | None | Unset
        if isinstance(self.epss, Unset):
            epss = UNSET
        else:
            epss = self.epss

        percentile: float | None | Unset
        if isinstance(self.percentile, Unset):
            percentile = UNSET
        else:
            percentile = self.percentile

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "cve_id": cve_id,
            }
        )
        if date is not UNSET:
            field_dict["date"] = date
        if epss is not UNSET:
            field_dict["epss"] = epss
        if percentile is not UNSET:
            field_dict["percentile"] = percentile

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        cve_id = d.pop("cve_id")

        def _parse_date(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        date = _parse_date(d.pop("date", UNSET))

        def _parse_epss(data: object) -> float | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(float | None | Unset, data)

        epss = _parse_epss(d.pop("epss", UNSET))

        def _parse_percentile(data: object) -> float | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(float | None | Unset, data)

        percentile = _parse_percentile(d.pop("percentile", UNSET))

        epss_score = cls(
            cve_id=cve_id,
            date=date,
            epss=epss,
            percentile=percentile,
        )

        epss_score.additional_properties = d
        return epss_score

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

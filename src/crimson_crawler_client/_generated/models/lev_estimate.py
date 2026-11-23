from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, BinaryIO, Generator, Literal, TextIO, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="LEVEstimate")


@_attrs_define
class LEVEstimate:
    """NIST CSWP 41 Likely Exploited Vulnerabilities (LEV2) over the EPSS history on record.

    Attributes:
        end (str): Last EPSS score date in the window (YYYY-MM-DD)
        probability (float): Lower bound on the probability the CVE was exploited at least once in the window (0-1)
        start (str): First EPSS score date in the window (YYYY-MM-DD)
        window_days (int): Daily EPSS scores the estimate rests on
        method (Literal['LEV2'] | Unset): NIST CSWP 41 variant: LEV2 uses daily scores Default: 'LEV2'.
    """

    end: str
    probability: float
    start: str
    window_days: int
    method: Literal["LEV2"] | Unset = "LEV2"
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        end = self.end

        probability = self.probability

        start = self.start

        window_days = self.window_days

        method = self.method

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "end": end,
                "probability": probability,
                "start": start,
                "window_days": window_days,
            }
        )
        if method is not UNSET:
            field_dict["method"] = method

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        end = d.pop("end")

        probability = d.pop("probability")

        start = d.pop("start")

        window_days = d.pop("window_days")

        method = cast(Literal["LEV2"] | Unset, d.pop("method", UNSET))
        if method != "LEV2" and not isinstance(method, Unset):
            raise ValueError(f"method must match const 'LEV2', got '{method}'")

        lev_estimate = cls(
            end=end,
            probability=probability,
            start=start,
            window_days=window_days,
            method=method,
        )

        lev_estimate.additional_properties = d
        return lev_estimate

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

from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, BinaryIO, Generator, TextIO, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="StatisticsDelta")


@_attrs_define
class StatisticsDelta:
    """Change counts over the standard freshness windows.

    Attributes:
        d1 (int | None | Unset): Changed in the last day
        d30 (int | None | Unset): Changed in the last 30 days
        d365 (int | None | Unset): Changed in the last 365 days
        d7 (int | None | Unset): Changed in the last 7 days
    """

    d1: int | None | Unset = UNSET
    d30: int | None | Unset = UNSET
    d365: int | None | Unset = UNSET
    d7: int | None | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        d1: int | None | Unset
        if isinstance(self.d1, Unset):
            d1 = UNSET
        else:
            d1 = self.d1

        d30: int | None | Unset
        if isinstance(self.d30, Unset):
            d30 = UNSET
        else:
            d30 = self.d30

        d365: int | None | Unset
        if isinstance(self.d365, Unset):
            d365 = UNSET
        else:
            d365 = self.d365

        d7: int | None | Unset
        if isinstance(self.d7, Unset):
            d7 = UNSET
        else:
            d7 = self.d7

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if d1 is not UNSET:
            field_dict["d1"] = d1
        if d30 is not UNSET:
            field_dict["d30"] = d30
        if d365 is not UNSET:
            field_dict["d365"] = d365
        if d7 is not UNSET:
            field_dict["d7"] = d7

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)

        def _parse_d1(data: object) -> int | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(int | None | Unset, data)

        d1 = _parse_d1(d.pop("d1", UNSET))

        def _parse_d30(data: object) -> int | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(int | None | Unset, data)

        d30 = _parse_d30(d.pop("d30", UNSET))

        def _parse_d365(data: object) -> int | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(int | None | Unset, data)

        d365 = _parse_d365(d.pop("d365", UNSET))

        def _parse_d7(data: object) -> int | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(int | None | Unset, data)

        d7 = _parse_d7(d.pop("d7", UNSET))

        statistics_delta = cls(
            d1=d1,
            d30=d30,
            d365=d365,
            d7=d7,
        )

        statistics_delta.additional_properties = d
        return statistics_delta

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

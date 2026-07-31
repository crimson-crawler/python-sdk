from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, BinaryIO, Generator, TextIO, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="OSVAffectedRange")


@_attrs_define
class OSVAffectedRange:
    """One affected version range for the queried package (from an OSV advisory's `affected[]`).

    Attributes:
        fixed (None | str | Unset): Version the vulnerability was fixed in (if known)
        introduced (None | str | Unset): Version it was introduced in ('0' = from the start)
        last_affected (None | str | Unset): Last version known to be affected (when no fix exists)
        type_ (str | Unset): Range type — SEMVER, ECOSYSTEM, or GIT Default: ''.
    """

    fixed: None | str | Unset = UNSET
    introduced: None | str | Unset = UNSET
    last_affected: None | str | Unset = UNSET
    type_: str | Unset = ""
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        fixed: None | str | Unset
        if isinstance(self.fixed, Unset):
            fixed = UNSET
        else:
            fixed = self.fixed

        introduced: None | str | Unset
        if isinstance(self.introduced, Unset):
            introduced = UNSET
        else:
            introduced = self.introduced

        last_affected: None | str | Unset
        if isinstance(self.last_affected, Unset):
            last_affected = UNSET
        else:
            last_affected = self.last_affected

        type_ = self.type_

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if fixed is not UNSET:
            field_dict["fixed"] = fixed
        if introduced is not UNSET:
            field_dict["introduced"] = introduced
        if last_affected is not UNSET:
            field_dict["last_affected"] = last_affected
        if type_ is not UNSET:
            field_dict["type"] = type_

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)

        def _parse_fixed(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        fixed = _parse_fixed(d.pop("fixed", UNSET))

        def _parse_introduced(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        introduced = _parse_introduced(d.pop("introduced", UNSET))

        def _parse_last_affected(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        last_affected = _parse_last_affected(d.pop("last_affected", UNSET))

        type_ = d.pop("type", UNSET)

        osv_affected_range = cls(
            fixed=fixed,
            introduced=introduced,
            last_affected=last_affected,
            type_=type_,
        )

        osv_affected_range.additional_properties = d
        return osv_affected_range

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

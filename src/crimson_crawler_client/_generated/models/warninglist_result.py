from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, BinaryIO, Generator, TextIO, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="WarninglistResult")


@_attrs_define
class WarninglistResult:
    """False-positive check result from known-benign indicator lists.

    Attributes:
        categories (list[str] | Unset): Categories/types of the matched warning lists (e.g. 'rfc1918')
        is_on_warninglist (bool | Unset): True if the indicator matches a warning list Default: False.
        warninglists (list[str] | Unset): Names of matched warning lists
    """

    categories: list[str] | Unset = UNSET
    is_on_warninglist: bool | Unset = False
    warninglists: list[str] | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        categories: list[str] | Unset = UNSET
        if not isinstance(self.categories, Unset):
            categories = self.categories

        is_on_warninglist = self.is_on_warninglist

        warninglists: list[str] | Unset = UNSET
        if not isinstance(self.warninglists, Unset):
            warninglists = self.warninglists

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if categories is not UNSET:
            field_dict["categories"] = categories
        if is_on_warninglist is not UNSET:
            field_dict["is_on_warninglist"] = is_on_warninglist
        if warninglists is not UNSET:
            field_dict["warninglists"] = warninglists

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        categories = cast(list[str], d.pop("categories", UNSET))

        is_on_warninglist = d.pop("is_on_warninglist", UNSET)

        warninglists = cast(list[str], d.pop("warninglists", UNSET))

        warninglist_result = cls(
            categories=categories,
            is_on_warninglist=is_on_warninglist,
            warninglists=warninglists,
        )

        warninglist_result.additional_properties = d
        return warninglist_result

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

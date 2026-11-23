from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, BinaryIO, Generator, TextIO, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="OSVAffectedRangeEcosystemSpecific")


@_attrs_define
class OSVAffectedRangeEcosystemSpecific:
    """THIS entry's own `ecosystem_specific` block — the ecosystem-private detail (for Go: the vulnerable import path and
    symbols). On a multi-package advisory it keeps each package's block with that package's ranges instead of collapsing
    them into one advisory-level answer (the response-level `ecosystem_specific` stays empty in that case)

    """

    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        osv_affected_range_ecosystem_specific = cls()

        osv_affected_range_ecosystem_specific.additional_properties = d
        return osv_affected_range_ecosystem_specific

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

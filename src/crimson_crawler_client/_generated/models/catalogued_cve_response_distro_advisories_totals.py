from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, BinaryIO, Generator, TextIO, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="CataloguedCVEResponseDistroAdvisoriesTotals")


@_attrs_define
class CataloguedCVEResponseDistroAdvisoriesTotals:
    """Rows each distro source produced before the 200-row cap, keyed by source (`suse_csaf_vex`, `ubuntu_openvex`,
    `alpine_secdb`). An unreadable source is 0. Compare with the listed rows to see how many were cut; each `source_url`
    names the complete document.

    """

    additional_properties: dict[str, int] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        catalogued_cve_response_distro_advisories_totals = cls()

        catalogued_cve_response_distro_advisories_totals.additional_properties = d
        return catalogued_cve_response_distro_advisories_totals

    @property
    def additional_keys(self) -> list[str]:
        return list(self.additional_properties.keys())

    def __getitem__(self, key: str) -> int:
        return self.additional_properties[key]

    def __setitem__(self, key: str, value: int) -> None:
        self.additional_properties[key] = value

    def __delitem__(self, key: str) -> None:
        del self.additional_properties[key]

    def __contains__(self, key: str) -> bool:
        return key in self.additional_properties

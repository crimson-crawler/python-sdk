from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, BinaryIO, Generator, TextIO, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="EnrichProductResponseCveFixVersions")


@_attrs_define
class EnrichProductResponseCveFixVersions:
    """Remediation guidance: `{cve_id: fix_version}` — the lowest version that resolves each CVE for this product (from the
    NVD `versionEndExcluding` applicability bound above the requested `version`). Only populated when `version` is set.
    A CVE is absent when NVD published no clean upper bound (all-versions-affected / fixed-after-unknown) — never a
    fabricated version.

    """

    additional_properties: dict[str, str] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        enrich_product_response_cve_fix_versions = cls()

        enrich_product_response_cve_fix_versions.additional_properties = d
        return enrich_product_response_cve_fix_versions

    @property
    def additional_keys(self) -> list[str]:
        return list(self.additional_properties.keys())

    def __getitem__(self, key: str) -> str:
        return self.additional_properties[key]

    def __setitem__(self, key: str, value: str) -> None:
        self.additional_properties[key] = value

    def __delitem__(self, key: str) -> None:
        del self.additional_properties[key]

    def __contains__(self, key: str) -> bool:
        return key in self.additional_properties

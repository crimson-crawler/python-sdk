from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, BinaryIO, Generator, TextIO, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.source_stamp import SourceStamp


T = TypeVar("T", bound="EnrichProductResponseCveFixSources")


@_attrs_define
class EnrichProductResponseCveFixSources:
    """Where a `cve_fix_versions` entry came from when it was NOT the NVD bound: `{cve_id: stamp}` naming the CVE Program
    record (and its CNA) that published the fixed version, with the record's own last-updated date. A CVE absent here
    was fixed by its NVD bound.

    """

    additional_properties: dict[str, SourceStamp] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        from ..models.source_stamp import SourceStamp  # noqa: PLC0415

        field_dict: dict[str, Any] = {}
        for prop_name, prop in self.additional_properties.items():
            field_dict[prop_name] = prop.to_dict()

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.source_stamp import SourceStamp  # noqa: PLC0415

        d = dict(src_dict)
        enrich_product_response_cve_fix_sources = cls()

        additional_properties = {}
        for prop_name, prop_dict in d.items():
            additional_property = SourceStamp.from_dict(prop_dict)

            additional_properties[prop_name] = additional_property

        enrich_product_response_cve_fix_sources.additional_properties = additional_properties
        return enrich_product_response_cve_fix_sources

    @property
    def additional_keys(self) -> list[str]:
        return list(self.additional_properties.keys())

    def __getitem__(self, key: str) -> SourceStamp:
        return self.additional_properties[key]

    def __setitem__(self, key: str, value: SourceStamp) -> None:
        self.additional_properties[key] = value

    def __delitem__(self, key: str) -> None:
        del self.additional_properties[key]

    def __contains__(self, key: str) -> bool:
        return key in self.additional_properties

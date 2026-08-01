from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, BinaryIO, Generator, TextIO, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="EnrichProductRequest")


@_attrs_define
class EnrichProductRequest:
    """Find vulnerabilities affecting a specific product and enrich each CVE.

    Attributes:
        product (str): Product name to search. Spaces and capitalization are normalized for CPE matching. Use the
            canonical CPE product name when known, such as `http_server`.
        include (list[str] | Unset): Layers to include for each matched CVE. Replaces the default list. Allowed values:
            affected_products, campaigns, capec, cwe, defend, details, detections, epss, exploits, groups, kev,
            knowledgebase, misp, mitigations, navigator, nist_controls, osv, poc, risk_summary, software, ssvc, summary,
            techniques, tie, web, web_scrape.
        vendor (None | str | Unset): Vendor name to narrow results. Normalized to CPE 2.3 shape (lowercase, whitespace →
            underscores).
        version (None | str | Unset): Version to hard-filter the matched CVE set by (major-line match: '7' keeps CVEs
            affecting any 7.x version or a range spanning 7.x; '2.4.51' keeps that exact version and ranges covering it).
            Zero matches returns an empty CVE set plus a 'version_filter'/'no_match' marker in errors[] — never a silent
            fallback to unfiltered.
    """

    product: str
    include: list[str] | Unset = UNSET
    vendor: None | str | Unset = UNSET
    version: None | str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        product = self.product

        include: list[str] | Unset = UNSET
        if not isinstance(self.include, Unset):
            include = self.include

        vendor: None | str | Unset
        if isinstance(self.vendor, Unset):
            vendor = UNSET
        else:
            vendor = self.vendor

        version: None | str | Unset
        if isinstance(self.version, Unset):
            version = UNSET
        else:
            version = self.version

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "product": product,
            }
        )
        if include is not UNSET:
            field_dict["include"] = include
        if vendor is not UNSET:
            field_dict["vendor"] = vendor
        if version is not UNSET:
            field_dict["version"] = version

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        product = d.pop("product")

        include = cast(list[str], d.pop("include", UNSET))

        def _parse_vendor(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        vendor = _parse_vendor(d.pop("vendor", UNSET))

        def _parse_version(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        version = _parse_version(d.pop("version", UNSET))

        enrich_product_request = cls(
            product=product,
            include=include,
            vendor=vendor,
            version=version,
        )

        enrich_product_request.additional_properties = d
        return enrich_product_request

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

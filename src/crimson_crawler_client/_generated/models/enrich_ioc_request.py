from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, BinaryIO, Generator, TextIO, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="EnrichIOCRequest")


@_attrs_define
class EnrichIOCRequest:
    """Enrich an indicator of compromise with linked threat events, techniques, and predictions.

    Attributes:
        value (str): Indicator value (IP address, hash, domain, etc.)
        include (list[str] | Unset): Response layers to include. Replaces the default list. Allowed values: campaigns,
            cves, defend, detections, galaxies, groups, inferred_chain, knowledgebase, misp_attributes, mitigations,
            navigator, nist_controls, poc, sightings, software, summary, techniques, tie, warninglist, web, web_scrape.
        type_ (str | Unset): Indicator type. Common values: ip-dst, ip-src, domain, hostname, md5, sha1, sha256, url,
            email Default: 'ip-dst'.
    """

    value: str
    include: list[str] | Unset = UNSET
    type_: str | Unset = "ip-dst"
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        value = self.value

        include: list[str] | Unset = UNSET
        if not isinstance(self.include, Unset):
            include = self.include

        type_ = self.type_

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "value": value,
            }
        )
        if include is not UNSET:
            field_dict["include"] = include
        if type_ is not UNSET:
            field_dict["type"] = type_

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        value = d.pop("value")

        include = cast(list[str], d.pop("include", UNSET))

        type_ = d.pop("type", UNSET)

        enrich_ioc_request = cls(
            value=value,
            include=include,
            type_=type_,
        )

        enrich_ioc_request.additional_properties = d
        return enrich_ioc_request

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

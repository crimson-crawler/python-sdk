from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, BinaryIO, Generator, Literal, TextIO, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="BatchIOCItem")


@_attrs_define
class BatchIOCItem:
    """Batch item: enrich an indicator of compromise.

    ``EnrichIOCRequest`` already owns a ``type`` field (the IOC indicator type,
    e.g. ip-dst). The batch union needs ``type`` as its discriminator, so the
    IOC indicator moves to ``value_type`` here and the dispatcher rebuilds a
    proper ``EnrichIOCRequest`` before calling the handler.

        Attributes:
            value (str): Indicator value (IP address, hash, domain, etc.)
            include (list[str] | Unset): Response layers to include. Replaces the default list. Allowed values: campaigns,
                cves, defend, detections, galaxies, groups, inferred_chain, knowledgebase, misp_attributes, mitigations,
                navigator, nist_controls, poc, sightings, software, summary, techniques, tie, warninglist, web, web_scrape.
            type_ (Literal['ioc'] | Unset): Selects IOC enrichment for this batch item Default: 'ioc'.
            value_type (str | Unset): Indicator type. Common values: ip-dst, ip-src, domain, hostname, md5, sha1, sha256,
                url, email Default: 'ip-dst'.
    """

    value: str
    include: list[str] | Unset = UNSET
    type_: Literal["ioc"] | Unset = "ioc"
    value_type: str | Unset = "ip-dst"
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        value = self.value

        include: list[str] | Unset = UNSET
        if not isinstance(self.include, Unset):
            include = self.include

        type_ = self.type_

        value_type = self.value_type

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
        if value_type is not UNSET:
            field_dict["value_type"] = value_type

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        value = d.pop("value")

        include = cast(list[str], d.pop("include", UNSET))

        type_ = cast(Literal["ioc"] | Unset, d.pop("type", UNSET))
        if type_ != "ioc" and not isinstance(type_, Unset):
            raise ValueError(f"type must match const 'ioc', got '{type_}'")

        value_type = d.pop("value_type", UNSET)

        batch_ioc_item = cls(
            value=value,
            include=include,
            type_=type_,
            value_type=value_type,
        )

        batch_ioc_item.additional_properties = d
        return batch_ioc_item

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

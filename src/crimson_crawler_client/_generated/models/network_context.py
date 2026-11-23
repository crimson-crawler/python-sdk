from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, BinaryIO, Generator, TextIO, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="NetworkContext")


@_attrs_define
class NetworkContext:
    """ASN / registration-country / covering-prefix facts for an IP indicator.

    Attributes:
        ip (str): The IP address this block describes
        version (int): Address family: 4 or 6
        as_name (None | str | Unset): AS description as iptoasn publishes it
        asn (int | None | Unset): Autonomous system number from iptoasn's registration ranges. `null` when the address
            is not covered by any announced range (or sits in a 'not routed' range).
        country (None | str | Unset): The country code the RIR holds for the range — a REGISTRATION country, not
            geolocation. `null` when the range carries none.
        prefix (None | str | Unset): The smallest aligned CIDR block that contains the matched iptoasn range. A range
            that is not CIDR-aligned is reported as its covering block, so an address inside the block is not always inside
            the range (for example 1.10.11.0-1.10.127.255 reports 1.10.0.0/17). The lookup is exact to the range.
        source (str | Unset): Data source; iptoasn.com, PDDL v1.0 Default: 'iptoasn'.
    """

    ip: str
    version: int
    as_name: None | str | Unset = UNSET
    asn: int | None | Unset = UNSET
    country: None | str | Unset = UNSET
    prefix: None | str | Unset = UNSET
    source: str | Unset = "iptoasn"
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        ip = self.ip

        version = self.version

        as_name: None | str | Unset
        if isinstance(self.as_name, Unset):
            as_name = UNSET
        else:
            as_name = self.as_name

        asn: int | None | Unset
        if isinstance(self.asn, Unset):
            asn = UNSET
        else:
            asn = self.asn

        country: None | str | Unset
        if isinstance(self.country, Unset):
            country = UNSET
        else:
            country = self.country

        prefix: None | str | Unset
        if isinstance(self.prefix, Unset):
            prefix = UNSET
        else:
            prefix = self.prefix

        source = self.source

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "ip": ip,
                "version": version,
            }
        )
        if as_name is not UNSET:
            field_dict["as_name"] = as_name
        if asn is not UNSET:
            field_dict["asn"] = asn
        if country is not UNSET:
            field_dict["country"] = country
        if prefix is not UNSET:
            field_dict["prefix"] = prefix
        if source is not UNSET:
            field_dict["source"] = source

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        ip = d.pop("ip")

        version = d.pop("version")

        def _parse_as_name(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        as_name = _parse_as_name(d.pop("as_name", UNSET))

        def _parse_asn(data: object) -> int | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(int | None | Unset, data)

        asn = _parse_asn(d.pop("asn", UNSET))

        def _parse_country(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        country = _parse_country(d.pop("country", UNSET))

        def _parse_prefix(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        prefix = _parse_prefix(d.pop("prefix", UNSET))

        source = d.pop("source", UNSET)

        network_context = cls(
            ip=ip,
            version=version,
            as_name=as_name,
            asn=asn,
            country=country,
            prefix=prefix,
            source=source,
        )

        network_context.additional_properties = d
        return network_context

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

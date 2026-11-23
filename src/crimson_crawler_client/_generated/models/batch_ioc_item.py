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
            include (list[str] | Unset): Response layers to include. Replaces the default list. Allowed values:
                analytic_details, campaigns, cisa_campaigns, cves, defend, detections, domain_context, galaxies,
                galaxy_clusters_full, groups, hashlookup, inferred_chain, knowledgebase, listed_on, log_sources,
                misp_attributes, mitigations, navigator, network_context, nist_controls, poc, sightings, software, summary,
                techniques, tie, warninglist. `galaxy_clusters_full` returns cluster profiles with inbound relations; the
                30-cluster fetch cap remains. `network_context` adds ASN / AS name / registration country / covering prefix from
                the seeded iptoasn corpus (IP values only). `domain_context` adds RDAP registration facts (registration and
                expiry dates, age in days, registrar, status) for a domain, hostname, or the host of a URL. `listed_on` unifies
                every list hit into one ledger — curated MISP feed caches plus the seeded Spamhaus DROP / ASN-DROP corpora — and
                is the only field that can report a `cidr` or `asn` match. `analytic_details` attaches each detection analytic's
                tunable fields and log sources. The technique-derived layers (analytic_details, campaigns, defend, detections,
                groups, log_sources, mitigations, navigator, nist_controls, software, techniques, tie) read the MISP attributes'
                galaxy tags, so each resolves that read for itself and answers without `misp_attributes` in the same request —
                while `misp_attributes` is still what publishes that section. `defend` reaches its countermeasures through the
                technique's ATT&CK mitigations — the corpus links D3FEND to mitigations, never directly to a technique — and
                reports `error: "no_mapping"` only where that join finds none. `hashlookup` attaches `hashlookup` — the CIRCL
                hashlookup / NSRL known-good verdict — and is answered only for the hash types (md5, sha1, sha256); every other
                type returns null and makes no request. `cisa_campaigns` attaches `cisa_campaigns[]` — the CISA joint
                cybersecurity advisories (AA-series) whose STIX bundle publishes this indicator, each carrying the matching
                observables in `matched_indicators`; matching is on the normalised observable type (`ip-src`/`ip-dst`/`ip` →
                IPv4/IPv6, `hostname` → domain, case-insensitive hashes and domains) and is exact, never a substring or a URL
                host of a domain.
            type_ (Literal['ioc'] | Unset): Selects IOC enrichment for this batch item Default: 'ioc'.
            value_type (str | Unset): Indicator type. Common values: ip-dst, ip-src, domain, hostname, md5, sha1, sha256,
                url, email. `ip-src` and `ip-dst` both search BOTH IP directions — an address is one indicator however the
                source labelled it — and `ip` is an alias for that same both-direction search. Which directions matched is
                reported as `matched_value_types`. Default: 'ip-dst'.
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

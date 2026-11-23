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
            canonical CPE product name — `http_server`, not `Apache httpd`. A human-style name that normalizes to no CPE
            (`Apache httpd` -> `apache_httpd`) returns an empty result set, so prefer the CPE form and pass the vendor
            separately: `http_server` + `vendor: apache` is the highest-yield shape.
        include (list[str] | Unset): Layers to include for each matched CVE. Replaces the default list. Allowed values:
            affected_products, campaigns, capec, cisa_kev, cwe, defend, details, detections, epss, exploits, groups, kev,
            knowledgebase, log_sources, metasploit, misp, mitigations, navigator, nist_controls, nuclei, osv,
            osv_restricted, poc, risk_summary, software, ssvc, summary, techniques, tie, lifecycle, cvss_bt, vulnrichment,
            cellular_core, certfr_advisories, jvn, ot_vendor_advisories, weakness_ranks, emb3d, csaf_advisories.
            `capec_full` and `certfr_advisories_full` restore nested CVE rows; `csaf_advisories_full` also restores complete
            product-level CSAF rows. `csaf_advisories_total` and `csaf_advisories_truncated` report the product-level
            summary cap. For full log sources, PoCs, Sigma rules, or D3FEND rows, call enrich/cve with the CVE ID,
            `techniques`, the base layer, and its `log_sources_full`, `poc_full`, `sigma_full`, or `defend_full` token.
            `lifecycle` attaches the product-level `lifecycle` block (endoflife.date); `cvss_bt` and `vulnrichment` are per-
            CVE layers forwarded to each matched CVE; `cellular_core`, `certfr_advisories`, `jvn` and `ot_vendor_advisories`
            are zero-cost in-process layers forwarded the same way. `details` does not gate this endpoint's own `product`
            object, its discovered CVEs, or the per-CVE fan-out — all are returned whether or not the token is requested
            (the token still counts toward the include set `confidence` reports). The technique-derived per-CVE layers
            (`groups`, `software`, `campaigns`, `mitigations`, `detections`, `defend`, `navigator`, `nist_controls`, `tie`)
            resolve the technique set they read, so they answer without `techniques` in the same request and never publish
            it. The product-level `nist_controls` rollup reads the nested rows' `techniques[]`, so it resolves them for the
            rollup and clears them again when the outer request did not `defend` reaches its countermeasures through the
            technique's ATT&CK mitigations — the corpus links D3FEND to mitigations, never directly to a technique — and
            reports `error: "no_mapping"` only where that join finds none. `ot_context` attaches the product-level OT/RF
            block and is forwarded to each nested CVE (so those rows carry their own `ot_context` too); it reads the cached
            Vulmatch software rows and the CSAF table when requested alone; `lifecycle` also fills its
            `fix_availability.eol`.
        limit (int | Unset): Maximum discovered CVEs per page (1–20) Default: 5.
        offset (int | Unset): Zero-based offset into the ranked discovered CVEs Default: 0.
        snapshot_id (None | str | Unset): Snapshot returned by page 0; required for later pages
        vendor (None | str | Unset): Vendor name to narrow results. Normalized to CPE 2.3 shape (lowercase, whitespace →
            underscores).
        version (None | str | Unset): Version to hard-filter the matched CVE set by (major-line match: '7' keeps CVEs
            affecting any 7.x version or a range spanning 7.x; '2.4.51' keeps that exact version and ranges covering it).
            Zero matches returns an empty CVE set plus a 'version_filter'/'no_match' marker in errors[] — never a silent
            fallback to unfiltered. When no matched CVE states a version for the product, the supplied version narrows
            nothing: errors[] carries 'version_filter'/'version_not_applied' instead, naming the product when no matched CPE
            lists the version at all.
    """

    product: str
    include: list[str] | Unset = UNSET
    limit: int | Unset = 5
    offset: int | Unset = 0
    snapshot_id: None | str | Unset = UNSET
    vendor: None | str | Unset = UNSET
    version: None | str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        product = self.product

        include: list[str] | Unset = UNSET
        if not isinstance(self.include, Unset):
            include = self.include

        limit = self.limit

        offset = self.offset

        snapshot_id: None | str | Unset
        if isinstance(self.snapshot_id, Unset):
            snapshot_id = UNSET
        else:
            snapshot_id = self.snapshot_id

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
        if limit is not UNSET:
            field_dict["limit"] = limit
        if offset is not UNSET:
            field_dict["offset"] = offset
        if snapshot_id is not UNSET:
            field_dict["snapshot_id"] = snapshot_id
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

        limit = d.pop("limit", UNSET)

        offset = d.pop("offset", UNSET)

        def _parse_snapshot_id(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        snapshot_id = _parse_snapshot_id(d.pop("snapshot_id", UNSET))

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
            limit=limit,
            offset=offset,
            snapshot_id=snapshot_id,
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

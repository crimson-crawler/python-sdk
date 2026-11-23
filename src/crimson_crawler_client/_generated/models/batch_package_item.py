from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, BinaryIO, Generator, Literal, TextIO, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="BatchPackageItem")


@_attrs_define
class BatchPackageItem:
    """Batch item: enrich an open-source package (OSV.dev).

    Attributes:
        ecosystem (str): Package ecosystem. Common loose spellings are normalized to OSV's canonical form (e.g. 'pypi' →
            'PyPI', 'cargo' → 'crates.io', 'go' → 'Go'); unrecognized values (incl. distro ecosystems like 'Debian') pass
            through verbatim.
        package (str): Package name as published in its ecosystem registry.
        include (list[str] | Unset): OSV advisory sections and nested CVE enrichment layers. Replaces the default list.
            Allowed values: affected, affected_products, campaigns, capec, cisa_kev, criteria, cwe, defend, details,
            detections, epss, exploits, groups, inferred_chain, kev, knowledgebase, log_sources, metasploit, misp,
            mitigations, navigator, nist_controls, nuclei, osv, osv_restricted, poc, poc_source, references, severity,
            similar_cves, software, ssvc, summary, techniques, tie, timeline, vendor_advisories, versions,
            affected_chipsets, csaf_advisories, cvss_bt, emb3d, sigma, vulnrichment, weakness_ranks, cellular_core,
            certfr_advisories, jvn, ot_vendor_advisories. `capec_full`, `csaf_advisories_full`, and `certfr_advisories_full`
            restore nested CVE rows. `vince`, `euvd`, `android_bulletin` and `cellular` are single-CVE-only sources and are
            rejected here: this endpoint fans out to every CVE the advisories alias. `osv_restricted` adds restricted and
            unknown-licence package and nested CVE advisories. `severity`, `affected`, and `references` choose the OSV
            advisory sections; every other layer is applied to each CVE the advisories alias to (`details` does both — it
            gates the advisory text and rides the per-CVE chain). `cisa_kev`, `criteria`, `metasploit`, `nuclei` and
            `vendor_advisories` are forwarded to that per-CVE chain as separate nested blocks. CISA KEV uses a stored
            catalog and contributes to KEV-derived scores; the other layers do not feed the offline authoritative path or
            the weaponization score. Advisory IDs, aliases, summaries, and fixed versions are always returned. `ot_context`
            is forwarded to each nested CVE (OT/RF context derived without a new upstream source).
        limit (int | Unset): Maximum advisories and CVEs per page (1–20) Default: 5.
        offset (int | Unset): Zero-based offset into each ranked result list Default: 0.
        snapshot_id (None | str | Unset): Snapshot returned by page 0; required for later pages
        type_ (Literal['package'] | Unset): Selects package enrichment for this batch item Default: 'package'.
        version (None | str | Unset): Installed version to filter advisories. Omit for versionless discovery in any
            stored ecosystem. Versioned matching supports PyPI, npm, Maven, Go, crates.io, RubyGems, NuGet, Packagist,
            Debian, Ubuntu and Alpine; other ecosystems report unsupported_ecosystem.
    """

    ecosystem: str
    package: str
    include: list[str] | Unset = UNSET
    limit: int | Unset = 5
    offset: int | Unset = 0
    snapshot_id: None | str | Unset = UNSET
    type_: Literal["package"] | Unset = "package"
    version: None | str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        ecosystem = self.ecosystem

        package = self.package

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

        type_ = self.type_

        version: None | str | Unset
        if isinstance(self.version, Unset):
            version = UNSET
        else:
            version = self.version

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "ecosystem": ecosystem,
                "package": package,
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
        if type_ is not UNSET:
            field_dict["type"] = type_
        if version is not UNSET:
            field_dict["version"] = version

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        ecosystem = d.pop("ecosystem")

        package = d.pop("package")

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

        type_ = cast(Literal["package"] | Unset, d.pop("type", UNSET))
        if type_ != "package" and not isinstance(type_, Unset):
            raise ValueError(f"type must match const 'package', got '{type_}'")

        def _parse_version(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        version = _parse_version(d.pop("version", UNSET))

        batch_package_item = cls(
            ecosystem=ecosystem,
            package=package,
            include=include,
            limit=limit,
            offset=offset,
            snapshot_id=snapshot_id,
            type_=type_,
            version=version,
        )

        batch_package_item.additional_properties = d
        return batch_package_item

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

from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, BinaryIO, Generator, TextIO, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="EnrichPackageRequest")


@_attrs_define
class EnrichPackageRequest:
    """Find vulnerabilities affecting an open-source package via OSV.dev.

    Keyed by package **ecosystem + name (+ optional version)** — the dependency-vuln
    surface (npm / PyPI / Go / Maven / crates.io / …) that the CPE-keyed `enrich/product`
    can't reach. With a version, results are filtered to advisories whose affected ranges
    include it; without one, every advisory for the package is returned.

        Attributes:
            ecosystem (str): Package ecosystem. Common loose spellings are normalized to OSV's canonical form (e.g. 'pypi' →
                'PyPI', 'cargo' → 'crates.io', 'go' → 'Go'); unrecognized values (incl. distro ecosystems like 'Debian') pass
                through verbatim.
            package (str): Package name as published in its ecosystem registry.
            include (list[str] | Unset): OSV advisory sections and nested CVE enrichment layers. Replaces the default list.
                Allowed values: affected, affected_products, campaigns, capec, cwe, defend, details, detections, epss, exploits,
                groups, inferred_chain, kev, knowledgebase, misp, mitigations, navigator, nist_controls, osv, poc, poc_source,
                references, sector_context, severity, similar_cves, software, ssvc, summary, techniques, tie, timeline, web,
                web_scrape. Advisory IDs, aliases, summaries, and fixed versions are always returned.
            version (None | str | Unset): Specific installed version to filter advisories to. Omit to list all advisories
                for the package.
    """

    ecosystem: str
    package: str
    include: list[str] | Unset = UNSET
    version: None | str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        ecosystem = self.ecosystem

        package = self.package

        include: list[str] | Unset = UNSET
        if not isinstance(self.include, Unset):
            include = self.include

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
        if version is not UNSET:
            field_dict["version"] = version

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        ecosystem = d.pop("ecosystem")

        package = d.pop("package")

        include = cast(list[str], d.pop("include", UNSET))

        def _parse_version(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        version = _parse_version(d.pop("version", UNSET))

        enrich_package_request = cls(
            ecosystem=ecosystem,
            package=package,
            include=include,
            version=version,
        )

        enrich_package_request.additional_properties = d
        return enrich_package_request

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

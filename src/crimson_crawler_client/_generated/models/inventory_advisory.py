from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, BinaryIO, Generator, TextIO, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="InventoryAdvisory")


@_attrs_define
class InventoryAdvisory:
    """A non-CVE OSV advisory captured on a package asset (GHSA-/PYSEC-/RUSTSEC-/GO-… with no CVE alias).

    CVE-aliased OSV advisories surface as fully-enriched `InventoryCVE`s in `top_cves`; this carries the
    ecosystem advisories OSV reports that carry NO CVE id — a large share of npm/PyPI/Go/crates findings —
    so a package vulnerable only via a GHSA still shows up on the asset instead of being silently dropped.

        Attributes:
            id (str): OSV advisory ID (e.g. GHSA-…, PYSEC-…, RUSTSEC-…, GO-…)
            aliases (list[str] | Unset): Cross-database aliases (no CVE — those become InventoryCVEs)
            fixed_versions (list[str] | Unset): Versions that fix the vulnerability for this package
            severity_label (None | str | Unset): Qualitative severity when declared, e.g. HIGH
            summary (None | str | Unset): One-line advisory summary
            url (None | str | Unset): Primary advisory link (first reference)
    """

    id: str
    aliases: list[str] | Unset = UNSET
    fixed_versions: list[str] | Unset = UNSET
    severity_label: None | str | Unset = UNSET
    summary: None | str | Unset = UNSET
    url: None | str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        id = self.id

        aliases: list[str] | Unset = UNSET
        if not isinstance(self.aliases, Unset):
            aliases = self.aliases

        fixed_versions: list[str] | Unset = UNSET
        if not isinstance(self.fixed_versions, Unset):
            fixed_versions = self.fixed_versions

        severity_label: None | str | Unset
        if isinstance(self.severity_label, Unset):
            severity_label = UNSET
        else:
            severity_label = self.severity_label

        summary: None | str | Unset
        if isinstance(self.summary, Unset):
            summary = UNSET
        else:
            summary = self.summary

        url: None | str | Unset
        if isinstance(self.url, Unset):
            url = UNSET
        else:
            url = self.url

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "id": id,
            }
        )
        if aliases is not UNSET:
            field_dict["aliases"] = aliases
        if fixed_versions is not UNSET:
            field_dict["fixed_versions"] = fixed_versions
        if severity_label is not UNSET:
            field_dict["severity_label"] = severity_label
        if summary is not UNSET:
            field_dict["summary"] = summary
        if url is not UNSET:
            field_dict["url"] = url

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        id = d.pop("id")

        aliases = cast(list[str], d.pop("aliases", UNSET))

        fixed_versions = cast(list[str], d.pop("fixed_versions", UNSET))

        def _parse_severity_label(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        severity_label = _parse_severity_label(d.pop("severity_label", UNSET))

        def _parse_summary(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        summary = _parse_summary(d.pop("summary", UNSET))

        def _parse_url(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        url = _parse_url(d.pop("url", UNSET))

        inventory_advisory = cls(
            id=id,
            aliases=aliases,
            fixed_versions=fixed_versions,
            severity_label=severity_label,
            summary=summary,
            url=url,
        )

        inventory_advisory.additional_properties = d
        return inventory_advisory

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

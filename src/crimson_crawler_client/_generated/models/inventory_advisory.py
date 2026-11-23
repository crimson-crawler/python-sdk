from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, BinaryIO, Generator, TextIO, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.osv_advisory_warning import OSVAdvisoryWarning


T = TypeVar("T", bound="InventoryAdvisory")


@_attrs_define
class InventoryAdvisory:
    """An OSV advisory captured on a package asset that is not a fully-enriched `InventoryCVE`.

    Two kinds land here: ecosystem advisories with NO CVE alias (GHSA-/PYSEC-/RUSTSEC-/GO-… — a
    large share of npm/PyPI/Go/crates findings, so a package vulnerable only via a GHSA still shows
    up instead of being silently dropped), and CVE-aliased advisories whose CVE alias the CVE
    catalog could not resolve (the CVE never enriched into `top_cves`, so the OSV-confirmed
    vulnerability is still surfaced rather than lost).

        Attributes:
            id (str): OSV advisory ID (e.g. GHSA-…, PYSEC-…, RUSTSEC-…, GO-…)
            aliases (list[str] | Unset): Cross-database aliases. CVE aliases present here were NOT resolved into an
                InventoryCVE (the CVE catalog had no record for them); they remain visible on the advisory so the OSV-confirmed
                vulnerability is never lost.
            attribution (None | str | Unset): Source attribution
            fixed_versions (list[str] | Unset): Versions that fix the vulnerability for this package
            licence (None | str | Unset): Source licence
            licence_url (None | str | Unset): Source licence URL
            projection_truncated (bool | None | Unset): Whether oversized sections were omitted
            severity_label (None | str | Unset): Qualitative severity when declared, e.g. HIGH
            source (None | str | Unset): Original OSV source
            source_ecosystems (list[str] | None | Unset): OSV dump ecosystems containing the advisory
            source_url (None | str | Unset): OSV advisory URL
            summary (None | str | Unset): One-line advisory summary
            unmodified_record_json (None | str | Unset): Complete no-derivatives JSON; omitted above 1 MiB
            url (None | str | Unset): Primary advisory link (first reference)
            version_affected (bool | None | Unset): Whether the queried version is affected
            version_fixed (bool | None | Unset): Whether the queried version is fixed
            warnings (list[OSVAdvisoryWarning] | Unset): Bounded source-field warnings for this advisory
            warnings_total (int | Unset): Observed warning count; a lower bound when diagnostics are incomplete Default: 0.
            warnings_truncated (bool | Unset): Whether warning diagnostics are incomplete Default: False.
    """

    id: str
    aliases: list[str] | Unset = UNSET
    attribution: None | str | Unset = UNSET
    fixed_versions: list[str] | Unset = UNSET
    licence: None | str | Unset = UNSET
    licence_url: None | str | Unset = UNSET
    projection_truncated: bool | None | Unset = UNSET
    severity_label: None | str | Unset = UNSET
    source: None | str | Unset = UNSET
    source_ecosystems: list[str] | None | Unset = UNSET
    source_url: None | str | Unset = UNSET
    summary: None | str | Unset = UNSET
    unmodified_record_json: None | str | Unset = UNSET
    url: None | str | Unset = UNSET
    version_affected: bool | None | Unset = UNSET
    version_fixed: bool | None | Unset = UNSET
    warnings: list[OSVAdvisoryWarning] | Unset = UNSET
    warnings_total: int | Unset = 0
    warnings_truncated: bool | Unset = False
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        from ..models.osv_advisory_warning import OSVAdvisoryWarning  # noqa: PLC0415

        id = self.id

        aliases: list[str] | Unset = UNSET
        if not isinstance(self.aliases, Unset):
            aliases = self.aliases

        attribution: None | str | Unset
        if isinstance(self.attribution, Unset):
            attribution = UNSET
        else:
            attribution = self.attribution

        fixed_versions: list[str] | Unset = UNSET
        if not isinstance(self.fixed_versions, Unset):
            fixed_versions = self.fixed_versions

        licence: None | str | Unset
        if isinstance(self.licence, Unset):
            licence = UNSET
        else:
            licence = self.licence

        licence_url: None | str | Unset
        if isinstance(self.licence_url, Unset):
            licence_url = UNSET
        else:
            licence_url = self.licence_url

        projection_truncated: bool | None | Unset
        if isinstance(self.projection_truncated, Unset):
            projection_truncated = UNSET
        else:
            projection_truncated = self.projection_truncated

        severity_label: None | str | Unset
        if isinstance(self.severity_label, Unset):
            severity_label = UNSET
        else:
            severity_label = self.severity_label

        source: None | str | Unset
        if isinstance(self.source, Unset):
            source = UNSET
        else:
            source = self.source

        source_ecosystems: list[str] | None | Unset
        if isinstance(self.source_ecosystems, Unset):
            source_ecosystems = UNSET
        elif isinstance(self.source_ecosystems, list):
            source_ecosystems = self.source_ecosystems

        else:
            source_ecosystems = self.source_ecosystems

        source_url: None | str | Unset
        if isinstance(self.source_url, Unset):
            source_url = UNSET
        else:
            source_url = self.source_url

        summary: None | str | Unset
        if isinstance(self.summary, Unset):
            summary = UNSET
        else:
            summary = self.summary

        unmodified_record_json: None | str | Unset
        if isinstance(self.unmodified_record_json, Unset):
            unmodified_record_json = UNSET
        else:
            unmodified_record_json = self.unmodified_record_json

        url: None | str | Unset
        if isinstance(self.url, Unset):
            url = UNSET
        else:
            url = self.url

        version_affected: bool | None | Unset
        if isinstance(self.version_affected, Unset):
            version_affected = UNSET
        else:
            version_affected = self.version_affected

        version_fixed: bool | None | Unset
        if isinstance(self.version_fixed, Unset):
            version_fixed = UNSET
        else:
            version_fixed = self.version_fixed

        warnings: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.warnings, Unset):
            warnings = []
            for warnings_item_data in self.warnings:
                warnings_item = warnings_item_data.to_dict()
                warnings.append(warnings_item)

        warnings_total = self.warnings_total

        warnings_truncated = self.warnings_truncated

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "id": id,
            }
        )
        if aliases is not UNSET:
            field_dict["aliases"] = aliases
        if attribution is not UNSET:
            field_dict["attribution"] = attribution
        if fixed_versions is not UNSET:
            field_dict["fixed_versions"] = fixed_versions
        if licence is not UNSET:
            field_dict["licence"] = licence
        if licence_url is not UNSET:
            field_dict["licence_url"] = licence_url
        if projection_truncated is not UNSET:
            field_dict["projection_truncated"] = projection_truncated
        if severity_label is not UNSET:
            field_dict["severity_label"] = severity_label
        if source is not UNSET:
            field_dict["source"] = source
        if source_ecosystems is not UNSET:
            field_dict["source_ecosystems"] = source_ecosystems
        if source_url is not UNSET:
            field_dict["source_url"] = source_url
        if summary is not UNSET:
            field_dict["summary"] = summary
        if unmodified_record_json is not UNSET:
            field_dict["unmodified_record_json"] = unmodified_record_json
        if url is not UNSET:
            field_dict["url"] = url
        if version_affected is not UNSET:
            field_dict["version_affected"] = version_affected
        if version_fixed is not UNSET:
            field_dict["version_fixed"] = version_fixed
        if warnings is not UNSET:
            field_dict["warnings"] = warnings
        if warnings_total is not UNSET:
            field_dict["warnings_total"] = warnings_total
        if warnings_truncated is not UNSET:
            field_dict["warnings_truncated"] = warnings_truncated

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.osv_advisory_warning import OSVAdvisoryWarning  # noqa: PLC0415

        d = dict(src_dict)
        id = d.pop("id")

        aliases = cast(list[str], d.pop("aliases", UNSET))

        def _parse_attribution(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        attribution = _parse_attribution(d.pop("attribution", UNSET))

        fixed_versions = cast(list[str], d.pop("fixed_versions", UNSET))

        def _parse_licence(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        licence = _parse_licence(d.pop("licence", UNSET))

        def _parse_licence_url(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        licence_url = _parse_licence_url(d.pop("licence_url", UNSET))

        def _parse_projection_truncated(data: object) -> bool | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(bool | None | Unset, data)

        projection_truncated = _parse_projection_truncated(d.pop("projection_truncated", UNSET))

        def _parse_severity_label(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        severity_label = _parse_severity_label(d.pop("severity_label", UNSET))

        def _parse_source(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        source = _parse_source(d.pop("source", UNSET))

        def _parse_source_ecosystems(data: object) -> list[str] | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, list):
                    raise TypeError()
                source_ecosystems_type_0 = cast(list[str], data)

                return source_ecosystems_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(list[str] | None | Unset, data)

        source_ecosystems = _parse_source_ecosystems(d.pop("source_ecosystems", UNSET))

        def _parse_source_url(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        source_url = _parse_source_url(d.pop("source_url", UNSET))

        def _parse_summary(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        summary = _parse_summary(d.pop("summary", UNSET))

        def _parse_unmodified_record_json(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        unmodified_record_json = _parse_unmodified_record_json(d.pop("unmodified_record_json", UNSET))

        def _parse_url(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        url = _parse_url(d.pop("url", UNSET))

        def _parse_version_affected(data: object) -> bool | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(bool | None | Unset, data)

        version_affected = _parse_version_affected(d.pop("version_affected", UNSET))

        def _parse_version_fixed(data: object) -> bool | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(bool | None | Unset, data)

        version_fixed = _parse_version_fixed(d.pop("version_fixed", UNSET))

        _warnings = d.pop("warnings", UNSET)
        warnings: list[OSVAdvisoryWarning] | Unset = UNSET
        if _warnings is not UNSET:
            warnings = []
            for warnings_item_data in _warnings:
                warnings_item = OSVAdvisoryWarning.from_dict(warnings_item_data)

                warnings.append(warnings_item)

        warnings_total = d.pop("warnings_total", UNSET)

        warnings_truncated = d.pop("warnings_truncated", UNSET)

        inventory_advisory = cls(
            id=id,
            aliases=aliases,
            attribution=attribution,
            fixed_versions=fixed_versions,
            licence=licence,
            licence_url=licence_url,
            projection_truncated=projection_truncated,
            severity_label=severity_label,
            source=source,
            source_ecosystems=source_ecosystems,
            source_url=source_url,
            summary=summary,
            unmodified_record_json=unmodified_record_json,
            url=url,
            version_affected=version_affected,
            version_fixed=version_fixed,
            warnings=warnings,
            warnings_total=warnings_total,
            warnings_truncated=warnings_truncated,
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

from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, BinaryIO, Generator, TextIO, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.cve_reference import CVEReference
    from ..models.osv_affected_range import OSVAffectedRange


T = TypeVar("T", bound="OSVAdvisory")


@_attrs_define
class OSVAdvisory:
    """A single OSV advisory, curated for an open-source package.

    Attributes:
        id (str): OSV advisory ID (e.g. GHSA-…, PYSEC-…, RUSTSEC-…)
        affected_ranges (list[OSVAffectedRange] | Unset): Affected / fixed version ranges (`affected`)
        aliases (list[str] | Unset): Cross-database aliases (CVE, GHSA, …)
        cve_ids (list[str] | Unset): CVE aliases extracted from `aliases`
        cvss_vector (None | str | Unset): CVSS vector string from the advisory (`severity` include)
        cwe_ids (list[str] | Unset): CWE IDs from the advisory's database_specific (`severity` include)
        details (None | str | Unset): Long advisory text (truncated; `details` include)
        fixed_versions (list[str] | Unset): Versions that fix the vulnerability for the queried package
        modified (None | str | Unset): Last-modified timestamp
        published (None | str | Unset): Publication timestamp
        references (list[CVEReference] | Unset): Advisory and fix links — `references` include
        severity_label (None | str | Unset): Qualitative severity when declared, e.g. HIGH
        summary (None | str | Unset): One-line advisory summary
    """

    id: str
    affected_ranges: list[OSVAffectedRange] | Unset = UNSET
    aliases: list[str] | Unset = UNSET
    cve_ids: list[str] | Unset = UNSET
    cvss_vector: None | str | Unset = UNSET
    cwe_ids: list[str] | Unset = UNSET
    details: None | str | Unset = UNSET
    fixed_versions: list[str] | Unset = UNSET
    modified: None | str | Unset = UNSET
    published: None | str | Unset = UNSET
    references: list[CVEReference] | Unset = UNSET
    severity_label: None | str | Unset = UNSET
    summary: None | str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        from ..models.cve_reference import CVEReference
        from ..models.osv_affected_range import OSVAffectedRange

        id = self.id

        affected_ranges: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.affected_ranges, Unset):
            affected_ranges = []
            for affected_ranges_item_data in self.affected_ranges:
                affected_ranges_item = affected_ranges_item_data.to_dict()
                affected_ranges.append(affected_ranges_item)

        aliases: list[str] | Unset = UNSET
        if not isinstance(self.aliases, Unset):
            aliases = self.aliases

        cve_ids: list[str] | Unset = UNSET
        if not isinstance(self.cve_ids, Unset):
            cve_ids = self.cve_ids

        cvss_vector: None | str | Unset
        if isinstance(self.cvss_vector, Unset):
            cvss_vector = UNSET
        else:
            cvss_vector = self.cvss_vector

        cwe_ids: list[str] | Unset = UNSET
        if not isinstance(self.cwe_ids, Unset):
            cwe_ids = self.cwe_ids

        details: None | str | Unset
        if isinstance(self.details, Unset):
            details = UNSET
        else:
            details = self.details

        fixed_versions: list[str] | Unset = UNSET
        if not isinstance(self.fixed_versions, Unset):
            fixed_versions = self.fixed_versions

        modified: None | str | Unset
        if isinstance(self.modified, Unset):
            modified = UNSET
        else:
            modified = self.modified

        published: None | str | Unset
        if isinstance(self.published, Unset):
            published = UNSET
        else:
            published = self.published

        references: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.references, Unset):
            references = []
            for references_item_data in self.references:
                references_item = references_item_data.to_dict()
                references.append(references_item)

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

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "id": id,
            }
        )
        if affected_ranges is not UNSET:
            field_dict["affected_ranges"] = affected_ranges
        if aliases is not UNSET:
            field_dict["aliases"] = aliases
        if cve_ids is not UNSET:
            field_dict["cve_ids"] = cve_ids
        if cvss_vector is not UNSET:
            field_dict["cvss_vector"] = cvss_vector
        if cwe_ids is not UNSET:
            field_dict["cwe_ids"] = cwe_ids
        if details is not UNSET:
            field_dict["details"] = details
        if fixed_versions is not UNSET:
            field_dict["fixed_versions"] = fixed_versions
        if modified is not UNSET:
            field_dict["modified"] = modified
        if published is not UNSET:
            field_dict["published"] = published
        if references is not UNSET:
            field_dict["references"] = references
        if severity_label is not UNSET:
            field_dict["severity_label"] = severity_label
        if summary is not UNSET:
            field_dict["summary"] = summary

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.cve_reference import CVEReference
        from ..models.osv_affected_range import OSVAffectedRange

        d = dict(src_dict)
        id = d.pop("id")

        _affected_ranges = d.pop("affected_ranges", UNSET)
        affected_ranges: list[OSVAffectedRange] | Unset = UNSET
        if _affected_ranges is not UNSET:
            affected_ranges = []
            for affected_ranges_item_data in _affected_ranges:
                affected_ranges_item = OSVAffectedRange.from_dict(affected_ranges_item_data)

                affected_ranges.append(affected_ranges_item)

        aliases = cast(list[str], d.pop("aliases", UNSET))

        cve_ids = cast(list[str], d.pop("cve_ids", UNSET))

        def _parse_cvss_vector(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        cvss_vector = _parse_cvss_vector(d.pop("cvss_vector", UNSET))

        cwe_ids = cast(list[str], d.pop("cwe_ids", UNSET))

        def _parse_details(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        details = _parse_details(d.pop("details", UNSET))

        fixed_versions = cast(list[str], d.pop("fixed_versions", UNSET))

        def _parse_modified(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        modified = _parse_modified(d.pop("modified", UNSET))

        def _parse_published(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        published = _parse_published(d.pop("published", UNSET))

        _references = d.pop("references", UNSET)
        references: list[CVEReference] | Unset = UNSET
        if _references is not UNSET:
            references = []
            for references_item_data in _references:
                references_item = CVEReference.from_dict(references_item_data)

                references.append(references_item)

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

        osv_advisory = cls(
            id=id,
            affected_ranges=affected_ranges,
            aliases=aliases,
            cve_ids=cve_ids,
            cvss_vector=cvss_vector,
            cwe_ids=cwe_ids,
            details=details,
            fixed_versions=fixed_versions,
            modified=modified,
            published=published,
            references=references,
            severity_label=severity_label,
            summary=summary,
        )

        osv_advisory.additional_properties = d
        return osv_advisory

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

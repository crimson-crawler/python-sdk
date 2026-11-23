from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, BinaryIO, Generator, TextIO, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.osv_advisory_ecosystem_specific import OSVAdvisoryEcosystemSpecific
    from ..models.osv_advisory_warning import OSVAdvisoryWarning
    from ..models.osv_affected_package import OSVAffectedPackage
    from ..models.osv_affected_range import OSVAffectedRange
    from ..models.osv_reference import OSVReference


T = TypeVar("T", bound="OSVAdvisory")


@_attrs_define
class OSVAdvisory:
    """A single OSV advisory, curated for an open-source package.

    Attributes:
        id (str): OSV advisory ID (e.g. GHSA-…, PYSEC-…, RUSTSEC-…)
        affected_packages (list[OSVAffectedPackage] | Unset): One row per `affected[]` entry, keeping each package's own
            purl and metadata. This is what makes a multi-package advisory readable per package, and the only place an entry
            that declares neither ranges nor versions stays visible.
        affected_ranges (list[OSVAffectedRange] | Unset): Affected / fixed version ranges (`affected`)
        aliases (list[None | str] | Unset): Cross-database aliases (CVE, GHSA, …)
        attribution (None | str | Unset): Source attribution
        cve_ids (list[str] | Unset): CVE identifiers equivalent to this advisory: its own CVE id and its `aliases`.
            Directional `upstream` and `related` identifiers are not aliases.
        cvss_v3_vector (None | str | Unset): CVSS v3.x vector string from the advisory, when it publishes one
            (`severity` include)
        cvss_v4_vector (None | str | Unset): CVSS v4.0 vector string from the advisory (`severity` include). OSV ships
            v4 for about a third of advisories; it was previously dropped whenever a v3 entry came first.
        cwe_ids (list[None | str] | Unset): CWE IDs from the advisory's database_specific (`severity` include)
        details (None | str | Unset): Long advisory text (truncated; `details` include)
        ecosystem_specific (OSVAdvisoryEcosystemSpecific | Unset): The queried package's `affected[].ecosystem_specific`
            block — for Go advisories this is where the vulnerable import path and symbols are named (`packages`, `imports`,
            `symbols`), which no other field carries. Empty when the advisory covers several packages and they disagree,
            because one block cannot describe all of them
        fixed_versions (list[str] | Unset): Release versions that fix the vulnerability for the queried package. A `GIT`
            range's `fixed` value is a commit SHA and is kept on the range (with its `repo`) rather than listed here, which
            would relabel a commit as a version
        licence (None | str | Unset): Original source licence, when known
        licence_url (None | str | Unset): Source licence URL
        modified (None | str | Unset): Last-modified timestamp
        package_purl (None | str | Unset): The queried package's Package URL (`affected[].package.purl`) — the
            ecosystem-independent identity a scanner matches against its own SBOM. Null when the advisory covers several
            packages with different purls (a Go advisory can cover a module and `stdlib`), rather than picking one of them
        projection_truncated (bool | None | Unset): Whether oversized advisory sections were omitted
        published (None | str | Unset): Publication timestamp
        references (list[OSVReference] | Unset): Advisory and fix links — `references` include
        related_ids (list[None | str] | Unset): Ids OSV marks related but NOT aliased (`related`) — a different advisory
            covering the same code, familiar from a different angle, or sharing the same reporters' mapping. Deliberately
            kept apart from `aliases`/`cve_ids`: GO-2023-2102 aliases CVE-2023-39325 and relates CVE-2023-44487, a separate
            HTTP/2 vulnerability
        severity_label (None | str | Unset): Qualitative severity when declared, e.g. HIGH
        source (None | str | Unset): Original OSV advisory source
        source_ecosystems (list[str] | None | Unset): OSV dump ecosystems containing this advisory
        source_url (None | str | Unset): OSV advisory URL
        summary (None | str | Unset): One-line advisory summary
        unmodified_record_json (None | str | Unset): Complete no-derivatives record as JSON; omitted above 1 MiB or when
            it cannot fit a public package page, use source_url
        upstream_ids (list[None | str] | Unset): Directional upstream vulnerability references, not aliases
        upstream_present (bool | None | Unset): Whether directional upstream references exist
        version_affected (bool | None | Unset): Whether the queried package version is affected
        version_fixed (bool | None | Unset): Whether the queried package version is fixed
        warnings (list[OSVAdvisoryWarning] | Unset): Bounded source-field warnings for this advisory
        warnings_total (int | Unset): Observed warning count; a lower bound when diagnostics are incomplete Default: 0.
        warnings_truncated (bool | Unset): Whether warning diagnostics are incomplete Default: False.
        withdrawn (bool | None | str | Unset): Withdrawal timestamp for ordinary advisories. For no-derivatives records,
            true marks a withdrawn advisory and withdrawn_at carries the source timestamp in the API envelope.
        withdrawn_at (None | str | Unset): Original withdrawal timestamp on a no-derivatives envelope
    """

    id: str
    affected_packages: list[OSVAffectedPackage] | Unset = UNSET
    affected_ranges: list[OSVAffectedRange] | Unset = UNSET
    aliases: list[None | str] | Unset = UNSET
    attribution: None | str | Unset = UNSET
    cve_ids: list[str] | Unset = UNSET
    cvss_v3_vector: None | str | Unset = UNSET
    cvss_v4_vector: None | str | Unset = UNSET
    cwe_ids: list[None | str] | Unset = UNSET
    details: None | str | Unset = UNSET
    ecosystem_specific: OSVAdvisoryEcosystemSpecific | Unset = UNSET
    fixed_versions: list[str] | Unset = UNSET
    licence: None | str | Unset = UNSET
    licence_url: None | str | Unset = UNSET
    modified: None | str | Unset = UNSET
    package_purl: None | str | Unset = UNSET
    projection_truncated: bool | None | Unset = UNSET
    published: None | str | Unset = UNSET
    references: list[OSVReference] | Unset = UNSET
    related_ids: list[None | str] | Unset = UNSET
    severity_label: None | str | Unset = UNSET
    source: None | str | Unset = UNSET
    source_ecosystems: list[str] | None | Unset = UNSET
    source_url: None | str | Unset = UNSET
    summary: None | str | Unset = UNSET
    unmodified_record_json: None | str | Unset = UNSET
    upstream_ids: list[None | str] | Unset = UNSET
    upstream_present: bool | None | Unset = UNSET
    version_affected: bool | None | Unset = UNSET
    version_fixed: bool | None | Unset = UNSET
    warnings: list[OSVAdvisoryWarning] | Unset = UNSET
    warnings_total: int | Unset = 0
    warnings_truncated: bool | Unset = False
    withdrawn: bool | None | str | Unset = UNSET
    withdrawn_at: None | str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        from ..models.osv_advisory_ecosystem_specific import OSVAdvisoryEcosystemSpecific  # noqa: PLC0415
        from ..models.osv_advisory_warning import OSVAdvisoryWarning  # noqa: PLC0415
        from ..models.osv_affected_package import OSVAffectedPackage  # noqa: PLC0415
        from ..models.osv_affected_range import OSVAffectedRange  # noqa: PLC0415
        from ..models.osv_reference import OSVReference  # noqa: PLC0415

        id = self.id

        affected_packages: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.affected_packages, Unset):
            affected_packages = []
            for affected_packages_item_data in self.affected_packages:
                affected_packages_item = affected_packages_item_data.to_dict()
                affected_packages.append(affected_packages_item)

        affected_ranges: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.affected_ranges, Unset):
            affected_ranges = []
            for affected_ranges_item_data in self.affected_ranges:
                affected_ranges_item = affected_ranges_item_data.to_dict()
                affected_ranges.append(affected_ranges_item)

        aliases: list[None | str] | Unset = UNSET
        if not isinstance(self.aliases, Unset):
            aliases = []
            for aliases_item_data in self.aliases:
                aliases_item: None | str
                aliases_item = aliases_item_data
                aliases.append(aliases_item)

        attribution: None | str | Unset
        if isinstance(self.attribution, Unset):
            attribution = UNSET
        else:
            attribution = self.attribution

        cve_ids: list[str] | Unset = UNSET
        if not isinstance(self.cve_ids, Unset):
            cve_ids = self.cve_ids

        cvss_v3_vector: None | str | Unset
        if isinstance(self.cvss_v3_vector, Unset):
            cvss_v3_vector = UNSET
        else:
            cvss_v3_vector = self.cvss_v3_vector

        cvss_v4_vector: None | str | Unset
        if isinstance(self.cvss_v4_vector, Unset):
            cvss_v4_vector = UNSET
        else:
            cvss_v4_vector = self.cvss_v4_vector

        cwe_ids: list[None | str] | Unset = UNSET
        if not isinstance(self.cwe_ids, Unset):
            cwe_ids = []
            for cwe_ids_item_data in self.cwe_ids:
                cwe_ids_item: None | str
                cwe_ids_item = cwe_ids_item_data
                cwe_ids.append(cwe_ids_item)

        details: None | str | Unset
        if isinstance(self.details, Unset):
            details = UNSET
        else:
            details = self.details

        ecosystem_specific: dict[str, Any] | Unset = UNSET
        if not isinstance(self.ecosystem_specific, Unset):
            ecosystem_specific = self.ecosystem_specific.to_dict()

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

        modified: None | str | Unset
        if isinstance(self.modified, Unset):
            modified = UNSET
        else:
            modified = self.modified

        package_purl: None | str | Unset
        if isinstance(self.package_purl, Unset):
            package_purl = UNSET
        else:
            package_purl = self.package_purl

        projection_truncated: bool | None | Unset
        if isinstance(self.projection_truncated, Unset):
            projection_truncated = UNSET
        else:
            projection_truncated = self.projection_truncated

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

        related_ids: list[None | str] | Unset = UNSET
        if not isinstance(self.related_ids, Unset):
            related_ids = []
            for related_ids_item_data in self.related_ids:
                related_ids_item: None | str
                related_ids_item = related_ids_item_data
                related_ids.append(related_ids_item)

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

        upstream_ids: list[None | str] | Unset = UNSET
        if not isinstance(self.upstream_ids, Unset):
            upstream_ids = []
            for upstream_ids_item_data in self.upstream_ids:
                upstream_ids_item: None | str
                upstream_ids_item = upstream_ids_item_data
                upstream_ids.append(upstream_ids_item)

        upstream_present: bool | None | Unset
        if isinstance(self.upstream_present, Unset):
            upstream_present = UNSET
        else:
            upstream_present = self.upstream_present

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

        withdrawn: bool | None | str | Unset
        if isinstance(self.withdrawn, Unset):
            withdrawn = UNSET
        else:
            withdrawn = self.withdrawn

        withdrawn_at: None | str | Unset
        if isinstance(self.withdrawn_at, Unset):
            withdrawn_at = UNSET
        else:
            withdrawn_at = self.withdrawn_at

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "id": id,
            }
        )
        if affected_packages is not UNSET:
            field_dict["affected_packages"] = affected_packages
        if affected_ranges is not UNSET:
            field_dict["affected_ranges"] = affected_ranges
        if aliases is not UNSET:
            field_dict["aliases"] = aliases
        if attribution is not UNSET:
            field_dict["attribution"] = attribution
        if cve_ids is not UNSET:
            field_dict["cve_ids"] = cve_ids
        if cvss_v3_vector is not UNSET:
            field_dict["cvss_v3_vector"] = cvss_v3_vector
        if cvss_v4_vector is not UNSET:
            field_dict["cvss_v4_vector"] = cvss_v4_vector
        if cwe_ids is not UNSET:
            field_dict["cwe_ids"] = cwe_ids
        if details is not UNSET:
            field_dict["details"] = details
        if ecosystem_specific is not UNSET:
            field_dict["ecosystem_specific"] = ecosystem_specific
        if fixed_versions is not UNSET:
            field_dict["fixed_versions"] = fixed_versions
        if licence is not UNSET:
            field_dict["licence"] = licence
        if licence_url is not UNSET:
            field_dict["licence_url"] = licence_url
        if modified is not UNSET:
            field_dict["modified"] = modified
        if package_purl is not UNSET:
            field_dict["package_purl"] = package_purl
        if projection_truncated is not UNSET:
            field_dict["projection_truncated"] = projection_truncated
        if published is not UNSET:
            field_dict["published"] = published
        if references is not UNSET:
            field_dict["references"] = references
        if related_ids is not UNSET:
            field_dict["related_ids"] = related_ids
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
        if upstream_ids is not UNSET:
            field_dict["upstream_ids"] = upstream_ids
        if upstream_present is not UNSET:
            field_dict["upstream_present"] = upstream_present
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
        if withdrawn is not UNSET:
            field_dict["withdrawn"] = withdrawn
        if withdrawn_at is not UNSET:
            field_dict["withdrawn_at"] = withdrawn_at

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.osv_advisory_ecosystem_specific import OSVAdvisoryEcosystemSpecific  # noqa: PLC0415
        from ..models.osv_advisory_warning import OSVAdvisoryWarning  # noqa: PLC0415
        from ..models.osv_affected_package import OSVAffectedPackage  # noqa: PLC0415
        from ..models.osv_affected_range import OSVAffectedRange  # noqa: PLC0415
        from ..models.osv_reference import OSVReference  # noqa: PLC0415

        d = dict(src_dict)
        id = d.pop("id")

        _affected_packages = d.pop("affected_packages", UNSET)
        affected_packages: list[OSVAffectedPackage] | Unset = UNSET
        if _affected_packages is not UNSET:
            affected_packages = []
            for affected_packages_item_data in _affected_packages:
                affected_packages_item = OSVAffectedPackage.from_dict(affected_packages_item_data)

                affected_packages.append(affected_packages_item)

        _affected_ranges = d.pop("affected_ranges", UNSET)
        affected_ranges: list[OSVAffectedRange] | Unset = UNSET
        if _affected_ranges is not UNSET:
            affected_ranges = []
            for affected_ranges_item_data in _affected_ranges:
                affected_ranges_item = OSVAffectedRange.from_dict(affected_ranges_item_data)

                affected_ranges.append(affected_ranges_item)

        _aliases = d.pop("aliases", UNSET)
        aliases: list[None | str] | Unset = UNSET
        if _aliases is not UNSET:
            aliases = []
            for aliases_item_data in _aliases:

                def _parse_aliases_item(data: object) -> None | str:
                    if data is None:
                        return data
                    return cast(None | str, data)

                aliases_item = _parse_aliases_item(aliases_item_data)

                aliases.append(aliases_item)

        def _parse_attribution(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        attribution = _parse_attribution(d.pop("attribution", UNSET))

        cve_ids = cast(list[str], d.pop("cve_ids", UNSET))

        def _parse_cvss_v3_vector(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        cvss_v3_vector = _parse_cvss_v3_vector(d.pop("cvss_v3_vector", UNSET))

        def _parse_cvss_v4_vector(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        cvss_v4_vector = _parse_cvss_v4_vector(d.pop("cvss_v4_vector", UNSET))

        _cwe_ids = d.pop("cwe_ids", UNSET)
        cwe_ids: list[None | str] | Unset = UNSET
        if _cwe_ids is not UNSET:
            cwe_ids = []
            for cwe_ids_item_data in _cwe_ids:

                def _parse_cwe_ids_item(data: object) -> None | str:
                    if data is None:
                        return data
                    return cast(None | str, data)

                cwe_ids_item = _parse_cwe_ids_item(cwe_ids_item_data)

                cwe_ids.append(cwe_ids_item)

        def _parse_details(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        details = _parse_details(d.pop("details", UNSET))

        _ecosystem_specific = d.pop("ecosystem_specific", UNSET)
        ecosystem_specific: OSVAdvisoryEcosystemSpecific | Unset
        if isinstance(_ecosystem_specific, Unset):
            ecosystem_specific = UNSET
        else:
            ecosystem_specific = OSVAdvisoryEcosystemSpecific.from_dict(_ecosystem_specific)

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

        def _parse_modified(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        modified = _parse_modified(d.pop("modified", UNSET))

        def _parse_package_purl(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        package_purl = _parse_package_purl(d.pop("package_purl", UNSET))

        def _parse_projection_truncated(data: object) -> bool | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(bool | None | Unset, data)

        projection_truncated = _parse_projection_truncated(d.pop("projection_truncated", UNSET))

        def _parse_published(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        published = _parse_published(d.pop("published", UNSET))

        _references = d.pop("references", UNSET)
        references: list[OSVReference] | Unset = UNSET
        if _references is not UNSET:
            references = []
            for references_item_data in _references:
                references_item = OSVReference.from_dict(references_item_data)

                references.append(references_item)

        _related_ids = d.pop("related_ids", UNSET)
        related_ids: list[None | str] | Unset = UNSET
        if _related_ids is not UNSET:
            related_ids = []
            for related_ids_item_data in _related_ids:

                def _parse_related_ids_item(data: object) -> None | str:
                    if data is None:
                        return data
                    return cast(None | str, data)

                related_ids_item = _parse_related_ids_item(related_ids_item_data)

                related_ids.append(related_ids_item)

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

        _upstream_ids = d.pop("upstream_ids", UNSET)
        upstream_ids: list[None | str] | Unset = UNSET
        if _upstream_ids is not UNSET:
            upstream_ids = []
            for upstream_ids_item_data in _upstream_ids:

                def _parse_upstream_ids_item(data: object) -> None | str:
                    if data is None:
                        return data
                    return cast(None | str, data)

                upstream_ids_item = _parse_upstream_ids_item(upstream_ids_item_data)

                upstream_ids.append(upstream_ids_item)

        def _parse_upstream_present(data: object) -> bool | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(bool | None | Unset, data)

        upstream_present = _parse_upstream_present(d.pop("upstream_present", UNSET))

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

        def _parse_withdrawn(data: object) -> bool | None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(bool | None | str | Unset, data)

        withdrawn = _parse_withdrawn(d.pop("withdrawn", UNSET))

        def _parse_withdrawn_at(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        withdrawn_at = _parse_withdrawn_at(d.pop("withdrawn_at", UNSET))

        osv_advisory = cls(
            id=id,
            affected_packages=affected_packages,
            affected_ranges=affected_ranges,
            aliases=aliases,
            attribution=attribution,
            cve_ids=cve_ids,
            cvss_v3_vector=cvss_v3_vector,
            cvss_v4_vector=cvss_v4_vector,
            cwe_ids=cwe_ids,
            details=details,
            ecosystem_specific=ecosystem_specific,
            fixed_versions=fixed_versions,
            licence=licence,
            licence_url=licence_url,
            modified=modified,
            package_purl=package_purl,
            projection_truncated=projection_truncated,
            published=published,
            references=references,
            related_ids=related_ids,
            severity_label=severity_label,
            source=source,
            source_ecosystems=source_ecosystems,
            source_url=source_url,
            summary=summary,
            unmodified_record_json=unmodified_record_json,
            upstream_ids=upstream_ids,
            upstream_present=upstream_present,
            version_affected=version_affected,
            version_fixed=version_fixed,
            warnings=warnings,
            warnings_total=warnings_total,
            warnings_truncated=warnings_truncated,
            withdrawn=withdrawn,
            withdrawn_at=withdrawn_at,
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

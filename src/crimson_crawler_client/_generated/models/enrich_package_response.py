from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, BinaryIO, Generator, TextIO, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.catalogued_cve_response import CataloguedCVEResponse
    from ..models.cve_context_catalog import CVEContextCatalog
    from ..models.error_detail import ErrorDetail
    from ..models.osv_advisory import OSVAdvisory


T = TypeVar("T", bound="EnrichPackageResponse")


@_attrs_define
class EnrichPackageResponse:
    """Open-source package enrichment — OSV.dev advisories + full multi-source CVE enrichment.

    The package-ecosystem sibling of `EnrichProductResponse`: OSV gives the advisories, and the CVEs
    they alias are enriched through the same multi-source CWE→CAPEC→ATT&CK + EPSS/KEV chain
    as `enrich/product`'s nested CVEs — gated by the CVE-chain `include` options.

        Attributes:
            ecosystem (str): Canonical OSV ecosystem queried
            package (str): Package name queried
            advisories (list[OSVAdvisory] | Unset): Matched OSV advisories (CVE-aliased first, then by id), withdrawn ones
                included — each carries its own `withdrawn` flag, and it is the flag (not an absent row) that reports the
                retraction. Only non-withdrawn advisories drive `vulnerability_count`, `cves`, and the fixed versions behind any
                remediation
            advisories_discovered (int | Unset): Total matched advisories before paging Default: 0.
            cve_context_catalog (CVEContextCatalog | Unset): Page-local shared CVE context, keyed by identifier with
                suffixes for differing versions.
            cves (list[CataloguedCVEResponse] | Unset): Paged CVE enrichment; shared context layers reference
                cve_context_catalog
            cves_discovered (int | Unset): Distinct active CVEs referenced by matched advisories Default: 0.
            cves_enrichment_limit (int | Unset): Maximum CVEs enriched and returned across all pages Default: 0.
            discovery_truncated (bool | None | Unset): Whether discovery was truncated; null if unknown
            discovery_truncation_reason (None | str | Unset): Why discovery is incomplete
            errors (list[ErrorDetail] | Unset): Partial failure details
            highest_weaponization_score (float | None | Unset): Max 0-100 weaponization score across the package's enriched
                CVEs
            identifier_resolved (bool | None | Unset): Whether the package matched any OSV advisories. `false` means OSV
                returned nothing for this ecosystem/package/version, which cannot distinguish a nonexistent package from a real
                package with no known advisories — the two were previously indistinguishable. `null` when resolution was not
                evaluated.
            next_offset (int | None | Unset): Offset for the next advisory and CVE page
            paging_incomplete (bool | Unset): Whether any page data could not be read Default: False.
            rollups_cve_ids (list[str] | Unset): CVE IDs included in the package rollups
            rollups_over (int | Unset): Number of CVEs contributing to package rollups Default: 0.
            snapshot_id (None | str | Unset): Snapshot identifier for continuation, expires after 30 minutes
            version (None | str | Unset): Version filter applied (if any)
            vulnerability_count (int | Unset): Number of ACTIVE advisories matched — a withdrawn advisory (OSV `withdrawn`
                set) is excluded, because the database retracted it and counting it would read as a live finding. The advisory
                itself is still returned in `advisories`, which is the list to check for it Default: 0.
    """

    ecosystem: str
    package: str
    advisories: list[OSVAdvisory] | Unset = UNSET
    advisories_discovered: int | Unset = 0
    cve_context_catalog: CVEContextCatalog | Unset = UNSET
    cves: list[CataloguedCVEResponse] | Unset = UNSET
    cves_discovered: int | Unset = 0
    cves_enrichment_limit: int | Unset = 0
    discovery_truncated: bool | None | Unset = UNSET
    discovery_truncation_reason: None | str | Unset = UNSET
    errors: list[ErrorDetail] | Unset = UNSET
    highest_weaponization_score: float | None | Unset = UNSET
    identifier_resolved: bool | None | Unset = UNSET
    next_offset: int | None | Unset = UNSET
    paging_incomplete: bool | Unset = False
    rollups_cve_ids: list[str] | Unset = UNSET
    rollups_over: int | Unset = 0
    snapshot_id: None | str | Unset = UNSET
    version: None | str | Unset = UNSET
    vulnerability_count: int | Unset = 0
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        from ..models.catalogued_cve_response import CataloguedCVEResponse  # noqa: PLC0415
        from ..models.cve_context_catalog import CVEContextCatalog  # noqa: PLC0415
        from ..models.error_detail import ErrorDetail  # noqa: PLC0415
        from ..models.osv_advisory import OSVAdvisory  # noqa: PLC0415

        ecosystem = self.ecosystem

        package = self.package

        advisories: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.advisories, Unset):
            advisories = []
            for advisories_item_data in self.advisories:
                advisories_item = advisories_item_data.to_dict()
                advisories.append(advisories_item)

        advisories_discovered = self.advisories_discovered

        cve_context_catalog: dict[str, Any] | Unset = UNSET
        if not isinstance(self.cve_context_catalog, Unset):
            cve_context_catalog = self.cve_context_catalog.to_dict()

        cves: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.cves, Unset):
            cves = []
            for cves_item_data in self.cves:
                cves_item = cves_item_data.to_dict()
                cves.append(cves_item)

        cves_discovered = self.cves_discovered

        cves_enrichment_limit = self.cves_enrichment_limit

        discovery_truncated: bool | None | Unset
        if isinstance(self.discovery_truncated, Unset):
            discovery_truncated = UNSET
        else:
            discovery_truncated = self.discovery_truncated

        discovery_truncation_reason: None | str | Unset
        if isinstance(self.discovery_truncation_reason, Unset):
            discovery_truncation_reason = UNSET
        else:
            discovery_truncation_reason = self.discovery_truncation_reason

        errors: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.errors, Unset):
            errors = []
            for errors_item_data in self.errors:
                errors_item = errors_item_data.to_dict()
                errors.append(errors_item)

        highest_weaponization_score: float | None | Unset
        if isinstance(self.highest_weaponization_score, Unset):
            highest_weaponization_score = UNSET
        else:
            highest_weaponization_score = self.highest_weaponization_score

        identifier_resolved: bool | None | Unset
        if isinstance(self.identifier_resolved, Unset):
            identifier_resolved = UNSET
        else:
            identifier_resolved = self.identifier_resolved

        next_offset: int | None | Unset
        if isinstance(self.next_offset, Unset):
            next_offset = UNSET
        else:
            next_offset = self.next_offset

        paging_incomplete = self.paging_incomplete

        rollups_cve_ids: list[str] | Unset = UNSET
        if not isinstance(self.rollups_cve_ids, Unset):
            rollups_cve_ids = self.rollups_cve_ids

        rollups_over = self.rollups_over

        snapshot_id: None | str | Unset
        if isinstance(self.snapshot_id, Unset):
            snapshot_id = UNSET
        else:
            snapshot_id = self.snapshot_id

        version: None | str | Unset
        if isinstance(self.version, Unset):
            version = UNSET
        else:
            version = self.version

        vulnerability_count = self.vulnerability_count

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "ecosystem": ecosystem,
                "package": package,
            }
        )
        if advisories is not UNSET:
            field_dict["advisories"] = advisories
        if advisories_discovered is not UNSET:
            field_dict["advisories_discovered"] = advisories_discovered
        if cve_context_catalog is not UNSET:
            field_dict["cve_context_catalog"] = cve_context_catalog
        if cves is not UNSET:
            field_dict["cves"] = cves
        if cves_discovered is not UNSET:
            field_dict["cves_discovered"] = cves_discovered
        if cves_enrichment_limit is not UNSET:
            field_dict["cves_enrichment_limit"] = cves_enrichment_limit
        if discovery_truncated is not UNSET:
            field_dict["discovery_truncated"] = discovery_truncated
        if discovery_truncation_reason is not UNSET:
            field_dict["discovery_truncation_reason"] = discovery_truncation_reason
        if errors is not UNSET:
            field_dict["errors"] = errors
        if highest_weaponization_score is not UNSET:
            field_dict["highest_weaponization_score"] = highest_weaponization_score
        if identifier_resolved is not UNSET:
            field_dict["identifier_resolved"] = identifier_resolved
        if next_offset is not UNSET:
            field_dict["next_offset"] = next_offset
        if paging_incomplete is not UNSET:
            field_dict["paging_incomplete"] = paging_incomplete
        if rollups_cve_ids is not UNSET:
            field_dict["rollups_cve_ids"] = rollups_cve_ids
        if rollups_over is not UNSET:
            field_dict["rollups_over"] = rollups_over
        if snapshot_id is not UNSET:
            field_dict["snapshot_id"] = snapshot_id
        if version is not UNSET:
            field_dict["version"] = version
        if vulnerability_count is not UNSET:
            field_dict["vulnerability_count"] = vulnerability_count

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.catalogued_cve_response import CataloguedCVEResponse  # noqa: PLC0415
        from ..models.cve_context_catalog import CVEContextCatalog  # noqa: PLC0415
        from ..models.error_detail import ErrorDetail  # noqa: PLC0415
        from ..models.osv_advisory import OSVAdvisory  # noqa: PLC0415

        d = dict(src_dict)
        ecosystem = d.pop("ecosystem")

        package = d.pop("package")

        _advisories = d.pop("advisories", UNSET)
        advisories: list[OSVAdvisory] | Unset = UNSET
        if _advisories is not UNSET:
            advisories = []
            for advisories_item_data in _advisories:
                advisories_item = OSVAdvisory.from_dict(advisories_item_data)

                advisories.append(advisories_item)

        advisories_discovered = d.pop("advisories_discovered", UNSET)

        _cve_context_catalog = d.pop("cve_context_catalog", UNSET)
        cve_context_catalog: CVEContextCatalog | Unset
        if isinstance(_cve_context_catalog, Unset):
            cve_context_catalog = UNSET
        else:
            cve_context_catalog = CVEContextCatalog.from_dict(_cve_context_catalog)

        _cves = d.pop("cves", UNSET)
        cves: list[CataloguedCVEResponse] | Unset = UNSET
        if _cves is not UNSET:
            cves = []
            for cves_item_data in _cves:
                cves_item = CataloguedCVEResponse.from_dict(cves_item_data)

                cves.append(cves_item)

        cves_discovered = d.pop("cves_discovered", UNSET)

        cves_enrichment_limit = d.pop("cves_enrichment_limit", UNSET)

        def _parse_discovery_truncated(data: object) -> bool | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(bool | None | Unset, data)

        discovery_truncated = _parse_discovery_truncated(d.pop("discovery_truncated", UNSET))

        def _parse_discovery_truncation_reason(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        discovery_truncation_reason = _parse_discovery_truncation_reason(d.pop("discovery_truncation_reason", UNSET))

        _errors = d.pop("errors", UNSET)
        errors: list[ErrorDetail] | Unset = UNSET
        if _errors is not UNSET:
            errors = []
            for errors_item_data in _errors:
                errors_item = ErrorDetail.from_dict(errors_item_data)

                errors.append(errors_item)

        def _parse_highest_weaponization_score(data: object) -> float | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(float | None | Unset, data)

        highest_weaponization_score = _parse_highest_weaponization_score(d.pop("highest_weaponization_score", UNSET))

        def _parse_identifier_resolved(data: object) -> bool | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(bool | None | Unset, data)

        identifier_resolved = _parse_identifier_resolved(d.pop("identifier_resolved", UNSET))

        def _parse_next_offset(data: object) -> int | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(int | None | Unset, data)

        next_offset = _parse_next_offset(d.pop("next_offset", UNSET))

        paging_incomplete = d.pop("paging_incomplete", UNSET)

        rollups_cve_ids = cast(list[str], d.pop("rollups_cve_ids", UNSET))

        rollups_over = d.pop("rollups_over", UNSET)

        def _parse_snapshot_id(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        snapshot_id = _parse_snapshot_id(d.pop("snapshot_id", UNSET))

        def _parse_version(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        version = _parse_version(d.pop("version", UNSET))

        vulnerability_count = d.pop("vulnerability_count", UNSET)

        enrich_package_response = cls(
            ecosystem=ecosystem,
            package=package,
            advisories=advisories,
            advisories_discovered=advisories_discovered,
            cve_context_catalog=cve_context_catalog,
            cves=cves,
            cves_discovered=cves_discovered,
            cves_enrichment_limit=cves_enrichment_limit,
            discovery_truncated=discovery_truncated,
            discovery_truncation_reason=discovery_truncation_reason,
            errors=errors,
            highest_weaponization_score=highest_weaponization_score,
            identifier_resolved=identifier_resolved,
            next_offset=next_offset,
            paging_incomplete=paging_incomplete,
            rollups_cve_ids=rollups_cve_ids,
            rollups_over=rollups_over,
            snapshot_id=snapshot_id,
            version=version,
            vulnerability_count=vulnerability_count,
        )

        enrich_package_response.additional_properties = d
        return enrich_package_response

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

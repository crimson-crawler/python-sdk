from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, BinaryIO, Generator, TextIO, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..models.enrich_product_response_match_kind import EnrichProductResponseMatchKind
from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.catalogued_cve_response import CataloguedCVEResponse
    from ..models.cpe_product import CPEProduct
    from ..models.csaf_advisory import CSAFAdvisory
    from ..models.cve_context_catalog import CVEContextCatalog
    from ..models.enrich_product_response_cve_fix_sources import EnrichProductResponseCveFixSources
    from ..models.enrich_product_response_cve_fix_versions import EnrichProductResponseCveFixVersions
    from ..models.error_detail import ErrorDetail
    from ..models.nist_control_mapping import NistControlMapping
    from ..models.ot_context import OTContext
    from ..models.product_lifecycle import ProductLifecycle
    from ..models.risk_summary import RiskSummary


T = TypeVar("T", bound="EnrichProductResponse")


@_attrs_define
class EnrichProductResponse:
    """Product vulnerability assessment - matched CVEs with per-CVE enrichment.

    Attributes:
        product (str): Searched product name
        cpe_matches (list[CPEProduct] | Unset): Matched product entries from the CPE dictionary
        csaf_advisories (list[CSAFAdvisory] | Unset): CSAF vendor advisories matching this product. The summary returns
            the 10 newest rows without remediation and product-status detail; `csaf_advisories_full` restores all rows and
            fields. An unavailable corpus adds an errors[] entry.
        csaf_advisories_total (int | Unset): Matching product-level CSAF advisories before the summary cap Default: 0.
        csaf_advisories_truncated (bool | Unset): True when product-level CSAF rows were shortened Default: False.
        cve_context_catalog (CVEContextCatalog | Unset): Page-local shared CVE context, keyed by identifier with
            suffixes for differing versions.
        cve_fix_sources (EnrichProductResponseCveFixSources | Unset): Where a `cve_fix_versions` entry came from when it
            was NOT the NVD bound: `{cve_id: stamp}` naming the CVE Program record (and its CNA) that published the fixed
            version, with the record's own last-updated date. A CVE absent here was fixed by its NVD bound.
        cve_fix_versions (EnrichProductResponseCveFixVersions | Unset): Remediation guidance: `{cve_id: fix_version}` —
            the lowest version that resolves each CVE for this product, strictly above the requested `version`. From the NVD
            `versionEndExcluding` applicability bound; for a CVE whose NVD configuration enumerates releases and so has no
            bound, from the CNA's own CVE record (a vendor hotfix such as PAN-OS `10.2.9-h1`) when the deployment enables
            public metadata (`ENRICH_PUBLIC_METADATA`) — that entry is named in `cve_fix_sources`. Only populated when
            `version` is set. A CVE is absent when no source published a clean fixed version (all-versions-affected / fixed-
            after-unknown) — never a fabricated version.
        cves (list[CataloguedCVEResponse] | Unset): Paged enriched CVEs; shared context layers reference
            cve_context_catalog
        cves_discovered (int | Unset): Number of CVEs in the bounded discovered set after filtering Default: 0.
        cves_enrichment_limit (int | Unset): Maximum discovered CVEs enriched per request Default: 0.
        cves_next_offset (int | None | Unset): Offset for the next page, or null at the end
        discovery_cpe_cap (int | Unset): Maximum CPE candidates queried for discovery Default: 0.
        discovery_cve_cap (int | None | Unset): CVE count at which discovery may stop early
        discovery_truncated (bool | None | Unset): Whether discovery was bounded; null means upstream completeness is
            unknown
        discovery_truncation_reason (None | str | Unset): Reason discovery was bounded or its completeness is unknown
        errors (list[ErrorDetail] | Unset): Partial failure details
        highest_weaponization_score (float | None | Unset): Highest weaponization score across the enriched CVEs; see
            rollups_over
        identifier_resolved (bool | None | Unset): Whether a direct-lookup identifier resolved to a record. `false`
            means the id was not found, so every layer below is empty for that reason rather than because the record exists
            and has no data — the two were previously indistinguishable. `null` when the request used `search` instead of an
            id, where an empty result is a legitimate no-match.
        lifecycle (None | ProductLifecycle | Unset): endoflife.date lifecycle for this product (support/EOL dates and
            the latest release). Opt-in via include=['lifecycle']; no slug match is null with no error, an upstream failure
            is null plus an `errors[]` entry.
        likely_tactics (list[str] | None | Unset): Likely ATT&CK tactic classes for the product's vendor. These are
            analyst hints, not technique IDs or authoritative attribution.
        match_kind (EnrichProductResponseMatchKind | Unset): How the requested product resolved against the CPE catalog:
            'cpe' when at least one candidate's vendor:product PRODUCT token equals the requested product token exactly,
            'cpe_fuzzy' when candidates exist but none is exact, 'none' when no candidate was found (or the identifier did
            not resolve). Default: EnrichProductResponseMatchKind.NONE.
        matched_products (list[str] | Unset): 'vendor:product' of the CPE candidates whose product token matches the
            requested product exactly; empty unless match_kind is 'cpe'.
        nist_controls (list[NistControlMapping] | Unset): NIST SP 800-53 rev 5 controls that mitigate the techniques on
            this response, via MITRE CTID. Pass-through static lookup; only populates when 'nist_controls' is in the request
            include set.
        ot_context (None | OTContext | Unset): Product-level OT/RF context: sectors from the ICS Advisory Project CSV
            and the curated vendor map, protocols and RF technology from the product/vendor/CSAF text, and the union of the
            nested CVEs' 62443 requirements. Opt-in via include=['ot_context']; `fix_availability.eol` is populated when
            `lifecycle` is also requested.
        paging_incomplete (bool | Unset): True when a consumer could not collect every available page Default: False.
        risk_summary (None | RiskSummary | Unset): Aggregate risk statistics over the enriched CVEs; see rollups_over
        rollups_cve_ids (list[str] | Unset): CVE IDs included in the frozen product rollups
        rollups_over (int | Unset): Number of enriched CVEs contributing to product rollups Default: 0.
        snapshot_id (None | str | Unset): Snapshot identifier for subsequent pages (expires after 30 minutes)
        summary (None | str | Unset): AI-generated executive brief across all matched CVEs for this product
        vendor (None | str | Unset): Vendor name filter applied
        version (None | str | Unset): Version filter applied
        version_unconfirmed_cves (list[str] | Unset): CVEs in `cves` whose applicability to the requested `version`
            could not be confirmed from NVD data; treat as not version-confirmed. A CVE is listed when it was kept without
            version evidence — NVD states the product is affected but names no version, its applicability for the product
            could not be read, or it carries no applicability record at all — and also every returned CVE when nothing in
            the matched set states a version for the product (the `version_filter`/`version_not_applied` case). Empty when
            no `version` was supplied. Sorted CVE ids; a CVE in `cves` that is absent here was confirmed against the
            requested version.
    """

    product: str
    cpe_matches: list[CPEProduct] | Unset = UNSET
    csaf_advisories: list[CSAFAdvisory] | Unset = UNSET
    csaf_advisories_total: int | Unset = 0
    csaf_advisories_truncated: bool | Unset = False
    cve_context_catalog: CVEContextCatalog | Unset = UNSET
    cve_fix_sources: EnrichProductResponseCveFixSources | Unset = UNSET
    cve_fix_versions: EnrichProductResponseCveFixVersions | Unset = UNSET
    cves: list[CataloguedCVEResponse] | Unset = UNSET
    cves_discovered: int | Unset = 0
    cves_enrichment_limit: int | Unset = 0
    cves_next_offset: int | None | Unset = UNSET
    discovery_cpe_cap: int | Unset = 0
    discovery_cve_cap: int | None | Unset = UNSET
    discovery_truncated: bool | None | Unset = UNSET
    discovery_truncation_reason: None | str | Unset = UNSET
    errors: list[ErrorDetail] | Unset = UNSET
    highest_weaponization_score: float | None | Unset = UNSET
    identifier_resolved: bool | None | Unset = UNSET
    lifecycle: None | ProductLifecycle | Unset = UNSET
    likely_tactics: list[str] | None | Unset = UNSET
    match_kind: EnrichProductResponseMatchKind | Unset = EnrichProductResponseMatchKind.NONE
    matched_products: list[str] | Unset = UNSET
    nist_controls: list[NistControlMapping] | Unset = UNSET
    ot_context: None | OTContext | Unset = UNSET
    paging_incomplete: bool | Unset = False
    risk_summary: None | RiskSummary | Unset = UNSET
    rollups_cve_ids: list[str] | Unset = UNSET
    rollups_over: int | Unset = 0
    snapshot_id: None | str | Unset = UNSET
    summary: None | str | Unset = UNSET
    vendor: None | str | Unset = UNSET
    version: None | str | Unset = UNSET
    version_unconfirmed_cves: list[str] | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        from ..models.catalogued_cve_response import CataloguedCVEResponse  # noqa: PLC0415
        from ..models.cpe_product import CPEProduct  # noqa: PLC0415
        from ..models.csaf_advisory import CSAFAdvisory  # noqa: PLC0415
        from ..models.cve_context_catalog import CVEContextCatalog  # noqa: PLC0415
        from ..models.enrich_product_response_cve_fix_sources import EnrichProductResponseCveFixSources  # noqa: PLC0415
        from ..models.enrich_product_response_cve_fix_versions import (
            EnrichProductResponseCveFixVersions,  # noqa: PLC0415
        )
        from ..models.error_detail import ErrorDetail  # noqa: PLC0415
        from ..models.nist_control_mapping import NistControlMapping  # noqa: PLC0415
        from ..models.ot_context import OTContext  # noqa: PLC0415
        from ..models.product_lifecycle import ProductLifecycle  # noqa: PLC0415
        from ..models.risk_summary import RiskSummary  # noqa: PLC0415

        product = self.product

        cpe_matches: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.cpe_matches, Unset):
            cpe_matches = []
            for cpe_matches_item_data in self.cpe_matches:
                cpe_matches_item = cpe_matches_item_data.to_dict()
                cpe_matches.append(cpe_matches_item)

        csaf_advisories: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.csaf_advisories, Unset):
            csaf_advisories = []
            for csaf_advisories_item_data in self.csaf_advisories:
                csaf_advisories_item = csaf_advisories_item_data.to_dict()
                csaf_advisories.append(csaf_advisories_item)

        csaf_advisories_total = self.csaf_advisories_total

        csaf_advisories_truncated = self.csaf_advisories_truncated

        cve_context_catalog: dict[str, Any] | Unset = UNSET
        if not isinstance(self.cve_context_catalog, Unset):
            cve_context_catalog = self.cve_context_catalog.to_dict()

        cve_fix_sources: dict[str, Any] | Unset = UNSET
        if not isinstance(self.cve_fix_sources, Unset):
            cve_fix_sources = self.cve_fix_sources.to_dict()

        cve_fix_versions: dict[str, Any] | Unset = UNSET
        if not isinstance(self.cve_fix_versions, Unset):
            cve_fix_versions = self.cve_fix_versions.to_dict()

        cves: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.cves, Unset):
            cves = []
            for cves_item_data in self.cves:
                cves_item = cves_item_data.to_dict()
                cves.append(cves_item)

        cves_discovered = self.cves_discovered

        cves_enrichment_limit = self.cves_enrichment_limit

        cves_next_offset: int | None | Unset
        if isinstance(self.cves_next_offset, Unset):
            cves_next_offset = UNSET
        else:
            cves_next_offset = self.cves_next_offset

        discovery_cpe_cap = self.discovery_cpe_cap

        discovery_cve_cap: int | None | Unset
        if isinstance(self.discovery_cve_cap, Unset):
            discovery_cve_cap = UNSET
        else:
            discovery_cve_cap = self.discovery_cve_cap

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

        lifecycle: dict[str, Any] | None | Unset
        if isinstance(self.lifecycle, Unset):
            lifecycle = UNSET
        elif isinstance(self.lifecycle, ProductLifecycle):
            lifecycle = self.lifecycle.to_dict()
        else:
            lifecycle = self.lifecycle

        likely_tactics: list[str] | None | Unset
        if isinstance(self.likely_tactics, Unset):
            likely_tactics = UNSET
        elif isinstance(self.likely_tactics, list):
            likely_tactics = self.likely_tactics

        else:
            likely_tactics = self.likely_tactics

        match_kind: str | Unset = UNSET
        if not isinstance(self.match_kind, Unset):
            match_kind = self.match_kind.value

        matched_products: list[str] | Unset = UNSET
        if not isinstance(self.matched_products, Unset):
            matched_products = self.matched_products

        nist_controls: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.nist_controls, Unset):
            nist_controls = []
            for nist_controls_item_data in self.nist_controls:
                nist_controls_item = nist_controls_item_data.to_dict()
                nist_controls.append(nist_controls_item)

        ot_context: dict[str, Any] | None | Unset
        if isinstance(self.ot_context, Unset):
            ot_context = UNSET
        elif isinstance(self.ot_context, OTContext):
            ot_context = self.ot_context.to_dict()
        else:
            ot_context = self.ot_context

        paging_incomplete = self.paging_incomplete

        risk_summary: dict[str, Any] | None | Unset
        if isinstance(self.risk_summary, Unset):
            risk_summary = UNSET
        elif isinstance(self.risk_summary, RiskSummary):
            risk_summary = self.risk_summary.to_dict()
        else:
            risk_summary = self.risk_summary

        rollups_cve_ids: list[str] | Unset = UNSET
        if not isinstance(self.rollups_cve_ids, Unset):
            rollups_cve_ids = self.rollups_cve_ids

        rollups_over = self.rollups_over

        snapshot_id: None | str | Unset
        if isinstance(self.snapshot_id, Unset):
            snapshot_id = UNSET
        else:
            snapshot_id = self.snapshot_id

        summary: None | str | Unset
        if isinstance(self.summary, Unset):
            summary = UNSET
        else:
            summary = self.summary

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

        version_unconfirmed_cves: list[str] | Unset = UNSET
        if not isinstance(self.version_unconfirmed_cves, Unset):
            version_unconfirmed_cves = self.version_unconfirmed_cves

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "product": product,
            }
        )
        if cpe_matches is not UNSET:
            field_dict["cpe_matches"] = cpe_matches
        if csaf_advisories is not UNSET:
            field_dict["csaf_advisories"] = csaf_advisories
        if csaf_advisories_total is not UNSET:
            field_dict["csaf_advisories_total"] = csaf_advisories_total
        if csaf_advisories_truncated is not UNSET:
            field_dict["csaf_advisories_truncated"] = csaf_advisories_truncated
        if cve_context_catalog is not UNSET:
            field_dict["cve_context_catalog"] = cve_context_catalog
        if cve_fix_sources is not UNSET:
            field_dict["cve_fix_sources"] = cve_fix_sources
        if cve_fix_versions is not UNSET:
            field_dict["cve_fix_versions"] = cve_fix_versions
        if cves is not UNSET:
            field_dict["cves"] = cves
        if cves_discovered is not UNSET:
            field_dict["cves_discovered"] = cves_discovered
        if cves_enrichment_limit is not UNSET:
            field_dict["cves_enrichment_limit"] = cves_enrichment_limit
        if cves_next_offset is not UNSET:
            field_dict["cves_next_offset"] = cves_next_offset
        if discovery_cpe_cap is not UNSET:
            field_dict["discovery_cpe_cap"] = discovery_cpe_cap
        if discovery_cve_cap is not UNSET:
            field_dict["discovery_cve_cap"] = discovery_cve_cap
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
        if lifecycle is not UNSET:
            field_dict["lifecycle"] = lifecycle
        if likely_tactics is not UNSET:
            field_dict["likely_tactics"] = likely_tactics
        if match_kind is not UNSET:
            field_dict["match_kind"] = match_kind
        if matched_products is not UNSET:
            field_dict["matched_products"] = matched_products
        if nist_controls is not UNSET:
            field_dict["nist_controls"] = nist_controls
        if ot_context is not UNSET:
            field_dict["ot_context"] = ot_context
        if paging_incomplete is not UNSET:
            field_dict["paging_incomplete"] = paging_incomplete
        if risk_summary is not UNSET:
            field_dict["risk_summary"] = risk_summary
        if rollups_cve_ids is not UNSET:
            field_dict["rollups_cve_ids"] = rollups_cve_ids
        if rollups_over is not UNSET:
            field_dict["rollups_over"] = rollups_over
        if snapshot_id is not UNSET:
            field_dict["snapshot_id"] = snapshot_id
        if summary is not UNSET:
            field_dict["summary"] = summary
        if vendor is not UNSET:
            field_dict["vendor"] = vendor
        if version is not UNSET:
            field_dict["version"] = version
        if version_unconfirmed_cves is not UNSET:
            field_dict["version_unconfirmed_cves"] = version_unconfirmed_cves

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.catalogued_cve_response import CataloguedCVEResponse  # noqa: PLC0415
        from ..models.cpe_product import CPEProduct  # noqa: PLC0415
        from ..models.csaf_advisory import CSAFAdvisory  # noqa: PLC0415
        from ..models.cve_context_catalog import CVEContextCatalog  # noqa: PLC0415
        from ..models.enrich_product_response_cve_fix_sources import EnrichProductResponseCveFixSources  # noqa: PLC0415
        from ..models.enrich_product_response_cve_fix_versions import (
            EnrichProductResponseCveFixVersions,  # noqa: PLC0415
        )
        from ..models.error_detail import ErrorDetail  # noqa: PLC0415
        from ..models.nist_control_mapping import NistControlMapping  # noqa: PLC0415
        from ..models.ot_context import OTContext  # noqa: PLC0415
        from ..models.product_lifecycle import ProductLifecycle  # noqa: PLC0415
        from ..models.risk_summary import RiskSummary  # noqa: PLC0415

        d = dict(src_dict)
        product = d.pop("product")

        _cpe_matches = d.pop("cpe_matches", UNSET)
        cpe_matches: list[CPEProduct] | Unset = UNSET
        if _cpe_matches is not UNSET:
            cpe_matches = []
            for cpe_matches_item_data in _cpe_matches:
                cpe_matches_item = CPEProduct.from_dict(cpe_matches_item_data)

                cpe_matches.append(cpe_matches_item)

        _csaf_advisories = d.pop("csaf_advisories", UNSET)
        csaf_advisories: list[CSAFAdvisory] | Unset = UNSET
        if _csaf_advisories is not UNSET:
            csaf_advisories = []
            for csaf_advisories_item_data in _csaf_advisories:
                csaf_advisories_item = CSAFAdvisory.from_dict(csaf_advisories_item_data)

                csaf_advisories.append(csaf_advisories_item)

        csaf_advisories_total = d.pop("csaf_advisories_total", UNSET)

        csaf_advisories_truncated = d.pop("csaf_advisories_truncated", UNSET)

        _cve_context_catalog = d.pop("cve_context_catalog", UNSET)
        cve_context_catalog: CVEContextCatalog | Unset
        if isinstance(_cve_context_catalog, Unset):
            cve_context_catalog = UNSET
        else:
            cve_context_catalog = CVEContextCatalog.from_dict(_cve_context_catalog)

        _cve_fix_sources = d.pop("cve_fix_sources", UNSET)
        cve_fix_sources: EnrichProductResponseCveFixSources | Unset
        if isinstance(_cve_fix_sources, Unset):
            cve_fix_sources = UNSET
        else:
            cve_fix_sources = EnrichProductResponseCveFixSources.from_dict(_cve_fix_sources)

        _cve_fix_versions = d.pop("cve_fix_versions", UNSET)
        cve_fix_versions: EnrichProductResponseCveFixVersions | Unset
        if isinstance(_cve_fix_versions, Unset):
            cve_fix_versions = UNSET
        else:
            cve_fix_versions = EnrichProductResponseCveFixVersions.from_dict(_cve_fix_versions)

        _cves = d.pop("cves", UNSET)
        cves: list[CataloguedCVEResponse] | Unset = UNSET
        if _cves is not UNSET:
            cves = []
            for cves_item_data in _cves:
                cves_item = CataloguedCVEResponse.from_dict(cves_item_data)

                cves.append(cves_item)

        cves_discovered = d.pop("cves_discovered", UNSET)

        cves_enrichment_limit = d.pop("cves_enrichment_limit", UNSET)

        def _parse_cves_next_offset(data: object) -> int | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(int | None | Unset, data)

        cves_next_offset = _parse_cves_next_offset(d.pop("cves_next_offset", UNSET))

        discovery_cpe_cap = d.pop("discovery_cpe_cap", UNSET)

        def _parse_discovery_cve_cap(data: object) -> int | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(int | None | Unset, data)

        discovery_cve_cap = _parse_discovery_cve_cap(d.pop("discovery_cve_cap", UNSET))

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

        def _parse_lifecycle(data: object) -> None | ProductLifecycle | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, dict):
                    raise TypeError()
                lifecycle_type_0 = ProductLifecycle.from_dict(data)

                return lifecycle_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(None | ProductLifecycle | Unset, data)

        lifecycle = _parse_lifecycle(d.pop("lifecycle", UNSET))

        def _parse_likely_tactics(data: object) -> list[str] | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, list):
                    raise TypeError()
                likely_tactics_type_0 = cast(list[str], data)

                return likely_tactics_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(list[str] | None | Unset, data)

        likely_tactics = _parse_likely_tactics(d.pop("likely_tactics", UNSET))

        _match_kind = d.pop("match_kind", UNSET)
        match_kind: EnrichProductResponseMatchKind | Unset
        if isinstance(_match_kind, Unset):
            match_kind = UNSET
        else:
            match_kind = EnrichProductResponseMatchKind(_match_kind)

        matched_products = cast(list[str], d.pop("matched_products", UNSET))

        _nist_controls = d.pop("nist_controls", UNSET)
        nist_controls: list[NistControlMapping] | Unset = UNSET
        if _nist_controls is not UNSET:
            nist_controls = []
            for nist_controls_item_data in _nist_controls:
                nist_controls_item = NistControlMapping.from_dict(nist_controls_item_data)

                nist_controls.append(nist_controls_item)

        def _parse_ot_context(data: object) -> None | OTContext | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, dict):
                    raise TypeError()
                ot_context_type_0 = OTContext.from_dict(data)

                return ot_context_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(None | OTContext | Unset, data)

        ot_context = _parse_ot_context(d.pop("ot_context", UNSET))

        paging_incomplete = d.pop("paging_incomplete", UNSET)

        def _parse_risk_summary(data: object) -> None | RiskSummary | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, dict):
                    raise TypeError()
                risk_summary_type_0 = RiskSummary.from_dict(data)

                return risk_summary_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(None | RiskSummary | Unset, data)

        risk_summary = _parse_risk_summary(d.pop("risk_summary", UNSET))

        rollups_cve_ids = cast(list[str], d.pop("rollups_cve_ids", UNSET))

        rollups_over = d.pop("rollups_over", UNSET)

        def _parse_snapshot_id(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        snapshot_id = _parse_snapshot_id(d.pop("snapshot_id", UNSET))

        def _parse_summary(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        summary = _parse_summary(d.pop("summary", UNSET))

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

        version_unconfirmed_cves = cast(list[str], d.pop("version_unconfirmed_cves", UNSET))

        enrich_product_response = cls(
            product=product,
            cpe_matches=cpe_matches,
            csaf_advisories=csaf_advisories,
            csaf_advisories_total=csaf_advisories_total,
            csaf_advisories_truncated=csaf_advisories_truncated,
            cve_context_catalog=cve_context_catalog,
            cve_fix_sources=cve_fix_sources,
            cve_fix_versions=cve_fix_versions,
            cves=cves,
            cves_discovered=cves_discovered,
            cves_enrichment_limit=cves_enrichment_limit,
            cves_next_offset=cves_next_offset,
            discovery_cpe_cap=discovery_cpe_cap,
            discovery_cve_cap=discovery_cve_cap,
            discovery_truncated=discovery_truncated,
            discovery_truncation_reason=discovery_truncation_reason,
            errors=errors,
            highest_weaponization_score=highest_weaponization_score,
            identifier_resolved=identifier_resolved,
            lifecycle=lifecycle,
            likely_tactics=likely_tactics,
            match_kind=match_kind,
            matched_products=matched_products,
            nist_controls=nist_controls,
            ot_context=ot_context,
            paging_incomplete=paging_incomplete,
            risk_summary=risk_summary,
            rollups_cve_ids=rollups_cve_ids,
            rollups_over=rollups_over,
            snapshot_id=snapshot_id,
            summary=summary,
            vendor=vendor,
            version=version,
            version_unconfirmed_cves=version_unconfirmed_cves,
        )

        enrich_product_response.additional_properties = d
        return enrich_product_response

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

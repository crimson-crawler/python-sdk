from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, BinaryIO, Generator, TextIO, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..models.inventory_asset_finding_match import InventoryAssetFindingMatch
from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.error_detail import ErrorDetail
    from ..models.inventory_advisory import InventoryAdvisory
    from ..models.inventory_cve import InventoryCVE
    from ..models.product_lifecycle import ProductLifecycle


T = TypeVar("T", bound="InventoryAssetFinding")


@_attrs_define
class InventoryAssetFinding:
    """Per-asset findings in an inventory assessment (echoes the input asset + its captured CVEs).

    Attributes:
        product (str): Product name (echoed)
        advisories (list[InventoryAdvisory] | Unset): OSV advisories not enriched into top_cves (package assets only),
            severity-desc (≤200)
        advisory_count (int | Unset): OSV advisories captured that did not become top_cves (no CVE alias, or a CVE alias
            the CVE catalog could not resolve) Default: 0.
        asset_class (None | str | Unset): OT/ICS asset class supplied by the caller (echoed, never inferred): plc, hmi,
            rtu, ied, sis, historian, engineering_workstation, gateway, sensor, or other. Null for a non-OT asset.
        asset_groups (list[str] | Unset): Additional organizational groups supplied for the asset
        category (None | str | Unset): Asset category (echoed)
        cpe (None | str | Unset): CPE 2.3 identifier supplied for the asset
        criticality (None | str | Unset): Asset criticality (echoed)
        cve_count (int | Unset): Distinct CVEs still actionable on this asset, across its versions. VEX-suppressed
            findings are EXCLUDED here (they are reported by the rollup's vex_suppressed_cves) but RETAINED in top_cves, so
            top_cves can be longer than cve_count. Default: 0.
        ecosystem (None | str | Unset): Package ecosystem (echoed; set ⇒ OSV-enriched package asset)
        environment (None | str | Unset): Deployment environment supplied for the asset
        errors (list[ErrorDetail] | Unset): Per-asset partial-failure details
        exposure (None | str | Unset): Deployment exposure supplied for the asset
        firmware_version (None | str | Unset): Firmware version supplied by the caller (echoed)
        fixable_cve_count (int | Unset): How many of the asset's actionable CVEs have a known published fix version
            (VEX-suppressed findings excluded) Default: 0.
        group (None | str | Unset): Primary organizational group supplied for the asset
        hardware_version (None | str | Unset): Hardware model/revision supplied by the caller (echoed)
        kev_count (int | Unset): How many of the asset's actionable CVEs are KEV-listed (VEX-suppressed findings
            excluded — a suppressed KEV CVE is still in top_cves with kev=true). Default: 0.
        lifecycle (None | ProductLifecycle | Unset): endoflife.date lifecycle for this asset's product (support/EOL and
            latest release). Null when the product has no slug match or the read failed.
        match (InventoryAssetFindingMatch | Unset): Why this asset matched what it did: 'package' when an OSV probe
            answered for the (ecosystem, name), 'cpe' when a CPE candidate's product token equals the requested product
            exactly, 'cpe_fuzzy' when candidates exist but none is exact, 'none' when nothing resolved (identifier
            unresolved, no candidates, unsupported ecosystem, or every probe failed). Default:
            InventoryAssetFindingMatch.NONE.
        match_detail (None | str | Unset): Human-readable detail on the match: the ecosystem/package OSV answered for,
            the resolved 'vendor:product' candidates (with the CPE candidate count), or why nothing matched. Null for the
            degraded/error finding.
        max_weaponization (float | None | Unset): Highest weaponization score across the asset's actionable CVEs (VEX-
            suppressed excluded)
        notes (None | str | Unset): Note (echoed)
        owner (None | str | Unset): Responsible team or person supplied for the asset
        protocols (list[str] | Unset): Industrial protocols supplied by the caller (echoed; each label ≤64 characters)
        purdue_level (int | None | Unset): ISA/IEC 62443 Purdue level 0-5 supplied by the caller (echoed); null when
            unknown
        purl (None | str | Unset): Scanner Package URL supplied for a distro package (echoed; the VEX binding leaf)
        recommended_fix_version (None | str | Unset): Upgrade target that clears EVERY fixable CVE on this asset AND is
            verified against known CVEs affecting the target itself (bumped past vulnerable intermediate versions, bounded
            verification). None when no CVE has a known published fix.
        recommended_fix_version_kev (None | str | Unset): The urgent minimum: upgrade target that clears all KEV-listed
            CVEs on this asset (highest fix version among KEV CVEs). None when no KEV CVE has a known fix.
        safety_critical (bool | None | Unset): Safety-instrumented-function membership supplied by the caller (echoed).
            Null = unknown; false = explicitly not safety-critical.
        source_refs (list[str] | Unset): Source identifiers or references supplied for the asset
        status (str | Unset): 'ok' or 'error' (enrichment failed for this asset) Default: 'ok'.
        stix_id (None | str | Unset): STIX identifier supplied for the asset
        tags (list[str] | Unset): Free-form labels supplied for the asset
        top_cves (list[InventoryCVE] | Unset): Captured CVEs, KEV-first then weaponization/CVSS-desc (≤200). Includes
            VEX-suppressed findings, each flagged suppressed_by_vex with its justification.
        vendor (None | str | Unset): Vendor (echoed)
        versions (list[str] | Unset): Versions assessed (echoed)
    """

    product: str
    advisories: list[InventoryAdvisory] | Unset = UNSET
    advisory_count: int | Unset = 0
    asset_class: None | str | Unset = UNSET
    asset_groups: list[str] | Unset = UNSET
    category: None | str | Unset = UNSET
    cpe: None | str | Unset = UNSET
    criticality: None | str | Unset = UNSET
    cve_count: int | Unset = 0
    ecosystem: None | str | Unset = UNSET
    environment: None | str | Unset = UNSET
    errors: list[ErrorDetail] | Unset = UNSET
    exposure: None | str | Unset = UNSET
    firmware_version: None | str | Unset = UNSET
    fixable_cve_count: int | Unset = 0
    group: None | str | Unset = UNSET
    hardware_version: None | str | Unset = UNSET
    kev_count: int | Unset = 0
    lifecycle: None | ProductLifecycle | Unset = UNSET
    match: InventoryAssetFindingMatch | Unset = InventoryAssetFindingMatch.NONE
    match_detail: None | str | Unset = UNSET
    max_weaponization: float | None | Unset = UNSET
    notes: None | str | Unset = UNSET
    owner: None | str | Unset = UNSET
    protocols: list[str] | Unset = UNSET
    purdue_level: int | None | Unset = UNSET
    purl: None | str | Unset = UNSET
    recommended_fix_version: None | str | Unset = UNSET
    recommended_fix_version_kev: None | str | Unset = UNSET
    safety_critical: bool | None | Unset = UNSET
    source_refs: list[str] | Unset = UNSET
    status: str | Unset = "ok"
    stix_id: None | str | Unset = UNSET
    tags: list[str] | Unset = UNSET
    top_cves: list[InventoryCVE] | Unset = UNSET
    vendor: None | str | Unset = UNSET
    versions: list[str] | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        from ..models.error_detail import ErrorDetail  # noqa: PLC0415
        from ..models.inventory_advisory import InventoryAdvisory  # noqa: PLC0415
        from ..models.inventory_cve import InventoryCVE  # noqa: PLC0415
        from ..models.product_lifecycle import ProductLifecycle  # noqa: PLC0415

        product = self.product

        advisories: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.advisories, Unset):
            advisories = []
            for advisories_item_data in self.advisories:
                advisories_item = advisories_item_data.to_dict()
                advisories.append(advisories_item)

        advisory_count = self.advisory_count

        asset_class: None | str | Unset
        if isinstance(self.asset_class, Unset):
            asset_class = UNSET
        else:
            asset_class = self.asset_class

        asset_groups: list[str] | Unset = UNSET
        if not isinstance(self.asset_groups, Unset):
            asset_groups = self.asset_groups

        category: None | str | Unset
        if isinstance(self.category, Unset):
            category = UNSET
        else:
            category = self.category

        cpe: None | str | Unset
        if isinstance(self.cpe, Unset):
            cpe = UNSET
        else:
            cpe = self.cpe

        criticality: None | str | Unset
        if isinstance(self.criticality, Unset):
            criticality = UNSET
        else:
            criticality = self.criticality

        cve_count = self.cve_count

        ecosystem: None | str | Unset
        if isinstance(self.ecosystem, Unset):
            ecosystem = UNSET
        else:
            ecosystem = self.ecosystem

        environment: None | str | Unset
        if isinstance(self.environment, Unset):
            environment = UNSET
        else:
            environment = self.environment

        errors: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.errors, Unset):
            errors = []
            for errors_item_data in self.errors:
                errors_item = errors_item_data.to_dict()
                errors.append(errors_item)

        exposure: None | str | Unset
        if isinstance(self.exposure, Unset):
            exposure = UNSET
        else:
            exposure = self.exposure

        firmware_version: None | str | Unset
        if isinstance(self.firmware_version, Unset):
            firmware_version = UNSET
        else:
            firmware_version = self.firmware_version

        fixable_cve_count = self.fixable_cve_count

        group: None | str | Unset
        if isinstance(self.group, Unset):
            group = UNSET
        else:
            group = self.group

        hardware_version: None | str | Unset
        if isinstance(self.hardware_version, Unset):
            hardware_version = UNSET
        else:
            hardware_version = self.hardware_version

        kev_count = self.kev_count

        lifecycle: dict[str, Any] | None | Unset
        if isinstance(self.lifecycle, Unset):
            lifecycle = UNSET
        elif isinstance(self.lifecycle, ProductLifecycle):
            lifecycle = self.lifecycle.to_dict()
        else:
            lifecycle = self.lifecycle

        match: str | Unset = UNSET
        if not isinstance(self.match, Unset):
            match = self.match.value

        match_detail: None | str | Unset
        if isinstance(self.match_detail, Unset):
            match_detail = UNSET
        else:
            match_detail = self.match_detail

        max_weaponization: float | None | Unset
        if isinstance(self.max_weaponization, Unset):
            max_weaponization = UNSET
        else:
            max_weaponization = self.max_weaponization

        notes: None | str | Unset
        if isinstance(self.notes, Unset):
            notes = UNSET
        else:
            notes = self.notes

        owner: None | str | Unset
        if isinstance(self.owner, Unset):
            owner = UNSET
        else:
            owner = self.owner

        protocols: list[str] | Unset = UNSET
        if not isinstance(self.protocols, Unset):
            protocols = self.protocols

        purdue_level: int | None | Unset
        if isinstance(self.purdue_level, Unset):
            purdue_level = UNSET
        else:
            purdue_level = self.purdue_level

        purl: None | str | Unset
        if isinstance(self.purl, Unset):
            purl = UNSET
        else:
            purl = self.purl

        recommended_fix_version: None | str | Unset
        if isinstance(self.recommended_fix_version, Unset):
            recommended_fix_version = UNSET
        else:
            recommended_fix_version = self.recommended_fix_version

        recommended_fix_version_kev: None | str | Unset
        if isinstance(self.recommended_fix_version_kev, Unset):
            recommended_fix_version_kev = UNSET
        else:
            recommended_fix_version_kev = self.recommended_fix_version_kev

        safety_critical: bool | None | Unset
        if isinstance(self.safety_critical, Unset):
            safety_critical = UNSET
        else:
            safety_critical = self.safety_critical

        source_refs: list[str] | Unset = UNSET
        if not isinstance(self.source_refs, Unset):
            source_refs = self.source_refs

        status = self.status

        stix_id: None | str | Unset
        if isinstance(self.stix_id, Unset):
            stix_id = UNSET
        else:
            stix_id = self.stix_id

        tags: list[str] | Unset = UNSET
        if not isinstance(self.tags, Unset):
            tags = self.tags

        top_cves: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.top_cves, Unset):
            top_cves = []
            for top_cves_item_data in self.top_cves:
                top_cves_item = top_cves_item_data.to_dict()
                top_cves.append(top_cves_item)

        vendor: None | str | Unset
        if isinstance(self.vendor, Unset):
            vendor = UNSET
        else:
            vendor = self.vendor

        versions: list[str] | Unset = UNSET
        if not isinstance(self.versions, Unset):
            versions = self.versions

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "product": product,
            }
        )
        if advisories is not UNSET:
            field_dict["advisories"] = advisories
        if advisory_count is not UNSET:
            field_dict["advisory_count"] = advisory_count
        if asset_class is not UNSET:
            field_dict["asset_class"] = asset_class
        if asset_groups is not UNSET:
            field_dict["asset_groups"] = asset_groups
        if category is not UNSET:
            field_dict["category"] = category
        if cpe is not UNSET:
            field_dict["cpe"] = cpe
        if criticality is not UNSET:
            field_dict["criticality"] = criticality
        if cve_count is not UNSET:
            field_dict["cve_count"] = cve_count
        if ecosystem is not UNSET:
            field_dict["ecosystem"] = ecosystem
        if environment is not UNSET:
            field_dict["environment"] = environment
        if errors is not UNSET:
            field_dict["errors"] = errors
        if exposure is not UNSET:
            field_dict["exposure"] = exposure
        if firmware_version is not UNSET:
            field_dict["firmware_version"] = firmware_version
        if fixable_cve_count is not UNSET:
            field_dict["fixable_cve_count"] = fixable_cve_count
        if group is not UNSET:
            field_dict["group"] = group
        if hardware_version is not UNSET:
            field_dict["hardware_version"] = hardware_version
        if kev_count is not UNSET:
            field_dict["kev_count"] = kev_count
        if lifecycle is not UNSET:
            field_dict["lifecycle"] = lifecycle
        if match is not UNSET:
            field_dict["match"] = match
        if match_detail is not UNSET:
            field_dict["match_detail"] = match_detail
        if max_weaponization is not UNSET:
            field_dict["max_weaponization"] = max_weaponization
        if notes is not UNSET:
            field_dict["notes"] = notes
        if owner is not UNSET:
            field_dict["owner"] = owner
        if protocols is not UNSET:
            field_dict["protocols"] = protocols
        if purdue_level is not UNSET:
            field_dict["purdue_level"] = purdue_level
        if purl is not UNSET:
            field_dict["purl"] = purl
        if recommended_fix_version is not UNSET:
            field_dict["recommended_fix_version"] = recommended_fix_version
        if recommended_fix_version_kev is not UNSET:
            field_dict["recommended_fix_version_kev"] = recommended_fix_version_kev
        if safety_critical is not UNSET:
            field_dict["safety_critical"] = safety_critical
        if source_refs is not UNSET:
            field_dict["source_refs"] = source_refs
        if status is not UNSET:
            field_dict["status"] = status
        if stix_id is not UNSET:
            field_dict["stix_id"] = stix_id
        if tags is not UNSET:
            field_dict["tags"] = tags
        if top_cves is not UNSET:
            field_dict["top_cves"] = top_cves
        if vendor is not UNSET:
            field_dict["vendor"] = vendor
        if versions is not UNSET:
            field_dict["versions"] = versions

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.error_detail import ErrorDetail  # noqa: PLC0415
        from ..models.inventory_advisory import InventoryAdvisory  # noqa: PLC0415
        from ..models.inventory_cve import InventoryCVE  # noqa: PLC0415
        from ..models.product_lifecycle import ProductLifecycle  # noqa: PLC0415

        d = dict(src_dict)
        product = d.pop("product")

        _advisories = d.pop("advisories", UNSET)
        advisories: list[InventoryAdvisory] | Unset = UNSET
        if _advisories is not UNSET:
            advisories = []
            for advisories_item_data in _advisories:
                advisories_item = InventoryAdvisory.from_dict(advisories_item_data)

                advisories.append(advisories_item)

        advisory_count = d.pop("advisory_count", UNSET)

        def _parse_asset_class(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        asset_class = _parse_asset_class(d.pop("asset_class", UNSET))

        asset_groups = cast(list[str], d.pop("asset_groups", UNSET))

        def _parse_category(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        category = _parse_category(d.pop("category", UNSET))

        def _parse_cpe(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        cpe = _parse_cpe(d.pop("cpe", UNSET))

        def _parse_criticality(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        criticality = _parse_criticality(d.pop("criticality", UNSET))

        cve_count = d.pop("cve_count", UNSET)

        def _parse_ecosystem(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        ecosystem = _parse_ecosystem(d.pop("ecosystem", UNSET))

        def _parse_environment(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        environment = _parse_environment(d.pop("environment", UNSET))

        _errors = d.pop("errors", UNSET)
        errors: list[ErrorDetail] | Unset = UNSET
        if _errors is not UNSET:
            errors = []
            for errors_item_data in _errors:
                errors_item = ErrorDetail.from_dict(errors_item_data)

                errors.append(errors_item)

        def _parse_exposure(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        exposure = _parse_exposure(d.pop("exposure", UNSET))

        def _parse_firmware_version(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        firmware_version = _parse_firmware_version(d.pop("firmware_version", UNSET))

        fixable_cve_count = d.pop("fixable_cve_count", UNSET)

        def _parse_group(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        group = _parse_group(d.pop("group", UNSET))

        def _parse_hardware_version(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        hardware_version = _parse_hardware_version(d.pop("hardware_version", UNSET))

        kev_count = d.pop("kev_count", UNSET)

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

        _match = d.pop("match", UNSET)
        match: InventoryAssetFindingMatch | Unset
        if isinstance(_match, Unset):
            match = UNSET
        else:
            match = InventoryAssetFindingMatch(_match)

        def _parse_match_detail(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        match_detail = _parse_match_detail(d.pop("match_detail", UNSET))

        def _parse_max_weaponization(data: object) -> float | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(float | None | Unset, data)

        max_weaponization = _parse_max_weaponization(d.pop("max_weaponization", UNSET))

        def _parse_notes(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        notes = _parse_notes(d.pop("notes", UNSET))

        def _parse_owner(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        owner = _parse_owner(d.pop("owner", UNSET))

        protocols = cast(list[str], d.pop("protocols", UNSET))

        def _parse_purdue_level(data: object) -> int | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(int | None | Unset, data)

        purdue_level = _parse_purdue_level(d.pop("purdue_level", UNSET))

        def _parse_purl(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        purl = _parse_purl(d.pop("purl", UNSET))

        def _parse_recommended_fix_version(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        recommended_fix_version = _parse_recommended_fix_version(d.pop("recommended_fix_version", UNSET))

        def _parse_recommended_fix_version_kev(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        recommended_fix_version_kev = _parse_recommended_fix_version_kev(d.pop("recommended_fix_version_kev", UNSET))

        def _parse_safety_critical(data: object) -> bool | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(bool | None | Unset, data)

        safety_critical = _parse_safety_critical(d.pop("safety_critical", UNSET))

        source_refs = cast(list[str], d.pop("source_refs", UNSET))

        status = d.pop("status", UNSET)

        def _parse_stix_id(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        stix_id = _parse_stix_id(d.pop("stix_id", UNSET))

        tags = cast(list[str], d.pop("tags", UNSET))

        _top_cves = d.pop("top_cves", UNSET)
        top_cves: list[InventoryCVE] | Unset = UNSET
        if _top_cves is not UNSET:
            top_cves = []
            for top_cves_item_data in _top_cves:
                top_cves_item = InventoryCVE.from_dict(top_cves_item_data)

                top_cves.append(top_cves_item)

        def _parse_vendor(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        vendor = _parse_vendor(d.pop("vendor", UNSET))

        versions = cast(list[str], d.pop("versions", UNSET))

        inventory_asset_finding = cls(
            product=product,
            advisories=advisories,
            advisory_count=advisory_count,
            asset_class=asset_class,
            asset_groups=asset_groups,
            category=category,
            cpe=cpe,
            criticality=criticality,
            cve_count=cve_count,
            ecosystem=ecosystem,
            environment=environment,
            errors=errors,
            exposure=exposure,
            firmware_version=firmware_version,
            fixable_cve_count=fixable_cve_count,
            group=group,
            hardware_version=hardware_version,
            kev_count=kev_count,
            lifecycle=lifecycle,
            match=match,
            match_detail=match_detail,
            max_weaponization=max_weaponization,
            notes=notes,
            owner=owner,
            protocols=protocols,
            purdue_level=purdue_level,
            purl=purl,
            recommended_fix_version=recommended_fix_version,
            recommended_fix_version_kev=recommended_fix_version_kev,
            safety_critical=safety_critical,
            source_refs=source_refs,
            status=status,
            stix_id=stix_id,
            tags=tags,
            top_cves=top_cves,
            vendor=vendor,
            versions=versions,
        )

        inventory_asset_finding.additional_properties = d
        return inventory_asset_finding

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

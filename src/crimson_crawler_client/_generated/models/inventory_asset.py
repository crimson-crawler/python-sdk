from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, BinaryIO, Generator, TextIO, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..models.inventory_asset_asset_class_type_0 import InventoryAssetAssetClassType0
from ..types import UNSET, Unset

T = TypeVar("T", bound="InventoryAsset")


@_attrs_define
class InventoryAsset:
    """One asset in an inventory assessment — a CPE-shaped product (+ optional versions + metadata).

    When ``ecosystem`` is set the asset is an **open-source package** (npm / PyPI / Go / …) and is
    enriched via OSV.dev (``enrich/package``) using ``product`` as the package name; otherwise it is a
    CPE-shaped product enriched via ``enrich/product``. The two converge on the same per-CVE
    chain, so a single inventory can mix products and packages.

        Attributes:
            product (str): Product name for CPE matching, or the package name when `ecosystem` is set
            asset_class (InventoryAssetAssetClassType0 | None | Unset): OT/ICS asset class supplied by the caller; preserved
                and echoed. One of: plc, hmi, rtu, ied, sis, historian, engineering_workstation, gateway, sensor, other. Omit
                for a non-OT asset — the engine never infers a class from the product name.
            asset_groups (list[str] | Unset): Additional organizational groups; preserved in the result
            category (None | str | Unset): Asset category (passthrough, echoed in the result)
            cpe (None | str | Unset): Known CPE 2.3 identifier for this asset, preserved in the result
            criticality (None | str | Unset): Asset criticality (passthrough; drives rollup counts)
            ecosystem (None | str | Unset): Open-source package ecosystem (npm / PyPI / Go / Maven / crates.io / …). When
                set, this asset is enriched via OSV.dev using `product` as the package name, instead of CPE/product enrichment.
                Omit for a normal product asset.
            environment (None | str | Unset): Deployment environment, such as production, staging, or development; preserved
                in the result
            exposure (None | str | Unset): Deployment exposure, such as internet, internal, or isolated; preserved in the
                result
            firmware_version (None | str | Unset): Asset firmware version (distinct from the software `version`/`versions`);
                preserved and echoed.
            group (None | str | Unset): Primary organizational group for the asset; preserved in the result
            hardware_version (None | str | Unset): Asset hardware model/revision (e.g. a PLC order number); preserved and
                echoed. A vendor's model string belongs here rather than in `product`.
            model_numbers (list[str] | Unset): Model numbers that identify this asset when it has no CPE (CSAF R11 join).
            notes (None | str | Unset): Free-text note (passthrough, echoed)
            owner (None | str | Unset): Responsible team or person; preserved in the result
            protocols (list[str] | Unset): Industrial protocols the asset speaks (e.g. modbus-tcp, s7comm, ethernet-ip, opc-
                ua, iec-61850-mms); free-form labels, each ≤64 characters, preserved and echoed. Up to 20.
            purdue_level (int | None | Unset): ISA/IEC 62443 Purdue model level (0-5) supplied by the caller; preserved and
                echoed. 0 = physical process, 1 = controllers, 2 = supervisory, 3 = operations, 4 = enterprise, 5 =
                external/cloud. Omit when unknown.
            purl (None | str | Unset): The asset's Package URL. A package purl (`pkg:npm/…`, `pkg:pypi/…`, `pkg:maven/…`, …)
                makes the asset a package: its ecosystem and package name are read from it when `ecosystem` is omitted. A distro
                purl (`pkg:apk/…`, `pkg:deb/…`, `pkg:rpm/…`) has no OSV ecosystem; it is an identifier a VEX statement may name,
                so an overlay written against a Trivy/Grype report binds to the asset it describes.
            safety_critical (bool | None | Unset): Whether the asset participates in a safety instrumented function. Absent
                = unknown; `false` is an explicit 'not safety-critical', which is different from never having been asked.
            source_refs (list[str] | Unset): Source identifiers or references for the asset; preserved in the result
            stix_id (None | str | Unset): STIX identifier associated with the asset; preserved in the result
            tags (list[str] | Unset): Free-form asset labels; preserved in the result
            vendor (None | str | Unset): Vendor to narrow CPE match. For a Maven or Packagist package given as a bare
                artifact name, the namespace (Maven group id, Packagist vendor), so `log4j-core` + `org.apache.logging.log4j` is
                queried as `org.apache.logging.log4j:log4j-core`. Ignored for other package ecosystems.
            version (None | str | Unset): Single version (use `versions` for several)
            versions (list[str] | Unset): Versions to enrich; each runs and findings merge onto the one asset. Up to 5
                (matches the per-asset enrichment cap — 6+ is rejected rather than silently dropped).
    """

    product: str
    asset_class: InventoryAssetAssetClassType0 | None | Unset = UNSET
    asset_groups: list[str] | Unset = UNSET
    category: None | str | Unset = UNSET
    cpe: None | str | Unset = UNSET
    criticality: None | str | Unset = UNSET
    ecosystem: None | str | Unset = UNSET
    environment: None | str | Unset = UNSET
    exposure: None | str | Unset = UNSET
    firmware_version: None | str | Unset = UNSET
    group: None | str | Unset = UNSET
    hardware_version: None | str | Unset = UNSET
    model_numbers: list[str] | Unset = UNSET
    notes: None | str | Unset = UNSET
    owner: None | str | Unset = UNSET
    protocols: list[str] | Unset = UNSET
    purdue_level: int | None | Unset = UNSET
    purl: None | str | Unset = UNSET
    safety_critical: bool | None | Unset = UNSET
    source_refs: list[str] | Unset = UNSET
    stix_id: None | str | Unset = UNSET
    tags: list[str] | Unset = UNSET
    vendor: None | str | Unset = UNSET
    version: None | str | Unset = UNSET
    versions: list[str] | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        product = self.product

        asset_class: None | str | Unset
        if isinstance(self.asset_class, Unset):
            asset_class = UNSET
        elif isinstance(self.asset_class, InventoryAssetAssetClassType0):
            asset_class = self.asset_class.value
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

        model_numbers: list[str] | Unset = UNSET
        if not isinstance(self.model_numbers, Unset):
            model_numbers = self.model_numbers

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

        safety_critical: bool | None | Unset
        if isinstance(self.safety_critical, Unset):
            safety_critical = UNSET
        else:
            safety_critical = self.safety_critical

        source_refs: list[str] | Unset = UNSET
        if not isinstance(self.source_refs, Unset):
            source_refs = self.source_refs

        stix_id: None | str | Unset
        if isinstance(self.stix_id, Unset):
            stix_id = UNSET
        else:
            stix_id = self.stix_id

        tags: list[str] | Unset = UNSET
        if not isinstance(self.tags, Unset):
            tags = self.tags

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
        if ecosystem is not UNSET:
            field_dict["ecosystem"] = ecosystem
        if environment is not UNSET:
            field_dict["environment"] = environment
        if exposure is not UNSET:
            field_dict["exposure"] = exposure
        if firmware_version is not UNSET:
            field_dict["firmware_version"] = firmware_version
        if group is not UNSET:
            field_dict["group"] = group
        if hardware_version is not UNSET:
            field_dict["hardware_version"] = hardware_version
        if model_numbers is not UNSET:
            field_dict["model_numbers"] = model_numbers
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
        if safety_critical is not UNSET:
            field_dict["safety_critical"] = safety_critical
        if source_refs is not UNSET:
            field_dict["source_refs"] = source_refs
        if stix_id is not UNSET:
            field_dict["stix_id"] = stix_id
        if tags is not UNSET:
            field_dict["tags"] = tags
        if vendor is not UNSET:
            field_dict["vendor"] = vendor
        if version is not UNSET:
            field_dict["version"] = version
        if versions is not UNSET:
            field_dict["versions"] = versions

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        product = d.pop("product")

        def _parse_asset_class(data: object) -> InventoryAssetAssetClassType0 | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, str):
                    raise TypeError()
                asset_class_type_0 = InventoryAssetAssetClassType0(data)

                return asset_class_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(InventoryAssetAssetClassType0 | None | Unset, data)

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

        model_numbers = cast(list[str], d.pop("model_numbers", UNSET))

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

        def _parse_safety_critical(data: object) -> bool | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(bool | None | Unset, data)

        safety_critical = _parse_safety_critical(d.pop("safety_critical", UNSET))

        source_refs = cast(list[str], d.pop("source_refs", UNSET))

        def _parse_stix_id(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        stix_id = _parse_stix_id(d.pop("stix_id", UNSET))

        tags = cast(list[str], d.pop("tags", UNSET))

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

        versions = cast(list[str], d.pop("versions", UNSET))

        inventory_asset = cls(
            product=product,
            asset_class=asset_class,
            asset_groups=asset_groups,
            category=category,
            cpe=cpe,
            criticality=criticality,
            ecosystem=ecosystem,
            environment=environment,
            exposure=exposure,
            firmware_version=firmware_version,
            group=group,
            hardware_version=hardware_version,
            model_numbers=model_numbers,
            notes=notes,
            owner=owner,
            protocols=protocols,
            purdue_level=purdue_level,
            purl=purl,
            safety_critical=safety_critical,
            source_refs=source_refs,
            stix_id=stix_id,
            tags=tags,
            vendor=vendor,
            version=version,
            versions=versions,
        )

        inventory_asset.additional_properties = d
        return inventory_asset

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

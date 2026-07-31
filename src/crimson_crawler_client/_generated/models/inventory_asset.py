from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, BinaryIO, Generator, TextIO, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

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
            group (None | str | Unset): Primary organizational group for the asset; preserved in the result
            notes (None | str | Unset): Free-text note (passthrough, echoed)
            owner (None | str | Unset): Responsible team or person; preserved in the result
            source_refs (list[str] | Unset): Source identifiers or references for the asset; preserved in the result
            stix_id (None | str | Unset): STIX identifier associated with the asset; preserved in the result
            tags (list[str] | Unset): Free-form asset labels; preserved in the result
            vendor (None | str | Unset): Vendor to narrow CPE match (ignored for package assets)
            version (None | str | Unset): Single version (use `versions` for several)
            versions (list[str] | Unset): Versions to enrich; each runs and findings merge onto the one asset. Up to 5
                (matches the per-asset enrichment cap — 6+ is rejected rather than silently dropped).
    """

    product: str
    asset_groups: list[str] | Unset = UNSET
    category: None | str | Unset = UNSET
    cpe: None | str | Unset = UNSET
    criticality: None | str | Unset = UNSET
    ecosystem: None | str | Unset = UNSET
    environment: None | str | Unset = UNSET
    exposure: None | str | Unset = UNSET
    group: None | str | Unset = UNSET
    notes: None | str | Unset = UNSET
    owner: None | str | Unset = UNSET
    source_refs: list[str] | Unset = UNSET
    stix_id: None | str | Unset = UNSET
    tags: list[str] | Unset = UNSET
    vendor: None | str | Unset = UNSET
    version: None | str | Unset = UNSET
    versions: list[str] | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        product = self.product

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

        group: None | str | Unset
        if isinstance(self.group, Unset):
            group = UNSET
        else:
            group = self.group

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
        if group is not UNSET:
            field_dict["group"] = group
        if notes is not UNSET:
            field_dict["notes"] = notes
        if owner is not UNSET:
            field_dict["owner"] = owner
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

        def _parse_group(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        group = _parse_group(d.pop("group", UNSET))

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
            asset_groups=asset_groups,
            category=category,
            cpe=cpe,
            criticality=criticality,
            ecosystem=ecosystem,
            environment=environment,
            exposure=exposure,
            group=group,
            notes=notes,
            owner=owner,
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

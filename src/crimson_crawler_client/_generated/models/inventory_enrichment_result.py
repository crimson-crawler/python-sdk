from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, BinaryIO, Generator, TextIO, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.error_detail import ErrorDetail
    from ..models.inventory_asset_finding import InventoryAssetFinding
    from ..models.inventory_enrichment_result_attachment_enrichment_type_0 import (
        InventoryEnrichmentResultAttachmentEnrichmentType0,
    )
    from ..models.inventory_mitigation_profile import InventoryMitigationProfile
    from ..models.inventory_rollup import InventoryRollup
    from ..models.inventory_technique_profile import InventoryTechniqueProfile


T = TypeVar("T", bound="InventoryEnrichmentResult")


@_attrs_define
class InventoryEnrichmentResult:
    """Completed Inventory Enrichment with per-asset findings and a portfolio rollup.

    Attributes:
        summary (InventoryRollup): Aggregate rollup across the whole assessed inventory.
        assets (list[InventoryAssetFinding] | Unset): Per-asset findings, in input order
        attachment_enrichment (InventoryEnrichmentResultAttachmentEnrichmentType0 | None | Unset): Artifact Enrichment
            report for files attached to the inventory. Present when attachments were supplied and processed; otherwise
            null.
        errors (list[ErrorDetail] | Unset): Scan-level partial-failure details
        mitigation_catalog (list[InventoryMitigationProfile] | Unset): Every mitigation referenced by the inventory's
            CVEs, with its full text, listed once. Per-CVE `mitigations[].description` stays cut at 400 characters because
            it repeats per CVE
        technique_catalog (list[InventoryTechniqueProfile] | Unset): Every ATT&CK technique linked to the inventory's
            CVEs, described once (detection strategies, log sources, mitigations), most-linked first. Per-CVE rows keep only
            the technique id and name
    """

    summary: InventoryRollup
    assets: list[InventoryAssetFinding] | Unset = UNSET
    attachment_enrichment: InventoryEnrichmentResultAttachmentEnrichmentType0 | None | Unset = UNSET
    errors: list[ErrorDetail] | Unset = UNSET
    mitigation_catalog: list[InventoryMitigationProfile] | Unset = UNSET
    technique_catalog: list[InventoryTechniqueProfile] | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        from ..models.error_detail import ErrorDetail  # noqa: PLC0415
        from ..models.inventory_asset_finding import InventoryAssetFinding  # noqa: PLC0415
        from ..models.inventory_enrichment_result_attachment_enrichment_type_0 import (
            InventoryEnrichmentResultAttachmentEnrichmentType0,  # noqa: PLC0415
        )
        from ..models.inventory_mitigation_profile import InventoryMitigationProfile  # noqa: PLC0415
        from ..models.inventory_rollup import InventoryRollup  # noqa: PLC0415
        from ..models.inventory_technique_profile import InventoryTechniqueProfile  # noqa: PLC0415

        summary = self.summary.to_dict()

        assets: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.assets, Unset):
            assets = []
            for assets_item_data in self.assets:
                assets_item = assets_item_data.to_dict()
                assets.append(assets_item)

        attachment_enrichment: dict[str, Any] | None | Unset
        if isinstance(self.attachment_enrichment, Unset):
            attachment_enrichment = UNSET
        elif isinstance(self.attachment_enrichment, InventoryEnrichmentResultAttachmentEnrichmentType0):
            attachment_enrichment = self.attachment_enrichment.to_dict()
        else:
            attachment_enrichment = self.attachment_enrichment

        errors: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.errors, Unset):
            errors = []
            for errors_item_data in self.errors:
                errors_item = errors_item_data.to_dict()
                errors.append(errors_item)

        mitigation_catalog: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.mitigation_catalog, Unset):
            mitigation_catalog = []
            for mitigation_catalog_item_data in self.mitigation_catalog:
                mitigation_catalog_item = mitigation_catalog_item_data.to_dict()
                mitigation_catalog.append(mitigation_catalog_item)

        technique_catalog: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.technique_catalog, Unset):
            technique_catalog = []
            for technique_catalog_item_data in self.technique_catalog:
                technique_catalog_item = technique_catalog_item_data.to_dict()
                technique_catalog.append(technique_catalog_item)

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "summary": summary,
            }
        )
        if assets is not UNSET:
            field_dict["assets"] = assets
        if attachment_enrichment is not UNSET:
            field_dict["attachment_enrichment"] = attachment_enrichment
        if errors is not UNSET:
            field_dict["errors"] = errors
        if mitigation_catalog is not UNSET:
            field_dict["mitigation_catalog"] = mitigation_catalog
        if technique_catalog is not UNSET:
            field_dict["technique_catalog"] = technique_catalog

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.error_detail import ErrorDetail  # noqa: PLC0415
        from ..models.inventory_asset_finding import InventoryAssetFinding  # noqa: PLC0415
        from ..models.inventory_enrichment_result_attachment_enrichment_type_0 import (
            InventoryEnrichmentResultAttachmentEnrichmentType0,  # noqa: PLC0415
        )
        from ..models.inventory_mitigation_profile import InventoryMitigationProfile  # noqa: PLC0415
        from ..models.inventory_rollup import InventoryRollup  # noqa: PLC0415
        from ..models.inventory_technique_profile import InventoryTechniqueProfile  # noqa: PLC0415

        d = dict(src_dict)
        summary = InventoryRollup.from_dict(d.pop("summary"))

        _assets = d.pop("assets", UNSET)
        assets: list[InventoryAssetFinding] | Unset = UNSET
        if _assets is not UNSET:
            assets = []
            for assets_item_data in _assets:
                assets_item = InventoryAssetFinding.from_dict(assets_item_data)

                assets.append(assets_item)

        def _parse_attachment_enrichment(
            data: object,
        ) -> InventoryEnrichmentResultAttachmentEnrichmentType0 | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, dict):
                    raise TypeError()
                attachment_enrichment_type_0 = InventoryEnrichmentResultAttachmentEnrichmentType0.from_dict(data)

                return attachment_enrichment_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(InventoryEnrichmentResultAttachmentEnrichmentType0 | None | Unset, data)

        attachment_enrichment = _parse_attachment_enrichment(d.pop("attachment_enrichment", UNSET))

        _errors = d.pop("errors", UNSET)
        errors: list[ErrorDetail] | Unset = UNSET
        if _errors is not UNSET:
            errors = []
            for errors_item_data in _errors:
                errors_item = ErrorDetail.from_dict(errors_item_data)

                errors.append(errors_item)

        _mitigation_catalog = d.pop("mitigation_catalog", UNSET)
        mitigation_catalog: list[InventoryMitigationProfile] | Unset = UNSET
        if _mitigation_catalog is not UNSET:
            mitigation_catalog = []
            for mitigation_catalog_item_data in _mitigation_catalog:
                mitigation_catalog_item = InventoryMitigationProfile.from_dict(mitigation_catalog_item_data)

                mitigation_catalog.append(mitigation_catalog_item)

        _technique_catalog = d.pop("technique_catalog", UNSET)
        technique_catalog: list[InventoryTechniqueProfile] | Unset = UNSET
        if _technique_catalog is not UNSET:
            technique_catalog = []
            for technique_catalog_item_data in _technique_catalog:
                technique_catalog_item = InventoryTechniqueProfile.from_dict(technique_catalog_item_data)

                technique_catalog.append(technique_catalog_item)

        inventory_enrichment_result = cls(
            summary=summary,
            assets=assets,
            attachment_enrichment=attachment_enrichment,
            errors=errors,
            mitigation_catalog=mitigation_catalog,
            technique_catalog=technique_catalog,
        )

        inventory_enrichment_result.additional_properties = d
        return inventory_enrichment_result

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

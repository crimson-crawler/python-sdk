from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, BinaryIO, Generator, TextIO, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.artifact_enrichment_file_input import ArtifactEnrichmentFileInput
    from ..models.inventory_asset import InventoryAsset


T = TypeVar("T", bound="InventoryEnrichmentRequest")


@_attrs_define
class InventoryEnrichmentRequest:
    """Submit product and package assets for asynchronous CVE findings and a portfolio rollup.

    Product assets use CPE matching. Assets with `ecosystem` set use package-advisory matching.
    Each asset can carry deployment and ownership context, which is preserved in the result.

        Attributes:
            items (list[InventoryAsset]): Assets to enrich (1-200). Each asset may carry one version or up to five versions;
                findings for the same asset are combined. Larger inventories can take longer to finish.
            attachments_files (list[ArtifactEnrichmentFileInput] | Unset): Optional attached files as base64-encoded bytes.
                Supports the same spreadsheet, PDF, email, scan, and text formats as Artifact Enrichment and combines them with
                `attachments_text`. Maximum 20 files.
            attachments_text (None | str | Unset): Optional text extracted from artifacts attached to the inventory, such as
                reports, IOC lists, or prior enrichments. When present, the Artifact Enricher analyzes it and returns the report
                in `result.attachment_enrichment`. Maximum 500,000 characters.
            include (list[str] | Unset): Per-asset CVE layers to include. Replaces the default list. Allowed values:
                affected_products, campaigns, capec, cwe, defend, details, detections, epss, exploits, groups, kev,
                knowledgebase, misp, mitigations, navigator, nist_controls, osv, poc, risk_summary, software, ssvc, summary,
                techniques, tie, web, web_scrape. Summary, web, web_scrape, and navigator are accepted for product compatibility
                but omitted by Inventory Enrichment.
    """

    items: list[InventoryAsset]
    attachments_files: list[ArtifactEnrichmentFileInput] | Unset = UNSET
    attachments_text: None | str | Unset = UNSET
    include: list[str] | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        from ..models.artifact_enrichment_file_input import ArtifactEnrichmentFileInput
        from ..models.inventory_asset import InventoryAsset

        items = []
        for items_item_data in self.items:
            items_item = items_item_data.to_dict()
            items.append(items_item)

        attachments_files: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.attachments_files, Unset):
            attachments_files = []
            for attachments_files_item_data in self.attachments_files:
                attachments_files_item = attachments_files_item_data.to_dict()
                attachments_files.append(attachments_files_item)

        attachments_text: None | str | Unset
        if isinstance(self.attachments_text, Unset):
            attachments_text = UNSET
        else:
            attachments_text = self.attachments_text

        include: list[str] | Unset = UNSET
        if not isinstance(self.include, Unset):
            include = self.include

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "items": items,
            }
        )
        if attachments_files is not UNSET:
            field_dict["attachments_files"] = attachments_files
        if attachments_text is not UNSET:
            field_dict["attachments_text"] = attachments_text
        if include is not UNSET:
            field_dict["include"] = include

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.artifact_enrichment_file_input import ArtifactEnrichmentFileInput
        from ..models.inventory_asset import InventoryAsset

        d = dict(src_dict)
        items = []
        _items = d.pop("items")
        for items_item_data in _items:
            items_item = InventoryAsset.from_dict(items_item_data)

            items.append(items_item)

        _attachments_files = d.pop("attachments_files", UNSET)
        attachments_files: list[ArtifactEnrichmentFileInput] | Unset = UNSET
        if _attachments_files is not UNSET:
            attachments_files = []
            for attachments_files_item_data in _attachments_files:
                attachments_files_item = ArtifactEnrichmentFileInput.from_dict(attachments_files_item_data)

                attachments_files.append(attachments_files_item)

        def _parse_attachments_text(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        attachments_text = _parse_attachments_text(d.pop("attachments_text", UNSET))

        include = cast(list[str], d.pop("include", UNSET))

        inventory_enrichment_request = cls(
            items=items,
            attachments_files=attachments_files,
            attachments_text=attachments_text,
            include=include,
        )

        inventory_enrichment_request.additional_properties = d
        return inventory_enrichment_request

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

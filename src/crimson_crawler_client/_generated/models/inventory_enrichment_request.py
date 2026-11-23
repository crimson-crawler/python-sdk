from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, BinaryIO, Generator, TextIO, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.artifact_enrichment_file_input import ArtifactEnrichmentFileInput
    from ..models.artifact_text_input import ArtifactTextInput
    from ..models.inventory_asset import InventoryAsset
    from ..models.vex_overlay_file import VexOverlayFile


T = TypeVar("T", bound="InventoryEnrichmentRequest")


@_attrs_define
class InventoryEnrichmentRequest:
    """Submit product and package assets for asynchronous CVE findings and a portfolio rollup.

    Product assets use CPE matching. Assets with `ecosystem` set use package-advisory matching.
    Each asset can carry deployment and ownership context, which is preserved in the result.
    An optional `vex_overlay` carries VEX statements (OpenVEX 0.2.0 / CSAF 2.0) that mark matching
    `not_affected` / `fixed` findings `suppressed_by_vex` — retained with their justification, excluded
    from the actionable counts — instead of re-reporting them.

        Attributes:
            items (list[InventoryAsset]): Assets to enrich (1-1000, of which at most 200 product assets without an
                `ecosystem`). Each asset may carry one version or up to five versions; findings for the same asset are combined.
                Larger inventories take longer to finish.
            attached_artifact_ids (list[str] | Unset): LEGACY whole-run provenance: the ids of the stored artifacts whose
                content is in the legacy scalar `attachments_text`. Recorded on the attachment report's `attachment_sources`
                (kind `text`), and every reference extracted from that text carries all of them. For exact per-reference
                attribution use `attachments_texts`, where each block names its own artifact. Ignored when `attachments_text` is
                empty.
            attachments_files (list[ArtifactEnrichmentFileInput] | Unset): Optional attached files as base64-encoded bytes.
                Supports the same formats as Artifact Enrichment (PDF (text layer), Word (.docx), PowerPoint (.pptx), Excel/CSV,
                EML, HTML, nmap/Nessus XML, STIX/SBOM/SARIF/MISP JSON, or any text) and combines them with `attachments_text`.
                Maximum 20 files.
            attachments_text (None | str | Unset): Optional text extracted from artifacts attached to the inventory, such as
                reports, IOC lists, or prior enrichments. When present, the Artifact Enricher analyzes it and returns the report
                in `result.attachment_enrichment`. Maximum 500,000 characters. Name the artifacts the text came from in
                `attached_artifact_ids` and the report records them as its sources — attribution is read from that field only,
                never guessed from the text.
            attachments_texts (list[ArtifactTextInput] | Unset): Structured attachment text blocks, each optionally naming
                the artifact it came from. Use this instead of the legacy scalar `attachments_text` when the content came from
                more than one artifact: every block is its own source, so a reference found in one block is attributed to that
                block's `source_artifact_id` and a reference found in several carries all of their ids. Combined with
                `attachments_text` and `attachments_files`; the aggregate of `attachments_text` + `attachments_texts[].text` is
                capped.
            include (list[str] | None | Unset): Per-asset CVE layers to include. Omit it for **every layer the product route
                accepts** minus the reasoned exclusions; optional public metadata follows the deployment setting. Pass a list to
                narrow it. Allowed values: affected_products, campaigns, capec, cisa_kev, cwe, defend, details, detections,
                epss, exploits, groups, kev, knowledgebase, log_sources, metasploit, misp, mitigations, navigator,
                nist_controls, nuclei, osv, osv_restricted, poc, risk_summary, software, ssvc, summary, techniques, tie,
                lifecycle, cvss_bt, vulnrichment, cellular_core, certfr_advisories, jvn, ot_vendor_advisories, weakness_ranks,
                emb3d, csaf_advisories. `capec_full`, `csaf_advisories_full`, and `certfr_advisories_full` request full nested
                CVE rows. For full log sources, PoCs, Sigma rules, or D3FEND rows, call enrich/cve with the CVE ID,
                `techniques`, the base layer, and its `log_sources_full`, `poc_full`, `sigma_full`, or `defend_full` token.
                Summary and navigator are accepted for product compatibility but omitted by Inventory Enrichment. When the
                deployment enables public metadata (`ENRICH_PUBLIC_METADATA`, on by default), cisa_kev, metasploit, and nuclei
                are added automatically. `ot_context` adds the per-CVE OT/RF block (sectors, protocols, fix availability, KEV-
                OT, RF technology, 62443).
            vex_overlay (None | Unset | VexOverlayFile): Optional VEX suppression overlay (OpenVEX 0.2.0 or CSAF 2.0 VEX
                JSON). Statements that are `not_affected`/`known_not_affected`/`fixed` for a CVE on one of the submitted assets'
                own CPE identifiers mark that finding `suppressed_by_vex` in the result — retained, labeled with the statement's
                justification, and excluded from the actionable posture counts. `affected`/`under_investigation` statements
                never suppress. The enricher's own OpenVEX/CSAF exports re-ingest: flip a statement to `not_affected`/`fixed`
                and submit it back.
    """

    items: list[InventoryAsset]
    attached_artifact_ids: list[str] | Unset = UNSET
    attachments_files: list[ArtifactEnrichmentFileInput] | Unset = UNSET
    attachments_text: None | str | Unset = UNSET
    attachments_texts: list[ArtifactTextInput] | Unset = UNSET
    include: list[str] | None | Unset = UNSET
    vex_overlay: None | Unset | VexOverlayFile = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        from ..models.artifact_enrichment_file_input import ArtifactEnrichmentFileInput  # noqa: PLC0415
        from ..models.artifact_text_input import ArtifactTextInput  # noqa: PLC0415
        from ..models.inventory_asset import InventoryAsset  # noqa: PLC0415
        from ..models.vex_overlay_file import VexOverlayFile  # noqa: PLC0415

        items = []
        for items_item_data in self.items:
            items_item = items_item_data.to_dict()
            items.append(items_item)

        attached_artifact_ids: list[str] | Unset = UNSET
        if not isinstance(self.attached_artifact_ids, Unset):
            attached_artifact_ids = self.attached_artifact_ids

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

        attachments_texts: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.attachments_texts, Unset):
            attachments_texts = []
            for attachments_texts_item_data in self.attachments_texts:
                attachments_texts_item = attachments_texts_item_data.to_dict()
                attachments_texts.append(attachments_texts_item)

        include: list[str] | None | Unset
        if isinstance(self.include, Unset):
            include = UNSET
        elif isinstance(self.include, list):
            include = self.include

        else:
            include = self.include

        vex_overlay: dict[str, Any] | None | Unset
        if isinstance(self.vex_overlay, Unset):
            vex_overlay = UNSET
        elif isinstance(self.vex_overlay, VexOverlayFile):
            vex_overlay = self.vex_overlay.to_dict()
        else:
            vex_overlay = self.vex_overlay

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "items": items,
            }
        )
        if attached_artifact_ids is not UNSET:
            field_dict["attached_artifact_ids"] = attached_artifact_ids
        if attachments_files is not UNSET:
            field_dict["attachments_files"] = attachments_files
        if attachments_text is not UNSET:
            field_dict["attachments_text"] = attachments_text
        if attachments_texts is not UNSET:
            field_dict["attachments_texts"] = attachments_texts
        if include is not UNSET:
            field_dict["include"] = include
        if vex_overlay is not UNSET:
            field_dict["vex_overlay"] = vex_overlay

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.artifact_enrichment_file_input import ArtifactEnrichmentFileInput  # noqa: PLC0415
        from ..models.artifact_text_input import ArtifactTextInput  # noqa: PLC0415
        from ..models.inventory_asset import InventoryAsset  # noqa: PLC0415
        from ..models.vex_overlay_file import VexOverlayFile  # noqa: PLC0415

        d = dict(src_dict)
        items = []
        _items = d.pop("items")
        for items_item_data in _items:
            items_item = InventoryAsset.from_dict(items_item_data)

            items.append(items_item)

        attached_artifact_ids = cast(list[str], d.pop("attached_artifact_ids", UNSET))

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

        _attachments_texts = d.pop("attachments_texts", UNSET)
        attachments_texts: list[ArtifactTextInput] | Unset = UNSET
        if _attachments_texts is not UNSET:
            attachments_texts = []
            for attachments_texts_item_data in _attachments_texts:
                attachments_texts_item = ArtifactTextInput.from_dict(attachments_texts_item_data)

                attachments_texts.append(attachments_texts_item)

        def _parse_include(data: object) -> list[str] | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, list):
                    raise TypeError()
                include_type_0 = cast(list[str], data)

                return include_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(list[str] | None | Unset, data)

        include = _parse_include(d.pop("include", UNSET))

        def _parse_vex_overlay(data: object) -> None | Unset | VexOverlayFile:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, dict):
                    raise TypeError()
                vex_overlay_type_0 = VexOverlayFile.from_dict(data)

                return vex_overlay_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(None | Unset | VexOverlayFile, data)

        vex_overlay = _parse_vex_overlay(d.pop("vex_overlay", UNSET))

        inventory_enrichment_request = cls(
            items=items,
            attached_artifact_ids=attached_artifact_ids,
            attachments_files=attachments_files,
            attachments_text=attachments_text,
            attachments_texts=attachments_texts,
            include=include,
            vex_overlay=vex_overlay,
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

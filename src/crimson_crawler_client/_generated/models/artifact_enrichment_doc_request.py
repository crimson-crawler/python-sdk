from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, BinaryIO, Generator, TextIO, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..models.artifact_enrichment_doc_request_formats_item import ArtifactEnrichmentDocRequestFormatsItem
from ..models.artifact_enrichment_doc_request_tlp import ArtifactEnrichmentDocRequestTlp
from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.artifact_enrichment_file_input import ArtifactEnrichmentFileInput
    from ..models.artifact_enrichment_stakeholder import ArtifactEnrichmentStakeholder
    from ..models.artifact_text_input import ArtifactTextInput


T = TypeVar("T", bound="ArtifactEnrichmentDocRequest")


@_attrs_define
class ArtifactEnrichmentDocRequest:
    """Extract security references from an artifact and enrich them into one graded report.

    Paste ``text`` and/or upload ``files`` (nmap XML, Tenable/Qualys CSV, PDF advisory, EML).
    Every CVE, product, weakness, technique, and indicator found is enriched into a single
    report: an SSVC decision and PATCH/BLOCK/WATCH/INFO action per reference, weaponization
    scores, a prioritized worklist with KEV deadlines, ATT&CK technique mappings with detection
    and mitigation guidance, kill-chain attack paths, and machine-readable exports.

        Attributes:
            attached_artifact_ids (list[str] | Unset): LEGACY whole-run provenance: the ids of the stored artifacts whose
                content is in the legacy scalar `text`. Recorded on the report's `attachment_sources`, and every reference
                extracted from `text` carries all of them (with several, the text is a merge and only the caller knows which
                block each value sat in). For exact per-reference attribution use `texts`, where each block names its own
                artifact. Never parsed out of the text. Ignored when `text` is empty — ids that name no content are not
                published as sources.
            files (list[ArtifactEnrichmentFileInput] | Unset): Uploaded artifacts as base64-encoded bytes: PDF (text layer),
                Word (.docx), PowerPoint (.pptx), Excel/CSV, EML, HTML, nmap/Nessus XML, STIX/SBOM/SARIF/MISP JSON, or any text.
                Parsed by format and combined with `text`. Images and scanned PDFs are not read. Up to 20 files per enrichment.
            formats (list[ArtifactEnrichmentDocRequestFormatsItem] | Unset): Export formats to serialize from the assembled
                report. Options: report, json (raw ArtifactEnrichmentReport), stix (2.1 bundle), vex (OpenVEX), csaf (CSAF 2.0
                VEX), navigator (ATT&CK Navigator v4.5 layer), kev_remediation, oscal_poam, misp (event JSON), csv.
            include (list[str] | Unset): Report sections to include. Replaces the default list. Allowed values:
                attack_paths, citations, defenses, enrichment, narrative, rollups, source_corroboration. Core decisions, scores,
                grades, and prioritized actions are always returned.
            stakeholder (ArtifactEnrichmentStakeholder | Unset): Deployment context for the SSVC decision.

                Defaults represent a conservative unknown environment: ``exposure=open`` and
                ``human_impact=medium``. ``method`` selects the CERT/CC Deployer tree (default) or the CISA
                Coordinator tree. ``human_impact`` applies to the Deployer tree; ``mission_prevalence`` and
                ``public_wellbeing_impact`` apply to the Coordinator tree.
            text (None | str | Unset): Pasted text — an IR note, advisory, or raw indicators. References are extracted
                automatically. Use `texts` instead when the content came from more than one artifact, so each reference can be
                attributed to the artifact it actually appeared in.
            texts (list[ArtifactTextInput] | Unset): Structured text blocks, each optionally naming the artifact it came
                from. Combined with the legacy `text` field and `files`; every block is its own source, so a reference found in
                one block is attributed to that block's `source_artifact_id` and a reference found in several carries all of
                their ids. Up to 20 blocks; the aggregate of `text` + `texts[].text` is capped.
            tlp (ArtifactEnrichmentDocRequestTlp | Unset): TLP 2.0 sharing marking stamped into every requested export that
                has a slot for one: CLEAR, GREEN, AMBER, AMBER+STRICT or RED. Omit it and the run uses YOUR saved default for
                the Artifact Enricher (GET/PUT /artifact-manager/settings, `artifact_tlp`), which is AMBER until you set one —
                an export can carry customer input, so nothing is marked CLEAR unless you choose it. An explicit `tlp` always
                wins over the saved default. CSAF 2.0 only accepts TLP 1.0 labels, so CLEAR is written as WHITE and AMBER+STRICT
                as AMBER plus a distribution note. STIX 2.1 gets the official TLP 2.0 marking-definition on every object, MISP a
                `tlp:*` event tag, Navigator a `TLP` metadata entry, OSCAL a `tlp` metadata prop, and the human report and KEV
                worksheet (both Crimson wrapper dicts) a top-level `tlp` label — the KEV worksheet's rows stay CISA-verbatim and
                the raw `json` pass-through is unmarked. OpenVEX (closed schema) and CSV (fixed column contract) have no marking
                slot and stay unmarked. Default: ArtifactEnrichmentDocRequestTlp.AMBER.
    """

    attached_artifact_ids: list[str] | Unset = UNSET
    files: list[ArtifactEnrichmentFileInput] | Unset = UNSET
    formats: list[ArtifactEnrichmentDocRequestFormatsItem] | Unset = UNSET
    include: list[str] | Unset = UNSET
    stakeholder: ArtifactEnrichmentStakeholder | Unset = UNSET
    text: None | str | Unset = UNSET
    texts: list[ArtifactTextInput] | Unset = UNSET
    tlp: ArtifactEnrichmentDocRequestTlp | Unset = ArtifactEnrichmentDocRequestTlp.AMBER
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        from ..models.artifact_enrichment_file_input import ArtifactEnrichmentFileInput  # noqa: PLC0415
        from ..models.artifact_enrichment_stakeholder import ArtifactEnrichmentStakeholder  # noqa: PLC0415
        from ..models.artifact_text_input import ArtifactTextInput  # noqa: PLC0415

        attached_artifact_ids: list[str] | Unset = UNSET
        if not isinstance(self.attached_artifact_ids, Unset):
            attached_artifact_ids = self.attached_artifact_ids

        files: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.files, Unset):
            files = []
            for files_item_data in self.files:
                files_item = files_item_data.to_dict()
                files.append(files_item)

        formats: list[str] | Unset = UNSET
        if not isinstance(self.formats, Unset):
            formats = []
            for formats_item_data in self.formats:
                formats_item = formats_item_data.value
                formats.append(formats_item)

        include: list[str] | Unset = UNSET
        if not isinstance(self.include, Unset):
            include = self.include

        stakeholder: dict[str, Any] | Unset = UNSET
        if not isinstance(self.stakeholder, Unset):
            stakeholder = self.stakeholder.to_dict()

        text: None | str | Unset
        if isinstance(self.text, Unset):
            text = UNSET
        else:
            text = self.text

        texts: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.texts, Unset):
            texts = []
            for texts_item_data in self.texts:
                texts_item = texts_item_data.to_dict()
                texts.append(texts_item)

        tlp: str | Unset = UNSET
        if not isinstance(self.tlp, Unset):
            tlp = self.tlp.value

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if attached_artifact_ids is not UNSET:
            field_dict["attached_artifact_ids"] = attached_artifact_ids
        if files is not UNSET:
            field_dict["files"] = files
        if formats is not UNSET:
            field_dict["formats"] = formats
        if include is not UNSET:
            field_dict["include"] = include
        if stakeholder is not UNSET:
            field_dict["stakeholder"] = stakeholder
        if text is not UNSET:
            field_dict["text"] = text
        if texts is not UNSET:
            field_dict["texts"] = texts
        if tlp is not UNSET:
            field_dict["tlp"] = tlp

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.artifact_enrichment_file_input import ArtifactEnrichmentFileInput  # noqa: PLC0415
        from ..models.artifact_enrichment_stakeholder import ArtifactEnrichmentStakeholder  # noqa: PLC0415
        from ..models.artifact_text_input import ArtifactTextInput  # noqa: PLC0415

        d = dict(src_dict)
        attached_artifact_ids = cast(list[str], d.pop("attached_artifact_ids", UNSET))

        _files = d.pop("files", UNSET)
        files: list[ArtifactEnrichmentFileInput] | Unset = UNSET
        if _files is not UNSET:
            files = []
            for files_item_data in _files:
                files_item = ArtifactEnrichmentFileInput.from_dict(files_item_data)

                files.append(files_item)

        _formats = d.pop("formats", UNSET)
        formats: list[ArtifactEnrichmentDocRequestFormatsItem] | Unset = UNSET
        if _formats is not UNSET:
            formats = []
            for formats_item_data in _formats:
                formats_item = ArtifactEnrichmentDocRequestFormatsItem(formats_item_data)

                formats.append(formats_item)

        include = cast(list[str], d.pop("include", UNSET))

        _stakeholder = d.pop("stakeholder", UNSET)
        stakeholder: ArtifactEnrichmentStakeholder | Unset
        if isinstance(_stakeholder, Unset):
            stakeholder = UNSET
        else:
            stakeholder = ArtifactEnrichmentStakeholder.from_dict(_stakeholder)

        def _parse_text(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        text = _parse_text(d.pop("text", UNSET))

        _texts = d.pop("texts", UNSET)
        texts: list[ArtifactTextInput] | Unset = UNSET
        if _texts is not UNSET:
            texts = []
            for texts_item_data in _texts:
                texts_item = ArtifactTextInput.from_dict(texts_item_data)

                texts.append(texts_item)

        _tlp = d.pop("tlp", UNSET)
        tlp: ArtifactEnrichmentDocRequestTlp | Unset
        if isinstance(_tlp, Unset):
            tlp = UNSET
        else:
            tlp = ArtifactEnrichmentDocRequestTlp(_tlp)

        artifact_enrichment_doc_request = cls(
            attached_artifact_ids=attached_artifact_ids,
            files=files,
            formats=formats,
            include=include,
            stakeholder=stakeholder,
            text=text,
            texts=texts,
            tlp=tlp,
        )

        artifact_enrichment_doc_request.additional_properties = d
        return artifact_enrichment_doc_request

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

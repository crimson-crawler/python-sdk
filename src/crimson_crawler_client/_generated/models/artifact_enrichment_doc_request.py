from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, BinaryIO, Generator, TextIO, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..models.artifact_enrichment_doc_request_formats_item import ArtifactEnrichmentDocRequestFormatsItem
from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.artifact_enrichment_file_input import ArtifactEnrichmentFileInput
    from ..models.artifact_enrichment_stakeholder import ArtifactEnrichmentStakeholder


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
            files (list[ArtifactEnrichmentFileInput] | Unset): Uploaded artifacts as base64-encoded bytes — nmap XML,
                Tenable/Qualys CSV, PDF advisory, or EML. Parsed by format and combined with `text`. Up to 20 files per
                enrichment.
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
                automatically.
    """

    files: list[ArtifactEnrichmentFileInput] | Unset = UNSET
    formats: list[ArtifactEnrichmentDocRequestFormatsItem] | Unset = UNSET
    include: list[str] | Unset = UNSET
    stakeholder: ArtifactEnrichmentStakeholder | Unset = UNSET
    text: None | str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        from ..models.artifact_enrichment_file_input import ArtifactEnrichmentFileInput
        from ..models.artifact_enrichment_stakeholder import ArtifactEnrichmentStakeholder

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

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
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

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.artifact_enrichment_file_input import ArtifactEnrichmentFileInput
        from ..models.artifact_enrichment_stakeholder import ArtifactEnrichmentStakeholder

        d = dict(src_dict)
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

        artifact_enrichment_doc_request = cls(
            files=files,
            formats=formats,
            include=include,
            stakeholder=stakeholder,
            text=text,
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

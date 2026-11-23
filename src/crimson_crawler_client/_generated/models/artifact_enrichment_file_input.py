from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, BinaryIO, Generator, TextIO, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="ArtifactEnrichmentFileInput")


@_attrs_define
class ArtifactEnrichmentFileInput:
    """One uploaded artifact: base64-encoded bytes plus the filename used for format detection.

    Attributes:
        content_b64 (str): Base64-encoded file bytes (~20 MB decoded cap).
        filename (str | Unset): Original filename — helps pick the format (e.g. scan.nmap.xml, hosts.csv, advisory.pdf,
            report.docx, alert.eml); content is sniffed first. Default: ''.
        source_artifact_id (None | str | Unset): Id of the stored artifact this file was exported from, when the caller
            knows it. Echoed back on the report's `attachment_sources` and used to attribute the report's references to it —
            bytes carry no identity of their own, so a file nobody can name stays unattributed rather than being guessed at.
    """

    content_b64: str
    filename: str | Unset = ""
    source_artifact_id: None | str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        content_b64 = self.content_b64

        filename = self.filename

        source_artifact_id: None | str | Unset
        if isinstance(self.source_artifact_id, Unset):
            source_artifact_id = UNSET
        else:
            source_artifact_id = self.source_artifact_id

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "content_b64": content_b64,
            }
        )
        if filename is not UNSET:
            field_dict["filename"] = filename
        if source_artifact_id is not UNSET:
            field_dict["source_artifact_id"] = source_artifact_id

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        content_b64 = d.pop("content_b64")

        filename = d.pop("filename", UNSET)

        def _parse_source_artifact_id(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        source_artifact_id = _parse_source_artifact_id(d.pop("source_artifact_id", UNSET))

        artifact_enrichment_file_input = cls(
            content_b64=content_b64,
            filename=filename,
            source_artifact_id=source_artifact_id,
        )

        artifact_enrichment_file_input.additional_properties = d
        return artifact_enrichment_file_input

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

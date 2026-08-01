from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, BinaryIO, Generator, TextIO, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="ArtifactEnrichmentFileInput")


@_attrs_define
class ArtifactEnrichmentFileInput:
    """One uploaded artifact: base64-encoded bytes plus the filename used for format detection.

    Attributes:
        content_b64 (str): Base64-encoded file bytes (~20 MB decoded cap).
        filename (str | Unset): Original filename — sets the format (e.g. scan.nmap.xml, hosts.csv, advisory.pdf,
            alert.eml). Default: ''.
    """

    content_b64: str
    filename: str | Unset = ""
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        content_b64 = self.content_b64

        filename = self.filename

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "content_b64": content_b64,
            }
        )
        if filename is not UNSET:
            field_dict["filename"] = filename

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        content_b64 = d.pop("content_b64")

        filename = d.pop("filename", UNSET)

        artifact_enrichment_file_input = cls(
            content_b64=content_b64,
            filename=filename,
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

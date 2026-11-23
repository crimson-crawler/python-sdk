from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, BinaryIO, Generator, TextIO, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="AttachmentSource")


@_attrs_define
class AttachmentSource:
    """One artifact whose content this report was built from.

    Structured provenance, supplied by the caller: each `texts[]` entry names the artifact behind that
    block, each uploaded file may carry `source_artifact_id`, and the legacy `attached_artifact_ids`
    names the artifacts behind the legacy scalar `text`. Nothing is inferred from the text, and only
    artifacts that ACTUALLY contributed a surviving reference appear — a named artifact whose block was
    dropped by the reference cap, or whose content yielded no reference at all, is not listed.

        Attributes:
            artifact_id (str): Id of the stored artifact (the library's artifact uuid)
            kind (str | Unset): What kind of block carried this source's content: 'text' for a `texts[]` entry or the legacy
                `attached_artifact_ids`, 'file' for an uploaded attachment Default: ''.
            name (None | str | Unset): Display name, from the caller (or the file's filename)
    """

    artifact_id: str
    kind: str | Unset = ""
    name: None | str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        artifact_id = self.artifact_id

        kind = self.kind

        name: None | str | Unset
        if isinstance(self.name, Unset):
            name = UNSET
        else:
            name = self.name

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "artifact_id": artifact_id,
            }
        )
        if kind is not UNSET:
            field_dict["kind"] = kind
        if name is not UNSET:
            field_dict["name"] = name

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        artifact_id = d.pop("artifact_id")

        kind = d.pop("kind", UNSET)

        def _parse_name(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        name = _parse_name(d.pop("name", UNSET))

        attachment_source = cls(
            artifact_id=artifact_id,
            kind=kind,
            name=name,
        )

        attachment_source.additional_properties = d
        return attachment_source

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

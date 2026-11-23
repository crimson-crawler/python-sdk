from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, BinaryIO, Generator, TextIO, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="ArtifactTextInput")


@_attrs_define
class ArtifactTextInput:
    """One block of pasted/forwarded text, with the artifact it came from when the caller knows it.

    The structured counterpart to the legacy scalar ``text`` / ``attachments_text``. Each entry is
    its own source: its ``source_artifact_id`` (when set) attributes every reference extracted from
    THAT block to that artifact, and a block with no id is unnamed — it is never attributed to some
    other entry's artifact. This is what makes multi-artifact attribution exact: a value found in
    two entries carries both origin ids, and a value found in one is attributed to that one.

        Attributes:
            text (str): The text block. References are extracted from it exactly like the legacy `text` field.
            filename (None | str | Unset): Display name for this block's source (e.g. the report filename), when the caller
                has one.
            source_artifact_id (None | str | Unset): Id of the stored artifact this block's text came from. Recorded on the
                report's `attachment_sources` and used to attribute the references found in THIS block to it. Leave unset when
                the caller cannot name the artifact — an unnamed block stays unattributed rather than being assigned to another
                entry's artifact.
    """

    text: str
    filename: None | str | Unset = UNSET
    source_artifact_id: None | str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        text = self.text

        filename: None | str | Unset
        if isinstance(self.filename, Unset):
            filename = UNSET
        else:
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
                "text": text,
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
        text = d.pop("text")

        def _parse_filename(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        filename = _parse_filename(d.pop("filename", UNSET))

        def _parse_source_artifact_id(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        source_artifact_id = _parse_source_artifact_id(d.pop("source_artifact_id", UNSET))

        artifact_text_input = cls(
            text=text,
            filename=filename,
            source_artifact_id=source_artifact_id,
        )

        artifact_text_input.additional_properties = d
        return artifact_text_input

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

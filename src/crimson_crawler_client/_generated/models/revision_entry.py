from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, BinaryIO, Generator, TextIO, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="RevisionEntry")


@_attrs_define
class RevisionEntry:
    """One revision of a knowledge-base object: when it changed and which KB versions carried it.

    Attributes:
        latest (bool | None | Unset): True for the object's current revision, False when the source states a different
            revision is current, and null when the source did not establish current status. Never inferred from list order.
        modified (str | Unset): When this revision was published (ISO 8601) Default: ''.
        versions (list[str] | Unset): KB versions that carried this revision (e.g. ['18.0'])
    """

    latest: bool | None | Unset = UNSET
    modified: str | Unset = ""
    versions: list[str] | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        latest: bool | None | Unset
        if isinstance(self.latest, Unset):
            latest = UNSET
        else:
            latest = self.latest

        modified = self.modified

        versions: list[str] | Unset = UNSET
        if not isinstance(self.versions, Unset):
            versions = self.versions

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if latest is not UNSET:
            field_dict["latest"] = latest
        if modified is not UNSET:
            field_dict["modified"] = modified
        if versions is not UNSET:
            field_dict["versions"] = versions

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)

        def _parse_latest(data: object) -> bool | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(bool | None | Unset, data)

        latest = _parse_latest(d.pop("latest", UNSET))

        modified = d.pop("modified", UNSET)

        versions = cast(list[str], d.pop("versions", UNSET))

        revision_entry = cls(
            latest=latest,
            modified=modified,
            versions=versions,
        )

        revision_entry.additional_properties = d
        return revision_entry

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

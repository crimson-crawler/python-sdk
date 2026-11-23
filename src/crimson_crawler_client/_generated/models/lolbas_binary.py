from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, BinaryIO, Generator, TextIO, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="LOLBASBinary")


@_attrs_define
class LOLBASBinary:
    """One LOLBAS binary, reduced to facts: name, ATT&CK ids and the project page.

    No command line, description or usecase is reproduced from the GPL-3.0 catalog.

        Attributes:
            name (str): Binary or script name as the catalogue publishes it
            project_url (str): The LOLBAS project page
            source_url (str): The LOLBAS repository URL
            dataset_version (None | str | Unset): Tarball sha256 or commit the projection came from
            source (str | Unset): Stable source label Default: 'lolbas'.
            technique_ids (list[str] | Unset): ATT&CK technique ids the binary's commands declare
    """

    name: str
    project_url: str
    source_url: str
    dataset_version: None | str | Unset = UNSET
    source: str | Unset = "lolbas"
    technique_ids: list[str] | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        name = self.name

        project_url = self.project_url

        source_url = self.source_url

        dataset_version: None | str | Unset
        if isinstance(self.dataset_version, Unset):
            dataset_version = UNSET
        else:
            dataset_version = self.dataset_version

        source = self.source

        technique_ids: list[str] | Unset = UNSET
        if not isinstance(self.technique_ids, Unset):
            technique_ids = self.technique_ids

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "name": name,
                "project_url": project_url,
                "source_url": source_url,
            }
        )
        if dataset_version is not UNSET:
            field_dict["dataset_version"] = dataset_version
        if source is not UNSET:
            field_dict["source"] = source
        if technique_ids is not UNSET:
            field_dict["technique_ids"] = technique_ids

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        name = d.pop("name")

        project_url = d.pop("project_url")

        source_url = d.pop("source_url")

        def _parse_dataset_version(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        dataset_version = _parse_dataset_version(d.pop("dataset_version", UNSET))

        source = d.pop("source", UNSET)

        technique_ids = cast(list[str], d.pop("technique_ids", UNSET))

        lolbas_binary = cls(
            name=name,
            project_url=project_url,
            source_url=source_url,
            dataset_version=dataset_version,
            source=source,
            technique_ids=technique_ids,
        )

        lolbas_binary.additional_properties = d
        return lolbas_binary

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

from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, BinaryIO, Generator, TextIO, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="GTFOBinsBinary")


@_attrs_define
class GTFOBinsBinary:
    """One GTFOBins tool, reduced to facts: name, function categories, ATT&CK ids, project page.

    No shell snippet, comment or description is reproduced from the GPL-3.0 catalogue.

        Attributes:
            name (str): Tool name as the catalogue publishes it
            project_url (str): The GTFOBins project page
            source_url (str): The GTFOBins repository URL
            alias_of (None | str | Unset): Tool this entry is only an alias for, when it declares no functions
            contexts (list[str] | Unset): Execution contexts the entry declares (sudo, suid, …)
            dataset_version (None | str | Unset): Tarball sha256 the projection came from
            functions (list[str] | Unset): GTFOBins function categories the entry declares
            source (str | Unset): Stable source label Default: 'gtfobins'.
            technique_ids (list[str] | Unset): ATT&CK technique ids the functions and contexts map onto
    """

    name: str
    project_url: str
    source_url: str
    alias_of: None | str | Unset = UNSET
    contexts: list[str] | Unset = UNSET
    dataset_version: None | str | Unset = UNSET
    functions: list[str] | Unset = UNSET
    source: str | Unset = "gtfobins"
    technique_ids: list[str] | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        name = self.name

        project_url = self.project_url

        source_url = self.source_url

        alias_of: None | str | Unset
        if isinstance(self.alias_of, Unset):
            alias_of = UNSET
        else:
            alias_of = self.alias_of

        contexts: list[str] | Unset = UNSET
        if not isinstance(self.contexts, Unset):
            contexts = self.contexts

        dataset_version: None | str | Unset
        if isinstance(self.dataset_version, Unset):
            dataset_version = UNSET
        else:
            dataset_version = self.dataset_version

        functions: list[str] | Unset = UNSET
        if not isinstance(self.functions, Unset):
            functions = self.functions

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
        if alias_of is not UNSET:
            field_dict["alias_of"] = alias_of
        if contexts is not UNSET:
            field_dict["contexts"] = contexts
        if dataset_version is not UNSET:
            field_dict["dataset_version"] = dataset_version
        if functions is not UNSET:
            field_dict["functions"] = functions
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

        def _parse_alias_of(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        alias_of = _parse_alias_of(d.pop("alias_of", UNSET))

        contexts = cast(list[str], d.pop("contexts", UNSET))

        def _parse_dataset_version(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        dataset_version = _parse_dataset_version(d.pop("dataset_version", UNSET))

        functions = cast(list[str], d.pop("functions", UNSET))

        source = d.pop("source", UNSET)

        technique_ids = cast(list[str], d.pop("technique_ids", UNSET))

        gtfo_bins_binary = cls(
            name=name,
            project_url=project_url,
            source_url=source_url,
            alias_of=alias_of,
            contexts=contexts,
            dataset_version=dataset_version,
            functions=functions,
            source=source,
            technique_ids=technique_ids,
        )

        gtfo_bins_binary.additional_properties = d
        return gtfo_bins_binary

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

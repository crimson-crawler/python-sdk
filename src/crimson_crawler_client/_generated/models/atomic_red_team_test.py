from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, BinaryIO, Generator, TextIO, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="AtomicRedTeamTest")


@_attrs_define
class AtomicRedTeamTest:
    """One Atomic Red Team test exercising an ATT&CK technique, reduced to facts.

    MIT-licensed upstream, but only metadata ships: name, GUID, supported platforms, the
    executor kind and the elevation flag. Command bodies, cleanup commands and descriptions
    never leave the upstream repository; `link` points at the technique's YAML file.

        Attributes:
            auto_generated_guid (str): The test's stable upstream GUID
            link (str): The technique's YAML file in the Atomic Red Team repository
            name (str): Atomic test name
            source_url (str): The Atomic Red Team repository URL
            technique_id (str): ATT&CK technique id the test exercises
            dataset_version (None | str | Unset): Index sha256 the projection came from
            elevation_required (bool | None | Unset): Whether the executor needs elevation; null when upstream omits the
                flag
            executor_name (None | str | Unset): Executor kind (powershell, command_prompt, bash, sh, manual)
            source (str | Unset): Stable source label Default: 'atomic_red_team'.
            supported_platforms (list[str] | Unset): Platform labels the test declares
    """

    auto_generated_guid: str
    link: str
    name: str
    source_url: str
    technique_id: str
    dataset_version: None | str | Unset = UNSET
    elevation_required: bool | None | Unset = UNSET
    executor_name: None | str | Unset = UNSET
    source: str | Unset = "atomic_red_team"
    supported_platforms: list[str] | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        auto_generated_guid = self.auto_generated_guid

        link = self.link

        name = self.name

        source_url = self.source_url

        technique_id = self.technique_id

        dataset_version: None | str | Unset
        if isinstance(self.dataset_version, Unset):
            dataset_version = UNSET
        else:
            dataset_version = self.dataset_version

        elevation_required: bool | None | Unset
        if isinstance(self.elevation_required, Unset):
            elevation_required = UNSET
        else:
            elevation_required = self.elevation_required

        executor_name: None | str | Unset
        if isinstance(self.executor_name, Unset):
            executor_name = UNSET
        else:
            executor_name = self.executor_name

        source = self.source

        supported_platforms: list[str] | Unset = UNSET
        if not isinstance(self.supported_platforms, Unset):
            supported_platforms = self.supported_platforms

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "auto_generated_guid": auto_generated_guid,
                "link": link,
                "name": name,
                "source_url": source_url,
                "technique_id": technique_id,
            }
        )
        if dataset_version is not UNSET:
            field_dict["dataset_version"] = dataset_version
        if elevation_required is not UNSET:
            field_dict["elevation_required"] = elevation_required
        if executor_name is not UNSET:
            field_dict["executor_name"] = executor_name
        if source is not UNSET:
            field_dict["source"] = source
        if supported_platforms is not UNSET:
            field_dict["supported_platforms"] = supported_platforms

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        auto_generated_guid = d.pop("auto_generated_guid")

        link = d.pop("link")

        name = d.pop("name")

        source_url = d.pop("source_url")

        technique_id = d.pop("technique_id")

        def _parse_dataset_version(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        dataset_version = _parse_dataset_version(d.pop("dataset_version", UNSET))

        def _parse_elevation_required(data: object) -> bool | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(bool | None | Unset, data)

        elevation_required = _parse_elevation_required(d.pop("elevation_required", UNSET))

        def _parse_executor_name(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        executor_name = _parse_executor_name(d.pop("executor_name", UNSET))

        source = d.pop("source", UNSET)

        supported_platforms = cast(list[str], d.pop("supported_platforms", UNSET))

        atomic_red_team_test = cls(
            auto_generated_guid=auto_generated_guid,
            link=link,
            name=name,
            source_url=source_url,
            technique_id=technique_id,
            dataset_version=dataset_version,
            elevation_required=elevation_required,
            executor_name=executor_name,
            source=source,
            supported_platforms=supported_platforms,
        )

        atomic_red_team_test.additional_properties = d
        return atomic_red_team_test

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

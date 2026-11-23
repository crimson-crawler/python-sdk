from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, BinaryIO, Generator, TextIO, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="FrameworkMapping")


@_attrs_define
class FrameworkMapping:
    """One CTID control/capability mapping for an ATT&CK technique.

    The nine committed families were built against **different** ATT&CK versions, so
    `attack_version` is a row field and rows are never merged across versions.

        Attributes:
            attack_version (str): ATT&CK version this mapping row was built against
            control_id (str): Framework capability/control identifier
            framework (str): Framework family (aws, azure, gcp, m365, csa_ccm, veris, cri_profile, intel-vpro, cis)
            framework_version (str): The framework's own version the mapping was built from
            source_url (str): The committed dataset file's upstream URL
            technique_id (str): ATT&CK technique the row maps (the file's own attack_object_id)
            control_name (None | str | Unset): Framework capability/control name
            source (str | Unset): Stable source label Default: 'ctid_mappings'.
            url (None | str | Unset): First reference URL the mapping publishes, when it carries one
    """

    attack_version: str
    control_id: str
    framework: str
    framework_version: str
    source_url: str
    technique_id: str
    control_name: None | str | Unset = UNSET
    source: str | Unset = "ctid_mappings"
    url: None | str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        attack_version = self.attack_version

        control_id = self.control_id

        framework = self.framework

        framework_version = self.framework_version

        source_url = self.source_url

        technique_id = self.technique_id

        control_name: None | str | Unset
        if isinstance(self.control_name, Unset):
            control_name = UNSET
        else:
            control_name = self.control_name

        source = self.source

        url: None | str | Unset
        if isinstance(self.url, Unset):
            url = UNSET
        else:
            url = self.url

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "attack_version": attack_version,
                "control_id": control_id,
                "framework": framework,
                "framework_version": framework_version,
                "source_url": source_url,
                "technique_id": technique_id,
            }
        )
        if control_name is not UNSET:
            field_dict["control_name"] = control_name
        if source is not UNSET:
            field_dict["source"] = source
        if url is not UNSET:
            field_dict["url"] = url

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        attack_version = d.pop("attack_version")

        control_id = d.pop("control_id")

        framework = d.pop("framework")

        framework_version = d.pop("framework_version")

        source_url = d.pop("source_url")

        technique_id = d.pop("technique_id")

        def _parse_control_name(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        control_name = _parse_control_name(d.pop("control_name", UNSET))

        source = d.pop("source", UNSET)

        def _parse_url(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        url = _parse_url(d.pop("url", UNSET))

        framework_mapping = cls(
            attack_version=attack_version,
            control_id=control_id,
            framework=framework,
            framework_version=framework_version,
            source_url=source_url,
            technique_id=technique_id,
            control_name=control_name,
            source=source,
            url=url,
        )

        framework_mapping.additional_properties = d
        return framework_mapping

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

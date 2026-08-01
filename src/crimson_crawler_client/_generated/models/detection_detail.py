from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, BinaryIO, Generator, TextIO, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="DetectionDetail")


@_attrs_define
class DetectionDetail:
    """ATT&CK detection data source and component for detecting a technique.

    Attributes:
        data_component (str | Unset): Data component (e.g. 'Process Creation') Default: ''.
        data_source (str | Unset): Data source name (e.g. 'Process', 'Network Traffic') Default: ''.
        description (str | Unset): Detection guidance Default: ''.
        stix_id (str | Unset): Unique object identifier for cross-referencing Default: ''.
    """

    data_component: str | Unset = ""
    data_source: str | Unset = ""
    description: str | Unset = ""
    stix_id: str | Unset = ""
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        data_component = self.data_component

        data_source = self.data_source

        description = self.description

        stix_id = self.stix_id

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if data_component is not UNSET:
            field_dict["data_component"] = data_component
        if data_source is not UNSET:
            field_dict["data_source"] = data_source
        if description is not UNSET:
            field_dict["description"] = description
        if stix_id is not UNSET:
            field_dict["stix_id"] = stix_id

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        data_component = d.pop("data_component", UNSET)

        data_source = d.pop("data_source", UNSET)

        description = d.pop("description", UNSET)

        stix_id = d.pop("stix_id", UNSET)

        detection_detail = cls(
            data_component=data_component,
            data_source=data_source,
            description=description,
            stix_id=stix_id,
        )

        detection_detail.additional_properties = d
        return detection_detail

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

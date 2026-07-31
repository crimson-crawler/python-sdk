from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, BinaryIO, Generator, TextIO, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="DetectionOpportunity")


@_attrs_define
class DetectionOpportunity:
    """A detection opportunity lifted from a resolved technique's data sources.

    Attributes:
        description (str): Detection guidance
        technique_id (str): ATT&CK technique ID the detection applies to
        data_source (None | str | Unset): Detection data source (from technique.data_sources)
        source (str | Unset): Provenance of the detection guidance Default: 'attack'.
    """

    description: str
    technique_id: str
    data_source: None | str | Unset = UNSET
    source: str | Unset = "attack"
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        description = self.description

        technique_id = self.technique_id

        data_source: None | str | Unset
        if isinstance(self.data_source, Unset):
            data_source = UNSET
        else:
            data_source = self.data_source

        source = self.source

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "description": description,
                "technique_id": technique_id,
            }
        )
        if data_source is not UNSET:
            field_dict["data_source"] = data_source
        if source is not UNSET:
            field_dict["source"] = source

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        description = d.pop("description")

        technique_id = d.pop("technique_id")

        def _parse_data_source(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        data_source = _parse_data_source(d.pop("data_source", UNSET))

        source = d.pop("source", UNSET)

        detection_opportunity = cls(
            description=description,
            technique_id=technique_id,
            data_source=data_source,
            source=source,
        )

        detection_opportunity.additional_properties = d
        return detection_opportunity

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

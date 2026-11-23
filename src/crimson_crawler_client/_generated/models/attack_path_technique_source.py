from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, BinaryIO, Generator, TextIO, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="AttackPathTechniqueSource")


@_attrs_define
class AttackPathTechniqueSource:
    """Evidence linking an artifact reference to a technique.

    Attributes:
        origin_id (str): Value of the artifact reference
        origin_type (str): Kind of artifact reference
        source (str): Source of the technique relationship
        technique_id (str): ATT&CK technique ID
    """

    origin_id: str
    origin_type: str
    source: str
    technique_id: str
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        origin_id = self.origin_id

        origin_type = self.origin_type

        source = self.source

        technique_id = self.technique_id

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "origin_id": origin_id,
                "origin_type": origin_type,
                "source": source,
                "technique_id": technique_id,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        origin_id = d.pop("origin_id")

        origin_type = d.pop("origin_type")

        source = d.pop("source")

        technique_id = d.pop("technique_id")

        attack_path_technique_source = cls(
            origin_id=origin_id,
            origin_type=origin_type,
            source=source,
            technique_id=technique_id,
        )

        attack_path_technique_source.additional_properties = d
        return attack_path_technique_source

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

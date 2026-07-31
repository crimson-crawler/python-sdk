from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, BinaryIO, Generator, TextIO, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="GalaxyData")


@_attrs_define
class GalaxyData:
    """Extracted threat context linked to an indicator or event.

    Attributes:
        malware (list[str] | Unset): Malware family names associated with this indicator
        technique_ids (list[str] | Unset): ATT&CK technique IDs linked to this indicator
        threat_actors (list[str] | Unset): Threat actor names associated with this indicator
    """

    malware: list[str] | Unset = UNSET
    technique_ids: list[str] | Unset = UNSET
    threat_actors: list[str] | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        malware: list[str] | Unset = UNSET
        if not isinstance(self.malware, Unset):
            malware = self.malware

        technique_ids: list[str] | Unset = UNSET
        if not isinstance(self.technique_ids, Unset):
            technique_ids = self.technique_ids

        threat_actors: list[str] | Unset = UNSET
        if not isinstance(self.threat_actors, Unset):
            threat_actors = self.threat_actors

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if malware is not UNSET:
            field_dict["malware"] = malware
        if technique_ids is not UNSET:
            field_dict["technique_ids"] = technique_ids
        if threat_actors is not UNSET:
            field_dict["threat_actors"] = threat_actors

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        malware = cast(list[str], d.pop("malware", UNSET))

        technique_ids = cast(list[str], d.pop("technique_ids", UNSET))

        threat_actors = cast(list[str], d.pop("threat_actors", UNSET))

        galaxy_data = cls(
            malware=malware,
            technique_ids=technique_ids,
            threat_actors=threat_actors,
        )

        galaxy_data.additional_properties = d
        return galaxy_data

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

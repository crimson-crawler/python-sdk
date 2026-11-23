from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, BinaryIO, Generator, TextIO, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="FightTechnique")


@_attrs_define
class FightTechnique:
    """One MITRE FiGHT 5G technique, joined to ATT&CK by its own id.

    The join is `FGT####[.###]` → `T####[.###]` (strip `FGT`, prefix `T`, keep the dotted
    suffix); never name matching. `bluf` is FiGHT's own bottom-line summary.

        Attributes:
            id (str): FiGHT technique id (FGT#### or FGT####.###)
            name (str): FiGHT technique name
            source_url (str): The FiGHT dataset URL
            attack_id (None | str | Unset): ATT&CK id derived from the FiGHT id, if it has one
            bluf (str | Unset): FiGHT's bottom-line-up-front summary Default: ''.
            dataset_version (None | str | Unset): FiGHT release the projection recorded
            source (str | Unset): Stable source label Default: 'fight'.
            status (str | Unset): FiGHT status (Observed, Theoretical, …) Default: ''.
            tactics (list[str] | Unset): FiGHT tactic ids the technique is filed under
    """

    id: str
    name: str
    source_url: str
    attack_id: None | str | Unset = UNSET
    bluf: str | Unset = ""
    dataset_version: None | str | Unset = UNSET
    source: str | Unset = "fight"
    status: str | Unset = ""
    tactics: list[str] | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        id = self.id

        name = self.name

        source_url = self.source_url

        attack_id: None | str | Unset
        if isinstance(self.attack_id, Unset):
            attack_id = UNSET
        else:
            attack_id = self.attack_id

        bluf = self.bluf

        dataset_version: None | str | Unset
        if isinstance(self.dataset_version, Unset):
            dataset_version = UNSET
        else:
            dataset_version = self.dataset_version

        source = self.source

        status = self.status

        tactics: list[str] | Unset = UNSET
        if not isinstance(self.tactics, Unset):
            tactics = self.tactics

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "id": id,
                "name": name,
                "source_url": source_url,
            }
        )
        if attack_id is not UNSET:
            field_dict["attack_id"] = attack_id
        if bluf is not UNSET:
            field_dict["bluf"] = bluf
        if dataset_version is not UNSET:
            field_dict["dataset_version"] = dataset_version
        if source is not UNSET:
            field_dict["source"] = source
        if status is not UNSET:
            field_dict["status"] = status
        if tactics is not UNSET:
            field_dict["tactics"] = tactics

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        id = d.pop("id")

        name = d.pop("name")

        source_url = d.pop("source_url")

        def _parse_attack_id(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        attack_id = _parse_attack_id(d.pop("attack_id", UNSET))

        bluf = d.pop("bluf", UNSET)

        def _parse_dataset_version(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        dataset_version = _parse_dataset_version(d.pop("dataset_version", UNSET))

        source = d.pop("source", UNSET)

        status = d.pop("status", UNSET)

        tactics = cast(list[str], d.pop("tactics", UNSET))

        fight_technique = cls(
            id=id,
            name=name,
            source_url=source_url,
            attack_id=attack_id,
            bluf=bluf,
            dataset_version=dataset_version,
            source=source,
            status=status,
            tactics=tactics,
        )

        fight_technique.additional_properties = d
        return fight_technique

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

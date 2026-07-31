from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, BinaryIO, Generator, TextIO, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="ThreatPrediction")


@_attrs_define
class ThreatPrediction:
    """Threat prediction - estimated probability that a technique will be employed.

    Attributes:
        probability (float): Predicted likelihood of technique usage (0.0-1.0)
        technique_id (str): ATT&CK technique ID
        name (None | str | Unset): Technique name
        rank (int | None | Unset): 1-indexed position in descending-probability order returned by the TIE model
        tactics (list[str] | Unset): Tactics associated with this technique
    """

    probability: float
    technique_id: str
    name: None | str | Unset = UNSET
    rank: int | None | Unset = UNSET
    tactics: list[str] | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        probability = self.probability

        technique_id = self.technique_id

        name: None | str | Unset
        if isinstance(self.name, Unset):
            name = UNSET
        else:
            name = self.name

        rank: int | None | Unset
        if isinstance(self.rank, Unset):
            rank = UNSET
        else:
            rank = self.rank

        tactics: list[str] | Unset = UNSET
        if not isinstance(self.tactics, Unset):
            tactics = self.tactics

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "probability": probability,
                "technique_id": technique_id,
            }
        )
        if name is not UNSET:
            field_dict["name"] = name
        if rank is not UNSET:
            field_dict["rank"] = rank
        if tactics is not UNSET:
            field_dict["tactics"] = tactics

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        probability = d.pop("probability")

        technique_id = d.pop("technique_id")

        def _parse_name(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        name = _parse_name(d.pop("name", UNSET))

        def _parse_rank(data: object) -> int | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(int | None | Unset, data)

        rank = _parse_rank(d.pop("rank", UNSET))

        tactics = cast(list[str], d.pop("tactics", UNSET))

        threat_prediction = cls(
            probability=probability,
            technique_id=technique_id,
            name=name,
            rank=rank,
            tactics=tactics,
        )

        threat_prediction.additional_properties = d
        return threat_prediction

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

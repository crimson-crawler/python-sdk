from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, BinaryIO, Generator, TextIO, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.attack_path_technique_source import AttackPathTechniqueSource


T = TypeVar("T", bound="AttackPathStep")


@_attrs_define
class AttackPathStep:
    """One kill-chain phase in an attack path, with the techniques mapped to it.

    Attributes:
        phase (str): Kill-chain phase / tactic name
        tactic_order (int | None | Unset): Source phase order or ATT&CK Enterprise v19 matrix position when known
        technique_ids (list[str] | Unset): Techniques mapped to this phase
        technique_sources (list[AttackPathTechniqueSource] | Unset): Known evidence for techniques in this phase
    """

    phase: str
    tactic_order: int | None | Unset = UNSET
    technique_ids: list[str] | Unset = UNSET
    technique_sources: list[AttackPathTechniqueSource] | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        from ..models.attack_path_technique_source import AttackPathTechniqueSource  # noqa: PLC0415

        phase = self.phase

        tactic_order: int | None | Unset
        if isinstance(self.tactic_order, Unset):
            tactic_order = UNSET
        else:
            tactic_order = self.tactic_order

        technique_ids: list[str] | Unset = UNSET
        if not isinstance(self.technique_ids, Unset):
            technique_ids = self.technique_ids

        technique_sources: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.technique_sources, Unset):
            technique_sources = []
            for technique_sources_item_data in self.technique_sources:
                technique_sources_item = technique_sources_item_data.to_dict()
                technique_sources.append(technique_sources_item)

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "phase": phase,
            }
        )
        if tactic_order is not UNSET:
            field_dict["tactic_order"] = tactic_order
        if technique_ids is not UNSET:
            field_dict["technique_ids"] = technique_ids
        if technique_sources is not UNSET:
            field_dict["technique_sources"] = technique_sources

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.attack_path_technique_source import AttackPathTechniqueSource  # noqa: PLC0415

        d = dict(src_dict)
        phase = d.pop("phase")

        def _parse_tactic_order(data: object) -> int | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(int | None | Unset, data)

        tactic_order = _parse_tactic_order(d.pop("tactic_order", UNSET))

        technique_ids = cast(list[str], d.pop("technique_ids", UNSET))

        _technique_sources = d.pop("technique_sources", UNSET)
        technique_sources: list[AttackPathTechniqueSource] | Unset = UNSET
        if _technique_sources is not UNSET:
            technique_sources = []
            for technique_sources_item_data in _technique_sources:
                technique_sources_item = AttackPathTechniqueSource.from_dict(technique_sources_item_data)

                technique_sources.append(technique_sources_item)

        attack_path_step = cls(
            phase=phase,
            tactic_order=tactic_order,
            technique_ids=technique_ids,
            technique_sources=technique_sources,
        )

        attack_path_step.additional_properties = d
        return attack_path_step

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

from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, BinaryIO, Generator, TextIO, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.attack_path_step import AttackPathStep


T = TypeVar("T", bound="AttackPath")


@_attrs_define
class AttackPath:
    """Kill-chain-ordered technique sequence for a reference or the report.

    Attributes:
        reference (None | str | Unset): The reference this path was built for (None = report-wide)
        steps (list[AttackPathStep] | Unset): Phase-ordered steps
    """

    reference: None | str | Unset = UNSET
    steps: list[AttackPathStep] | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        from ..models.attack_path_step import AttackPathStep

        reference: None | str | Unset
        if isinstance(self.reference, Unset):
            reference = UNSET
        else:
            reference = self.reference

        steps: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.steps, Unset):
            steps = []
            for steps_item_data in self.steps:
                steps_item = steps_item_data.to_dict()
                steps.append(steps_item)

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if reference is not UNSET:
            field_dict["reference"] = reference
        if steps is not UNSET:
            field_dict["steps"] = steps

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.attack_path_step import AttackPathStep

        d = dict(src_dict)

        def _parse_reference(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        reference = _parse_reference(d.pop("reference", UNSET))

        _steps = d.pop("steps", UNSET)
        steps: list[AttackPathStep] | Unset = UNSET
        if _steps is not UNSET:
            steps = []
            for steps_item_data in _steps:
                steps_item = AttackPathStep.from_dict(steps_item_data)

                steps.append(steps_item)

        attack_path = cls(
            reference=reference,
            steps=steps,
        )

        attack_path.additional_properties = d
        return attack_path

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

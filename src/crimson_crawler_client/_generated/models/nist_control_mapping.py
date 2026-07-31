from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, BinaryIO, Generator, Literal, TextIO, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="NistControlMapping")


@_attrs_define
class NistControlMapping:
    """One NIST SP 800-53 rev 5 control mapped to an ATT&CK technique.

    Returned when `nist_controls` is included. Each mapping identifies the control, its family,
    the ATT&CK technique it covers, and the MITRE Center for Threat-Informed Defense rationale.

        Attributes:
            control_id (str): NIST 800-53 rev 5 control id (e.g. 'AC-02')
            control_name (str): Control name (e.g. 'Account Management')
            via_technique (str): ATT&CK technique that sourced this mapping (e.g. 'T1556.009'). When the same control is
                reached via multiple techniques the entry is repeated once per source technique.
            control_family (str | Unset): Two-letter NIST control family abbreviation (e.g. 'AC' for Access Control)
                Default: ''.
            mapping_type (Literal['mitigates'] | Unset): Relationship kind. MITRE CTID currently only emits 'mitigates'.
                Default: 'mitigates'.
            rationale (None | str | Unset): MITRE CTID's comments paragraph explaining why this control mitigates the
                technique. Pass-through, never paraphrased or summarised.
    """

    control_id: str
    control_name: str
    via_technique: str
    control_family: str | Unset = ""
    mapping_type: Literal["mitigates"] | Unset = "mitigates"
    rationale: None | str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        control_id = self.control_id

        control_name = self.control_name

        via_technique = self.via_technique

        control_family = self.control_family

        mapping_type = self.mapping_type

        rationale: None | str | Unset
        if isinstance(self.rationale, Unset):
            rationale = UNSET
        else:
            rationale = self.rationale

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "control_id": control_id,
                "control_name": control_name,
                "via_technique": via_technique,
            }
        )
        if control_family is not UNSET:
            field_dict["control_family"] = control_family
        if mapping_type is not UNSET:
            field_dict["mapping_type"] = mapping_type
        if rationale is not UNSET:
            field_dict["rationale"] = rationale

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        control_id = d.pop("control_id")

        control_name = d.pop("control_name")

        via_technique = d.pop("via_technique")

        control_family = d.pop("control_family", UNSET)

        mapping_type = cast(Literal["mitigates"] | Unset, d.pop("mapping_type", UNSET))
        if mapping_type != "mitigates" and not isinstance(mapping_type, Unset):
            raise ValueError(f"mapping_type must match const 'mitigates', got '{mapping_type}'")

        def _parse_rationale(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        rationale = _parse_rationale(d.pop("rationale", UNSET))

        nist_control_mapping = cls(
            control_id=control_id,
            control_name=control_name,
            via_technique=via_technique,
            control_family=control_family,
            mapping_type=mapping_type,
            rationale=rationale,
        )

        nist_control_mapping.additional_properties = d
        return nist_control_mapping

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

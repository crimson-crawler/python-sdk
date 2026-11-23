from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, BinaryIO, Generator, TextIO, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.iec62443_requirement import IEC62443Requirement


T = TypeVar("T", bound="IEC62443Summary")


@_attrs_define
class IEC62443Summary:
    """The ISA/IEC 62443 requirements a CVE's weaknesses are mapped to.

    Attributes:
        cwe_ids (list[str] | Unset): The CVE weaknesses that carry a 62443 mapping
        requirements (list[IEC62443Requirement] | Unset): One row per (part, requirement), listing the mapped CWEs
    """

    cwe_ids: list[str] | Unset = UNSET
    requirements: list[IEC62443Requirement] | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        from ..models.iec62443_requirement import IEC62443Requirement  # noqa: PLC0415

        cwe_ids: list[str] | Unset = UNSET
        if not isinstance(self.cwe_ids, Unset):
            cwe_ids = self.cwe_ids

        requirements: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.requirements, Unset):
            requirements = []
            for requirements_item_data in self.requirements:
                requirements_item = requirements_item_data.to_dict()
                requirements.append(requirements_item)

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if cwe_ids is not UNSET:
            field_dict["cwe_ids"] = cwe_ids
        if requirements is not UNSET:
            field_dict["requirements"] = requirements

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.iec62443_requirement import IEC62443Requirement  # noqa: PLC0415

        d = dict(src_dict)
        cwe_ids = cast(list[str], d.pop("cwe_ids", UNSET))

        _requirements = d.pop("requirements", UNSET)
        requirements: list[IEC62443Requirement] | Unset = UNSET
        if _requirements is not UNSET:
            requirements = []
            for requirements_item_data in _requirements:
                requirements_item = IEC62443Requirement.from_dict(requirements_item_data)

                requirements.append(requirements_item)

        iec62443_summary = cls(
            cwe_ids=cwe_ids,
            requirements=requirements,
        )

        iec62443_summary.additional_properties = d
        return iec62443_summary

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

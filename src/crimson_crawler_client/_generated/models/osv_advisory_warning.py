from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, BinaryIO, Generator, TextIO, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..models.osv_advisory_warning_rule import OSVAdvisoryWarningRule
from ..types import UNSET, Unset

T = TypeVar("T", bound="OSVAdvisoryWarning")


@_attrs_define
class OSVAdvisoryWarning:
    """A source-field problem attached to the advisory that caused it.

    Attributes:
        field (str): Source field path, or * for an oversized projection
        rule (OSVAdvisoryWarningRule): Curation rule that fired
    """

    field: str
    rule: OSVAdvisoryWarningRule
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        field = self.field

        rule = self.rule.value

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "field": field,
                "rule": rule,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        field = d.pop("field")

        rule = OSVAdvisoryWarningRule(d.pop("rule"))

        osv_advisory_warning = cls(
            field=field,
            rule=rule,
        )

        osv_advisory_warning.additional_properties = d
        return osv_advisory_warning

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

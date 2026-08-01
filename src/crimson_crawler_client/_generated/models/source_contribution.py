from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, BinaryIO, Generator, TextIO, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="SourceContribution")


@_attrs_define
class SourceContribution:
    """How much one intelligence source contributed to the report.

    Attributes:
        source (str): Source name (kev, epss, cisa-kev, attack, misp, poc, d3fend, web, knowledgebase, …)
        references_touched (int | Unset): References this source produced a signal for Default: 0.
    """

    source: str
    references_touched: int | Unset = 0
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        source = self.source

        references_touched = self.references_touched

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "source": source,
            }
        )
        if references_touched is not UNSET:
            field_dict["references_touched"] = references_touched

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        source = d.pop("source")

        references_touched = d.pop("references_touched", UNSET)

        source_contribution = cls(
            source=source,
            references_touched=references_touched,
        )

        source_contribution.additional_properties = d
        return source_contribution

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

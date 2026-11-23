from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, BinaryIO, Generator, TextIO, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="SimilarCVEMiniSignalBreakdown")


@_attrs_define
class SimilarCVEMiniSignalBreakdown:
    """Per-signal contribution to `similarity_score`: `jaccard_technique` (×0.50), `jaccard_cwe` (×0.30), `jaccard_capec`
    (materialised from tactic overlap, ×0.20), `cpe_overlap` (+0.15 when a vendor:product matches) and `cvss_distance`
    (≤+0.10, from the AV/AC/PR/UI Hamming similarity)

    """

    additional_properties: dict[str, float] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        similar_cve_mini_signal_breakdown = cls()

        similar_cve_mini_signal_breakdown.additional_properties = d
        return similar_cve_mini_signal_breakdown

    @property
    def additional_keys(self) -> list[str]:
        return list(self.additional_properties.keys())

    def __getitem__(self, key: str) -> float:
        return self.additional_properties[key]

    def __setitem__(self, key: str, value: float) -> None:
        self.additional_properties[key] = value

    def __delitem__(self, key: str) -> None:
        del self.additional_properties[key]

    def __contains__(self, key: str) -> bool:
        return key in self.additional_properties

from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, BinaryIO, Generator, TextIO, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.kbcve_ranking_by_year_item import KBCVERankingByYearItem


T = TypeVar("T", bound="KBCVERanking")


@_attrs_define
class KBCVERanking:
    """One knowledge-base object ranked by how many CVEs link to it — the corpus's prioritisation view.

    Attributes:
        by_year (list[KBCVERankingByYearItem] | Unset): The object's CVE-volume trend, in the corpus's own order ({year,
            cve_count})
        kb (str | Unset): Which knowledge base the row ranks: cwe, capec, or attack Default: ''.
        object_id (str | Unset): The object's own catalogue id (e.g. 'CWE-79', 'CAPEC-209', 'T1562.003') Default: ''.
        total_cve_count (int | Unset): How many CVEs link to this object Default: 0.
    """

    by_year: list[KBCVERankingByYearItem] | Unset = UNSET
    kb: str | Unset = ""
    object_id: str | Unset = ""
    total_cve_count: int | Unset = 0
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        from ..models.kbcve_ranking_by_year_item import KBCVERankingByYearItem  # noqa: PLC0415

        by_year: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.by_year, Unset):
            by_year = []
            for by_year_item_data in self.by_year:
                by_year_item = by_year_item_data.to_dict()
                by_year.append(by_year_item)

        kb = self.kb

        object_id = self.object_id

        total_cve_count = self.total_cve_count

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if by_year is not UNSET:
            field_dict["by_year"] = by_year
        if kb is not UNSET:
            field_dict["kb"] = kb
        if object_id is not UNSET:
            field_dict["object_id"] = object_id
        if total_cve_count is not UNSET:
            field_dict["total_cve_count"] = total_cve_count

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.kbcve_ranking_by_year_item import KBCVERankingByYearItem  # noqa: PLC0415

        d = dict(src_dict)
        _by_year = d.pop("by_year", UNSET)
        by_year: list[KBCVERankingByYearItem] | Unset = UNSET
        if _by_year is not UNSET:
            by_year = []
            for by_year_item_data in _by_year:
                by_year_item = KBCVERankingByYearItem.from_dict(by_year_item_data)

                by_year.append(by_year_item)

        kb = d.pop("kb", UNSET)

        object_id = d.pop("object_id", UNSET)

        total_cve_count = d.pop("total_cve_count", UNSET)

        kbcve_ranking = cls(
            by_year=by_year,
            kb=kb,
            object_id=object_id,
            total_cve_count=total_cve_count,
        )

        kbcve_ranking.additional_properties = d
        return kbcve_ranking

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

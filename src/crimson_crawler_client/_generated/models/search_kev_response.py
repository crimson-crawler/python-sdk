from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, BinaryIO, Generator, TextIO, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.corpus_statistics import CorpusStatistics
    from ..models.error_detail import ErrorDetail
    from ..models.kev_entry import KEVEntry


T = TypeVar("T", bound="SearchKEVResponse")


@_attrs_define
class SearchKEVResponse:
    """Known Exploited Vulnerabilities catalog search results.

    Attributes:
        errors (list[ErrorDetail] | Unset): Partial failure details
        results (list[KEVEntry] | Unset): Matching KEV entries
        statistics (CorpusStatistics | None | Unset): Deployment-wide corpus coverage and freshness. Included by
            default; an explicit include list replaces the defaults, and include=[] omits it. Same block `/v1/search/cve`
            returns, including `kev_by_year` and `kev_created_since`.
    """

    errors: list[ErrorDetail] | Unset = UNSET
    results: list[KEVEntry] | Unset = UNSET
    statistics: CorpusStatistics | None | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        from ..models.corpus_statistics import CorpusStatistics  # noqa: PLC0415
        from ..models.error_detail import ErrorDetail  # noqa: PLC0415
        from ..models.kev_entry import KEVEntry  # noqa: PLC0415

        errors: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.errors, Unset):
            errors = []
            for errors_item_data in self.errors:
                errors_item = errors_item_data.to_dict()
                errors.append(errors_item)

        results: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.results, Unset):
            results = []
            for results_item_data in self.results:
                results_item = results_item_data.to_dict()
                results.append(results_item)

        statistics: dict[str, Any] | None | Unset
        if isinstance(self.statistics, Unset):
            statistics = UNSET
        elif isinstance(self.statistics, CorpusStatistics):
            statistics = self.statistics.to_dict()
        else:
            statistics = self.statistics

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if errors is not UNSET:
            field_dict["errors"] = errors
        if results is not UNSET:
            field_dict["results"] = results
        if statistics is not UNSET:
            field_dict["statistics"] = statistics

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.corpus_statistics import CorpusStatistics  # noqa: PLC0415
        from ..models.error_detail import ErrorDetail  # noqa: PLC0415
        from ..models.kev_entry import KEVEntry  # noqa: PLC0415

        d = dict(src_dict)
        _errors = d.pop("errors", UNSET)
        errors: list[ErrorDetail] | Unset = UNSET
        if _errors is not UNSET:
            errors = []
            for errors_item_data in _errors:
                errors_item = ErrorDetail.from_dict(errors_item_data)

                errors.append(errors_item)

        _results = d.pop("results", UNSET)
        results: list[KEVEntry] | Unset = UNSET
        if _results is not UNSET:
            results = []
            for results_item_data in _results:
                results_item = KEVEntry.from_dict(results_item_data)

                results.append(results_item)

        def _parse_statistics(data: object) -> CorpusStatistics | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, dict):
                    raise TypeError()
                statistics_type_0 = CorpusStatistics.from_dict(data)

                return statistics_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(CorpusStatistics | None | Unset, data)

        statistics = _parse_statistics(d.pop("statistics", UNSET))

        search_kev_response = cls(
            errors=errors,
            results=results,
            statistics=statistics,
        )

        search_kev_response.additional_properties = d
        return search_kev_response

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

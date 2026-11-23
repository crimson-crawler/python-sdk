from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, BinaryIO, Generator, TextIO, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.cna_identity import CNAIdentity
    from ..models.corpus_statistics import CorpusStatistics
    from ..models.cve_detail import CVEDetail
    from ..models.epss_score import EPSSScore
    from ..models.error_detail import ErrorDetail
    from ..models.kbcve_ranking import KBCVERanking


T = TypeVar("T", bound="SearchCVEResponse")


@_attrs_define
class SearchCVEResponse:
    """Vulnerability search results.

    Attributes:
        cnas (list[CNAIdentity] | Unset): CNA directory — only when 'cna' is in include (up to `limit` rows)
        epss_reports (list[EPSSScore] | Unset): EPSS scores for the CVEs THIS search returned, newest EPSS report first
            — the listing half of the corpus-wide EPSS model, resolved for exactly the ids in `results` and never for a
            different set. Only when 'epss_reports' is in include.
        epss_reports_page (int | None | Unset): Source page number the `epss_reports` rows came from
        epss_reports_page_size (int | None | Unset): Source page size the `epss_reports` rows came from
        epss_reports_total (int | None | Unset): True number of EPSS records the source holds for the returned ids — the
            SOURCE's own total, so `epss_reports` can legitimately be shorter (a report with no EPSS series contributes no
            row).
        errors (list[ErrorDetail] | Unset): Partial failure details
        kb_rankings (list[KBCVERanking] | Unset): Per-knowledge-base CVE-volume rankings (cwe, capec, attack), each in
            its corpus's own order. The summary keeps up to 100 rows per knowledge base without per-year trends; request
            'kb_rankings_full' to restore all rows and trends.
        kb_rankings_total (int | Unset): Number of ranking rows returned by the available sources before summarization
            Default: 0.
        kb_rankings_truncated (bool | Unset): True when at least one ranking row or per-year trend was omitted Default:
            False.
        results (list[CVEDetail] | Unset): Matching CVE entries
        statistics (CorpusStatistics | None | Unset): Corpus coverage and freshness — only when 'statistics' is in
            include
    """

    cnas: list[CNAIdentity] | Unset = UNSET
    epss_reports: list[EPSSScore] | Unset = UNSET
    epss_reports_page: int | None | Unset = UNSET
    epss_reports_page_size: int | None | Unset = UNSET
    epss_reports_total: int | None | Unset = UNSET
    errors: list[ErrorDetail] | Unset = UNSET
    kb_rankings: list[KBCVERanking] | Unset = UNSET
    kb_rankings_total: int | Unset = 0
    kb_rankings_truncated: bool | Unset = False
    results: list[CVEDetail] | Unset = UNSET
    statistics: CorpusStatistics | None | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        from ..models.cna_identity import CNAIdentity  # noqa: PLC0415
        from ..models.corpus_statistics import CorpusStatistics  # noqa: PLC0415
        from ..models.cve_detail import CVEDetail  # noqa: PLC0415
        from ..models.epss_score import EPSSScore  # noqa: PLC0415
        from ..models.error_detail import ErrorDetail  # noqa: PLC0415
        from ..models.kbcve_ranking import KBCVERanking  # noqa: PLC0415

        cnas: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.cnas, Unset):
            cnas = []
            for cnas_item_data in self.cnas:
                cnas_item = cnas_item_data.to_dict()
                cnas.append(cnas_item)

        epss_reports: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.epss_reports, Unset):
            epss_reports = []
            for epss_reports_item_data in self.epss_reports:
                epss_reports_item = epss_reports_item_data.to_dict()
                epss_reports.append(epss_reports_item)

        epss_reports_page: int | None | Unset
        if isinstance(self.epss_reports_page, Unset):
            epss_reports_page = UNSET
        else:
            epss_reports_page = self.epss_reports_page

        epss_reports_page_size: int | None | Unset
        if isinstance(self.epss_reports_page_size, Unset):
            epss_reports_page_size = UNSET
        else:
            epss_reports_page_size = self.epss_reports_page_size

        epss_reports_total: int | None | Unset
        if isinstance(self.epss_reports_total, Unset):
            epss_reports_total = UNSET
        else:
            epss_reports_total = self.epss_reports_total

        errors: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.errors, Unset):
            errors = []
            for errors_item_data in self.errors:
                errors_item = errors_item_data.to_dict()
                errors.append(errors_item)

        kb_rankings: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.kb_rankings, Unset):
            kb_rankings = []
            for kb_rankings_item_data in self.kb_rankings:
                kb_rankings_item = kb_rankings_item_data.to_dict()
                kb_rankings.append(kb_rankings_item)

        kb_rankings_total = self.kb_rankings_total

        kb_rankings_truncated = self.kb_rankings_truncated

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
        if cnas is not UNSET:
            field_dict["cnas"] = cnas
        if epss_reports is not UNSET:
            field_dict["epss_reports"] = epss_reports
        if epss_reports_page is not UNSET:
            field_dict["epss_reports_page"] = epss_reports_page
        if epss_reports_page_size is not UNSET:
            field_dict["epss_reports_page_size"] = epss_reports_page_size
        if epss_reports_total is not UNSET:
            field_dict["epss_reports_total"] = epss_reports_total
        if errors is not UNSET:
            field_dict["errors"] = errors
        if kb_rankings is not UNSET:
            field_dict["kb_rankings"] = kb_rankings
        if kb_rankings_total is not UNSET:
            field_dict["kb_rankings_total"] = kb_rankings_total
        if kb_rankings_truncated is not UNSET:
            field_dict["kb_rankings_truncated"] = kb_rankings_truncated
        if results is not UNSET:
            field_dict["results"] = results
        if statistics is not UNSET:
            field_dict["statistics"] = statistics

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.cna_identity import CNAIdentity  # noqa: PLC0415
        from ..models.corpus_statistics import CorpusStatistics  # noqa: PLC0415
        from ..models.cve_detail import CVEDetail  # noqa: PLC0415
        from ..models.epss_score import EPSSScore  # noqa: PLC0415
        from ..models.error_detail import ErrorDetail  # noqa: PLC0415
        from ..models.kbcve_ranking import KBCVERanking  # noqa: PLC0415

        d = dict(src_dict)
        _cnas = d.pop("cnas", UNSET)
        cnas: list[CNAIdentity] | Unset = UNSET
        if _cnas is not UNSET:
            cnas = []
            for cnas_item_data in _cnas:
                cnas_item = CNAIdentity.from_dict(cnas_item_data)

                cnas.append(cnas_item)

        _epss_reports = d.pop("epss_reports", UNSET)
        epss_reports: list[EPSSScore] | Unset = UNSET
        if _epss_reports is not UNSET:
            epss_reports = []
            for epss_reports_item_data in _epss_reports:
                epss_reports_item = EPSSScore.from_dict(epss_reports_item_data)

                epss_reports.append(epss_reports_item)

        def _parse_epss_reports_page(data: object) -> int | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(int | None | Unset, data)

        epss_reports_page = _parse_epss_reports_page(d.pop("epss_reports_page", UNSET))

        def _parse_epss_reports_page_size(data: object) -> int | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(int | None | Unset, data)

        epss_reports_page_size = _parse_epss_reports_page_size(d.pop("epss_reports_page_size", UNSET))

        def _parse_epss_reports_total(data: object) -> int | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(int | None | Unset, data)

        epss_reports_total = _parse_epss_reports_total(d.pop("epss_reports_total", UNSET))

        _errors = d.pop("errors", UNSET)
        errors: list[ErrorDetail] | Unset = UNSET
        if _errors is not UNSET:
            errors = []
            for errors_item_data in _errors:
                errors_item = ErrorDetail.from_dict(errors_item_data)

                errors.append(errors_item)

        _kb_rankings = d.pop("kb_rankings", UNSET)
        kb_rankings: list[KBCVERanking] | Unset = UNSET
        if _kb_rankings is not UNSET:
            kb_rankings = []
            for kb_rankings_item_data in _kb_rankings:
                kb_rankings_item = KBCVERanking.from_dict(kb_rankings_item_data)

                kb_rankings.append(kb_rankings_item)

        kb_rankings_total = d.pop("kb_rankings_total", UNSET)

        kb_rankings_truncated = d.pop("kb_rankings_truncated", UNSET)

        _results = d.pop("results", UNSET)
        results: list[CVEDetail] | Unset = UNSET
        if _results is not UNSET:
            results = []
            for results_item_data in _results:
                results_item = CVEDetail.from_dict(results_item_data)

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

        search_cve_response = cls(
            cnas=cnas,
            epss_reports=epss_reports,
            epss_reports_page=epss_reports_page,
            epss_reports_page_size=epss_reports_page_size,
            epss_reports_total=epss_reports_total,
            errors=errors,
            kb_rankings=kb_rankings,
            kb_rankings_total=kb_rankings_total,
            kb_rankings_truncated=kb_rankings_truncated,
            results=results,
            statistics=statistics,
        )

        search_cve_response.additional_properties = d
        return search_cve_response

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

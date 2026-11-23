from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, BinaryIO, Generator, TextIO, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.corpus_statistics_cve_by_year_item import CorpusStatisticsCveByYearItem
    from ..models.corpus_statistics_cvss_v2_distribution_item import CorpusStatisticsCvssV2DistributionItem
    from ..models.corpus_statistics_cvss_v3_distribution_item import CorpusStatisticsCvssV3DistributionItem
    from ..models.corpus_statistics_cvss_v4_distribution_item import CorpusStatisticsCvssV4DistributionItem
    from ..models.corpus_statistics_epss_score_distribution_item import CorpusStatisticsEpssScoreDistributionItem
    from ..models.corpus_statistics_kev_by_year_item import CorpusStatisticsKevByYearItem
    from ..models.statistics_delta import StatisticsDelta


T = TypeVar("T", bound="CorpusStatistics")


@_attrs_define
class CorpusStatistics:
    """Deployment-wide corpus coverage and freshness — what backs every search on this stack.

    Folded onto `/v1/search/cve` via include=['statistics'] rather than a new route: it answers
    "how much data is behind this search", a property of the search surface itself.

        Attributes:
            cve_by_year (list[CorpusStatisticsCveByYearItem] | Unset): CVE count per year ({year, count})
            cve_created_since (None | StatisticsDelta | Unset): CVEs created in each window
            cve_modified_since (None | StatisticsDelta | Unset): CVEs modified in each window
            cve_total_count (int | None | Unset): Total CVEs in the corpus
            cvss_v2_distribution (list[CorpusStatisticsCvssV2DistributionItem] | Unset): CVSS v2.0 score buckets
                ({range_group, count}) — NVD's own 0.1-step buckets, labels passed through verbatim (NVD pads them: '0.9 -
                1.0'). Empty when that read failed
            cvss_v3_distribution (list[CorpusStatisticsCvssV3DistributionItem] | Unset): CVSS v3.x score buckets
                ({range_group, count}) — same shape as `cvss_v2_distribution`
            cvss_v4_distribution (list[CorpusStatisticsCvssV4DistributionItem] | Unset): CVSS v4.0 score buckets
                ({range_group, count}) — same shape as `cvss_v2_distribution`
            earliest_cve (None | str | Unset): Oldest CVE in the corpus
            earliest_cve_created_at (None | str | Unset): When that oldest CVE was created
            epss_score_distribution (list[CorpusStatisticsEpssScoreDistributionItem] | Unset): EPSS score buckets
                ({range_group, count}) — the corpus-wide probability spread
            generated_on (None | str | Unset): Date these counts were computed (ISO 8601 date)
            kev_by_year (list[CorpusStatisticsKevByYearItem] | Unset): KEV entry count per year ({year, count})
            kev_created_since (None | StatisticsDelta | Unset): KEV entries added in each window; null when the KEV
                statistics were unavailable
            latest_cve (None | str | Unset): Newest CVE in the corpus
            latest_cve_created_at (None | str | Unset): When that newest CVE was created
    """

    cve_by_year: list[CorpusStatisticsCveByYearItem] | Unset = UNSET
    cve_created_since: None | StatisticsDelta | Unset = UNSET
    cve_modified_since: None | StatisticsDelta | Unset = UNSET
    cve_total_count: int | None | Unset = UNSET
    cvss_v2_distribution: list[CorpusStatisticsCvssV2DistributionItem] | Unset = UNSET
    cvss_v3_distribution: list[CorpusStatisticsCvssV3DistributionItem] | Unset = UNSET
    cvss_v4_distribution: list[CorpusStatisticsCvssV4DistributionItem] | Unset = UNSET
    earliest_cve: None | str | Unset = UNSET
    earliest_cve_created_at: None | str | Unset = UNSET
    epss_score_distribution: list[CorpusStatisticsEpssScoreDistributionItem] | Unset = UNSET
    generated_on: None | str | Unset = UNSET
    kev_by_year: list[CorpusStatisticsKevByYearItem] | Unset = UNSET
    kev_created_since: None | StatisticsDelta | Unset = UNSET
    latest_cve: None | str | Unset = UNSET
    latest_cve_created_at: None | str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        from ..models.corpus_statistics_cve_by_year_item import CorpusStatisticsCveByYearItem  # noqa: PLC0415
        from ..models.corpus_statistics_cvss_v2_distribution_item import (
            CorpusStatisticsCvssV2DistributionItem,  # noqa: PLC0415
        )
        from ..models.corpus_statistics_cvss_v3_distribution_item import (
            CorpusStatisticsCvssV3DistributionItem,  # noqa: PLC0415
        )
        from ..models.corpus_statistics_cvss_v4_distribution_item import (
            CorpusStatisticsCvssV4DistributionItem,  # noqa: PLC0415
        )
        from ..models.corpus_statistics_epss_score_distribution_item import (
            CorpusStatisticsEpssScoreDistributionItem,  # noqa: PLC0415
        )
        from ..models.corpus_statistics_kev_by_year_item import CorpusStatisticsKevByYearItem  # noqa: PLC0415
        from ..models.statistics_delta import StatisticsDelta  # noqa: PLC0415

        cve_by_year: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.cve_by_year, Unset):
            cve_by_year = []
            for cve_by_year_item_data in self.cve_by_year:
                cve_by_year_item = cve_by_year_item_data.to_dict()
                cve_by_year.append(cve_by_year_item)

        cve_created_since: dict[str, Any] | None | Unset
        if isinstance(self.cve_created_since, Unset):
            cve_created_since = UNSET
        elif isinstance(self.cve_created_since, StatisticsDelta):
            cve_created_since = self.cve_created_since.to_dict()
        else:
            cve_created_since = self.cve_created_since

        cve_modified_since: dict[str, Any] | None | Unset
        if isinstance(self.cve_modified_since, Unset):
            cve_modified_since = UNSET
        elif isinstance(self.cve_modified_since, StatisticsDelta):
            cve_modified_since = self.cve_modified_since.to_dict()
        else:
            cve_modified_since = self.cve_modified_since

        cve_total_count: int | None | Unset
        if isinstance(self.cve_total_count, Unset):
            cve_total_count = UNSET
        else:
            cve_total_count = self.cve_total_count

        cvss_v2_distribution: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.cvss_v2_distribution, Unset):
            cvss_v2_distribution = []
            for cvss_v2_distribution_item_data in self.cvss_v2_distribution:
                cvss_v2_distribution_item = cvss_v2_distribution_item_data.to_dict()
                cvss_v2_distribution.append(cvss_v2_distribution_item)

        cvss_v3_distribution: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.cvss_v3_distribution, Unset):
            cvss_v3_distribution = []
            for cvss_v3_distribution_item_data in self.cvss_v3_distribution:
                cvss_v3_distribution_item = cvss_v3_distribution_item_data.to_dict()
                cvss_v3_distribution.append(cvss_v3_distribution_item)

        cvss_v4_distribution: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.cvss_v4_distribution, Unset):
            cvss_v4_distribution = []
            for cvss_v4_distribution_item_data in self.cvss_v4_distribution:
                cvss_v4_distribution_item = cvss_v4_distribution_item_data.to_dict()
                cvss_v4_distribution.append(cvss_v4_distribution_item)

        earliest_cve: None | str | Unset
        if isinstance(self.earliest_cve, Unset):
            earliest_cve = UNSET
        else:
            earliest_cve = self.earliest_cve

        earliest_cve_created_at: None | str | Unset
        if isinstance(self.earliest_cve_created_at, Unset):
            earliest_cve_created_at = UNSET
        else:
            earliest_cve_created_at = self.earliest_cve_created_at

        epss_score_distribution: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.epss_score_distribution, Unset):
            epss_score_distribution = []
            for epss_score_distribution_item_data in self.epss_score_distribution:
                epss_score_distribution_item = epss_score_distribution_item_data.to_dict()
                epss_score_distribution.append(epss_score_distribution_item)

        generated_on: None | str | Unset
        if isinstance(self.generated_on, Unset):
            generated_on = UNSET
        else:
            generated_on = self.generated_on

        kev_by_year: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.kev_by_year, Unset):
            kev_by_year = []
            for kev_by_year_item_data in self.kev_by_year:
                kev_by_year_item = kev_by_year_item_data.to_dict()
                kev_by_year.append(kev_by_year_item)

        kev_created_since: dict[str, Any] | None | Unset
        if isinstance(self.kev_created_since, Unset):
            kev_created_since = UNSET
        elif isinstance(self.kev_created_since, StatisticsDelta):
            kev_created_since = self.kev_created_since.to_dict()
        else:
            kev_created_since = self.kev_created_since

        latest_cve: None | str | Unset
        if isinstance(self.latest_cve, Unset):
            latest_cve = UNSET
        else:
            latest_cve = self.latest_cve

        latest_cve_created_at: None | str | Unset
        if isinstance(self.latest_cve_created_at, Unset):
            latest_cve_created_at = UNSET
        else:
            latest_cve_created_at = self.latest_cve_created_at

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if cve_by_year is not UNSET:
            field_dict["cve_by_year"] = cve_by_year
        if cve_created_since is not UNSET:
            field_dict["cve_created_since"] = cve_created_since
        if cve_modified_since is not UNSET:
            field_dict["cve_modified_since"] = cve_modified_since
        if cve_total_count is not UNSET:
            field_dict["cve_total_count"] = cve_total_count
        if cvss_v2_distribution is not UNSET:
            field_dict["cvss_v2_distribution"] = cvss_v2_distribution
        if cvss_v3_distribution is not UNSET:
            field_dict["cvss_v3_distribution"] = cvss_v3_distribution
        if cvss_v4_distribution is not UNSET:
            field_dict["cvss_v4_distribution"] = cvss_v4_distribution
        if earliest_cve is not UNSET:
            field_dict["earliest_cve"] = earliest_cve
        if earliest_cve_created_at is not UNSET:
            field_dict["earliest_cve_created_at"] = earliest_cve_created_at
        if epss_score_distribution is not UNSET:
            field_dict["epss_score_distribution"] = epss_score_distribution
        if generated_on is not UNSET:
            field_dict["generated_on"] = generated_on
        if kev_by_year is not UNSET:
            field_dict["kev_by_year"] = kev_by_year
        if kev_created_since is not UNSET:
            field_dict["kev_created_since"] = kev_created_since
        if latest_cve is not UNSET:
            field_dict["latest_cve"] = latest_cve
        if latest_cve_created_at is not UNSET:
            field_dict["latest_cve_created_at"] = latest_cve_created_at

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.corpus_statistics_cve_by_year_item import CorpusStatisticsCveByYearItem  # noqa: PLC0415
        from ..models.corpus_statistics_cvss_v2_distribution_item import (
            CorpusStatisticsCvssV2DistributionItem,  # noqa: PLC0415
        )
        from ..models.corpus_statistics_cvss_v3_distribution_item import (
            CorpusStatisticsCvssV3DistributionItem,  # noqa: PLC0415
        )
        from ..models.corpus_statistics_cvss_v4_distribution_item import (
            CorpusStatisticsCvssV4DistributionItem,  # noqa: PLC0415
        )
        from ..models.corpus_statistics_epss_score_distribution_item import (
            CorpusStatisticsEpssScoreDistributionItem,  # noqa: PLC0415
        )
        from ..models.corpus_statistics_kev_by_year_item import CorpusStatisticsKevByYearItem  # noqa: PLC0415
        from ..models.statistics_delta import StatisticsDelta  # noqa: PLC0415

        d = dict(src_dict)
        _cve_by_year = d.pop("cve_by_year", UNSET)
        cve_by_year: list[CorpusStatisticsCveByYearItem] | Unset = UNSET
        if _cve_by_year is not UNSET:
            cve_by_year = []
            for cve_by_year_item_data in _cve_by_year:
                cve_by_year_item = CorpusStatisticsCveByYearItem.from_dict(cve_by_year_item_data)

                cve_by_year.append(cve_by_year_item)

        def _parse_cve_created_since(data: object) -> None | StatisticsDelta | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, dict):
                    raise TypeError()
                cve_created_since_type_0 = StatisticsDelta.from_dict(data)

                return cve_created_since_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(None | StatisticsDelta | Unset, data)

        cve_created_since = _parse_cve_created_since(d.pop("cve_created_since", UNSET))

        def _parse_cve_modified_since(data: object) -> None | StatisticsDelta | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, dict):
                    raise TypeError()
                cve_modified_since_type_0 = StatisticsDelta.from_dict(data)

                return cve_modified_since_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(None | StatisticsDelta | Unset, data)

        cve_modified_since = _parse_cve_modified_since(d.pop("cve_modified_since", UNSET))

        def _parse_cve_total_count(data: object) -> int | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(int | None | Unset, data)

        cve_total_count = _parse_cve_total_count(d.pop("cve_total_count", UNSET))

        _cvss_v2_distribution = d.pop("cvss_v2_distribution", UNSET)
        cvss_v2_distribution: list[CorpusStatisticsCvssV2DistributionItem] | Unset = UNSET
        if _cvss_v2_distribution is not UNSET:
            cvss_v2_distribution = []
            for cvss_v2_distribution_item_data in _cvss_v2_distribution:
                cvss_v2_distribution_item = CorpusStatisticsCvssV2DistributionItem.from_dict(
                    cvss_v2_distribution_item_data
                )

                cvss_v2_distribution.append(cvss_v2_distribution_item)

        _cvss_v3_distribution = d.pop("cvss_v3_distribution", UNSET)
        cvss_v3_distribution: list[CorpusStatisticsCvssV3DistributionItem] | Unset = UNSET
        if _cvss_v3_distribution is not UNSET:
            cvss_v3_distribution = []
            for cvss_v3_distribution_item_data in _cvss_v3_distribution:
                cvss_v3_distribution_item = CorpusStatisticsCvssV3DistributionItem.from_dict(
                    cvss_v3_distribution_item_data
                )

                cvss_v3_distribution.append(cvss_v3_distribution_item)

        _cvss_v4_distribution = d.pop("cvss_v4_distribution", UNSET)
        cvss_v4_distribution: list[CorpusStatisticsCvssV4DistributionItem] | Unset = UNSET
        if _cvss_v4_distribution is not UNSET:
            cvss_v4_distribution = []
            for cvss_v4_distribution_item_data in _cvss_v4_distribution:
                cvss_v4_distribution_item = CorpusStatisticsCvssV4DistributionItem.from_dict(
                    cvss_v4_distribution_item_data
                )

                cvss_v4_distribution.append(cvss_v4_distribution_item)

        def _parse_earliest_cve(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        earliest_cve = _parse_earliest_cve(d.pop("earliest_cve", UNSET))

        def _parse_earliest_cve_created_at(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        earliest_cve_created_at = _parse_earliest_cve_created_at(d.pop("earliest_cve_created_at", UNSET))

        _epss_score_distribution = d.pop("epss_score_distribution", UNSET)
        epss_score_distribution: list[CorpusStatisticsEpssScoreDistributionItem] | Unset = UNSET
        if _epss_score_distribution is not UNSET:
            epss_score_distribution = []
            for epss_score_distribution_item_data in _epss_score_distribution:
                epss_score_distribution_item = CorpusStatisticsEpssScoreDistributionItem.from_dict(
                    epss_score_distribution_item_data
                )

                epss_score_distribution.append(epss_score_distribution_item)

        def _parse_generated_on(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        generated_on = _parse_generated_on(d.pop("generated_on", UNSET))

        _kev_by_year = d.pop("kev_by_year", UNSET)
        kev_by_year: list[CorpusStatisticsKevByYearItem] | Unset = UNSET
        if _kev_by_year is not UNSET:
            kev_by_year = []
            for kev_by_year_item_data in _kev_by_year:
                kev_by_year_item = CorpusStatisticsKevByYearItem.from_dict(kev_by_year_item_data)

                kev_by_year.append(kev_by_year_item)

        def _parse_kev_created_since(data: object) -> None | StatisticsDelta | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, dict):
                    raise TypeError()
                kev_created_since_type_0 = StatisticsDelta.from_dict(data)

                return kev_created_since_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(None | StatisticsDelta | Unset, data)

        kev_created_since = _parse_kev_created_since(d.pop("kev_created_since", UNSET))

        def _parse_latest_cve(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        latest_cve = _parse_latest_cve(d.pop("latest_cve", UNSET))

        def _parse_latest_cve_created_at(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        latest_cve_created_at = _parse_latest_cve_created_at(d.pop("latest_cve_created_at", UNSET))

        corpus_statistics = cls(
            cve_by_year=cve_by_year,
            cve_created_since=cve_created_since,
            cve_modified_since=cve_modified_since,
            cve_total_count=cve_total_count,
            cvss_v2_distribution=cvss_v2_distribution,
            cvss_v3_distribution=cvss_v3_distribution,
            cvss_v4_distribution=cvss_v4_distribution,
            earliest_cve=earliest_cve,
            earliest_cve_created_at=earliest_cve_created_at,
            epss_score_distribution=epss_score_distribution,
            generated_on=generated_on,
            kev_by_year=kev_by_year,
            kev_created_since=kev_created_since,
            latest_cve=latest_cve,
            latest_cve_created_at=latest_cve_created_at,
        )

        corpus_statistics.additional_properties = d
        return corpus_statistics

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

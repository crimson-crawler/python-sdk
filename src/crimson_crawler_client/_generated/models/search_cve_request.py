from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, BinaryIO, Generator, TextIO, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..models.search_cve_request_sort_type_0 import SearchCVERequestSortType0
from ..models.search_cve_request_vuln_status_type_0 import SearchCVERequestVulnStatusType0
from ..types import UNSET, Unset

T = TypeVar("T", bound="SearchCVERequest")


@_attrs_define
class SearchCVERequest:
    """Search vulnerabilities by severity, exploit status, technique, weakness, date range, and more.

    Attributes:
        attack_id (None | str | Unset): Filter CVEs linked to an ATT&CK technique (e.g. T1190)
        capec_id (None | str | Unset): Filter CVEs linked to a CAPEC attack pattern (e.g. CAPEC-665)
        cpe (None | str | Unset): Filter CVEs by affected product (CPE string)
        cpes_not_vulnerable (None | str | Unset): Exclude CVEs whose configuration requires (but is not vulnerable in)
            this CPE 2.3 string
        created_by_ref (None | str | Unset): Filter by CNA / numbering-authority identity STIX ID
        created_max (None | str | Unset): Latest creation date (YYYY-MM-DDThh:mm:ss.sssZ)
        created_min (None | str | Unset): Earliest creation date (YYYY-MM-DDThh:mm:ss.sssZ)
        cve_id (None | str | Unset): Direct CVE ID lookup
        cvss_min (float | None | Unset): Minimum CVSS v3.1 base score (0.0-10.0)
        cvss_v2_min (float | None | Unset): Minimum CVSS v2 base score (0.0-10.0)
        cvss_v4_min (float | None | Unset): Minimum CVSS v4 base score (0.0-10.0)
        cwe_id (None | str | Unset): Filter CVEs by weakness type
        epss_min (float | None | Unset): Minimum EPSS score (0.0-1.0)
        epss_percentile_min (float | None | Unset): Minimum EPSS percentile (0.0-1.0) — rank vs all CVEs, not the raw
            score
        include (list[str] | Unset): Result layers to include. The only allowed value is `details`; an empty list
            returns summaries.
        kev_only (bool | Unset): Only return CVEs in the Known Exploited Vulnerabilities catalog Default: False.
        limit (int | Unset): Maximum number of results to return (1-100) Default: 50.
        modified_max (None | str | Unset): Latest modification date (YYYY-MM-DDThh:mm:ss.sssZ)
        modified_min (None | str | Unset): Earliest modification date (YYYY-MM-DDThh:mm:ss.sssZ)
        page (int | Unset): Page number for pagination (1-indexed, max 100) Default: 1.
        query (None | str | Unset): Compatibility field for a future description search. It does not currently filter
            results and is rejected unless another filter or a sort is supplied.
        sort (None | SearchCVERequestSortType0 | Unset): Sort order: created_ascending, created_descending,
            modified_ascending, modified_descending, epss_score_descending, x_opencti_cvss_base_score_descending
        stix_id (None | str | Unset): Filter by exact vulnerability STIX ID
        vuln_status (None | SearchCVERequestVulnStatusType0 | Unset): Filter by vulnerability status: Analyzed, Awaiting
            Analysis, Modified, Received, Rejected
    """

    attack_id: None | str | Unset = UNSET
    capec_id: None | str | Unset = UNSET
    cpe: None | str | Unset = UNSET
    cpes_not_vulnerable: None | str | Unset = UNSET
    created_by_ref: None | str | Unset = UNSET
    created_max: None | str | Unset = UNSET
    created_min: None | str | Unset = UNSET
    cve_id: None | str | Unset = UNSET
    cvss_min: float | None | Unset = UNSET
    cvss_v2_min: float | None | Unset = UNSET
    cvss_v4_min: float | None | Unset = UNSET
    cwe_id: None | str | Unset = UNSET
    epss_min: float | None | Unset = UNSET
    epss_percentile_min: float | None | Unset = UNSET
    include: list[str] | Unset = UNSET
    kev_only: bool | Unset = False
    limit: int | Unset = 50
    modified_max: None | str | Unset = UNSET
    modified_min: None | str | Unset = UNSET
    page: int | Unset = 1
    query: None | str | Unset = UNSET
    sort: None | SearchCVERequestSortType0 | Unset = UNSET
    stix_id: None | str | Unset = UNSET
    vuln_status: None | SearchCVERequestVulnStatusType0 | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        attack_id: None | str | Unset
        if isinstance(self.attack_id, Unset):
            attack_id = UNSET
        else:
            attack_id = self.attack_id

        capec_id: None | str | Unset
        if isinstance(self.capec_id, Unset):
            capec_id = UNSET
        else:
            capec_id = self.capec_id

        cpe: None | str | Unset
        if isinstance(self.cpe, Unset):
            cpe = UNSET
        else:
            cpe = self.cpe

        cpes_not_vulnerable: None | str | Unset
        if isinstance(self.cpes_not_vulnerable, Unset):
            cpes_not_vulnerable = UNSET
        else:
            cpes_not_vulnerable = self.cpes_not_vulnerable

        created_by_ref: None | str | Unset
        if isinstance(self.created_by_ref, Unset):
            created_by_ref = UNSET
        else:
            created_by_ref = self.created_by_ref

        created_max: None | str | Unset
        if isinstance(self.created_max, Unset):
            created_max = UNSET
        else:
            created_max = self.created_max

        created_min: None | str | Unset
        if isinstance(self.created_min, Unset):
            created_min = UNSET
        else:
            created_min = self.created_min

        cve_id: None | str | Unset
        if isinstance(self.cve_id, Unset):
            cve_id = UNSET
        else:
            cve_id = self.cve_id

        cvss_min: float | None | Unset
        if isinstance(self.cvss_min, Unset):
            cvss_min = UNSET
        else:
            cvss_min = self.cvss_min

        cvss_v2_min: float | None | Unset
        if isinstance(self.cvss_v2_min, Unset):
            cvss_v2_min = UNSET
        else:
            cvss_v2_min = self.cvss_v2_min

        cvss_v4_min: float | None | Unset
        if isinstance(self.cvss_v4_min, Unset):
            cvss_v4_min = UNSET
        else:
            cvss_v4_min = self.cvss_v4_min

        cwe_id: None | str | Unset
        if isinstance(self.cwe_id, Unset):
            cwe_id = UNSET
        else:
            cwe_id = self.cwe_id

        epss_min: float | None | Unset
        if isinstance(self.epss_min, Unset):
            epss_min = UNSET
        else:
            epss_min = self.epss_min

        epss_percentile_min: float | None | Unset
        if isinstance(self.epss_percentile_min, Unset):
            epss_percentile_min = UNSET
        else:
            epss_percentile_min = self.epss_percentile_min

        include: list[str] | Unset = UNSET
        if not isinstance(self.include, Unset):
            include = self.include

        kev_only = self.kev_only

        limit = self.limit

        modified_max: None | str | Unset
        if isinstance(self.modified_max, Unset):
            modified_max = UNSET
        else:
            modified_max = self.modified_max

        modified_min: None | str | Unset
        if isinstance(self.modified_min, Unset):
            modified_min = UNSET
        else:
            modified_min = self.modified_min

        page = self.page

        query: None | str | Unset
        if isinstance(self.query, Unset):
            query = UNSET
        else:
            query = self.query

        sort: None | str | Unset
        if isinstance(self.sort, Unset):
            sort = UNSET
        elif isinstance(self.sort, SearchCVERequestSortType0):
            sort = self.sort.value
        else:
            sort = self.sort

        stix_id: None | str | Unset
        if isinstance(self.stix_id, Unset):
            stix_id = UNSET
        else:
            stix_id = self.stix_id

        vuln_status: None | str | Unset
        if isinstance(self.vuln_status, Unset):
            vuln_status = UNSET
        elif isinstance(self.vuln_status, SearchCVERequestVulnStatusType0):
            vuln_status = self.vuln_status.value
        else:
            vuln_status = self.vuln_status

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if attack_id is not UNSET:
            field_dict["attack_id"] = attack_id
        if capec_id is not UNSET:
            field_dict["capec_id"] = capec_id
        if cpe is not UNSET:
            field_dict["cpe"] = cpe
        if cpes_not_vulnerable is not UNSET:
            field_dict["cpes_not_vulnerable"] = cpes_not_vulnerable
        if created_by_ref is not UNSET:
            field_dict["created_by_ref"] = created_by_ref
        if created_max is not UNSET:
            field_dict["created_max"] = created_max
        if created_min is not UNSET:
            field_dict["created_min"] = created_min
        if cve_id is not UNSET:
            field_dict["cve_id"] = cve_id
        if cvss_min is not UNSET:
            field_dict["cvss_min"] = cvss_min
        if cvss_v2_min is not UNSET:
            field_dict["cvss_v2_min"] = cvss_v2_min
        if cvss_v4_min is not UNSET:
            field_dict["cvss_v4_min"] = cvss_v4_min
        if cwe_id is not UNSET:
            field_dict["cwe_id"] = cwe_id
        if epss_min is not UNSET:
            field_dict["epss_min"] = epss_min
        if epss_percentile_min is not UNSET:
            field_dict["epss_percentile_min"] = epss_percentile_min
        if include is not UNSET:
            field_dict["include"] = include
        if kev_only is not UNSET:
            field_dict["kev_only"] = kev_only
        if limit is not UNSET:
            field_dict["limit"] = limit
        if modified_max is not UNSET:
            field_dict["modified_max"] = modified_max
        if modified_min is not UNSET:
            field_dict["modified_min"] = modified_min
        if page is not UNSET:
            field_dict["page"] = page
        if query is not UNSET:
            field_dict["query"] = query
        if sort is not UNSET:
            field_dict["sort"] = sort
        if stix_id is not UNSET:
            field_dict["stix_id"] = stix_id
        if vuln_status is not UNSET:
            field_dict["vuln_status"] = vuln_status

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)

        def _parse_attack_id(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        attack_id = _parse_attack_id(d.pop("attack_id", UNSET))

        def _parse_capec_id(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        capec_id = _parse_capec_id(d.pop("capec_id", UNSET))

        def _parse_cpe(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        cpe = _parse_cpe(d.pop("cpe", UNSET))

        def _parse_cpes_not_vulnerable(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        cpes_not_vulnerable = _parse_cpes_not_vulnerable(d.pop("cpes_not_vulnerable", UNSET))

        def _parse_created_by_ref(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        created_by_ref = _parse_created_by_ref(d.pop("created_by_ref", UNSET))

        def _parse_created_max(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        created_max = _parse_created_max(d.pop("created_max", UNSET))

        def _parse_created_min(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        created_min = _parse_created_min(d.pop("created_min", UNSET))

        def _parse_cve_id(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        cve_id = _parse_cve_id(d.pop("cve_id", UNSET))

        def _parse_cvss_min(data: object) -> float | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(float | None | Unset, data)

        cvss_min = _parse_cvss_min(d.pop("cvss_min", UNSET))

        def _parse_cvss_v2_min(data: object) -> float | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(float | None | Unset, data)

        cvss_v2_min = _parse_cvss_v2_min(d.pop("cvss_v2_min", UNSET))

        def _parse_cvss_v4_min(data: object) -> float | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(float | None | Unset, data)

        cvss_v4_min = _parse_cvss_v4_min(d.pop("cvss_v4_min", UNSET))

        def _parse_cwe_id(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        cwe_id = _parse_cwe_id(d.pop("cwe_id", UNSET))

        def _parse_epss_min(data: object) -> float | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(float | None | Unset, data)

        epss_min = _parse_epss_min(d.pop("epss_min", UNSET))

        def _parse_epss_percentile_min(data: object) -> float | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(float | None | Unset, data)

        epss_percentile_min = _parse_epss_percentile_min(d.pop("epss_percentile_min", UNSET))

        include = cast(list[str], d.pop("include", UNSET))

        kev_only = d.pop("kev_only", UNSET)

        limit = d.pop("limit", UNSET)

        def _parse_modified_max(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        modified_max = _parse_modified_max(d.pop("modified_max", UNSET))

        def _parse_modified_min(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        modified_min = _parse_modified_min(d.pop("modified_min", UNSET))

        page = d.pop("page", UNSET)

        def _parse_query(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        query = _parse_query(d.pop("query", UNSET))

        def _parse_sort(data: object) -> None | SearchCVERequestSortType0 | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, str):
                    raise TypeError()
                sort_type_0 = SearchCVERequestSortType0(data)

                return sort_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(None | SearchCVERequestSortType0 | Unset, data)

        sort = _parse_sort(d.pop("sort", UNSET))

        def _parse_stix_id(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        stix_id = _parse_stix_id(d.pop("stix_id", UNSET))

        def _parse_vuln_status(data: object) -> None | SearchCVERequestVulnStatusType0 | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, str):
                    raise TypeError()
                vuln_status_type_0 = SearchCVERequestVulnStatusType0(data)

                return vuln_status_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(None | SearchCVERequestVulnStatusType0 | Unset, data)

        vuln_status = _parse_vuln_status(d.pop("vuln_status", UNSET))

        search_cve_request = cls(
            attack_id=attack_id,
            capec_id=capec_id,
            cpe=cpe,
            cpes_not_vulnerable=cpes_not_vulnerable,
            created_by_ref=created_by_ref,
            created_max=created_max,
            created_min=created_min,
            cve_id=cve_id,
            cvss_min=cvss_min,
            cvss_v2_min=cvss_v2_min,
            cvss_v4_min=cvss_v4_min,
            cwe_id=cwe_id,
            epss_min=epss_min,
            epss_percentile_min=epss_percentile_min,
            include=include,
            kev_only=kev_only,
            limit=limit,
            modified_max=modified_max,
            modified_min=modified_min,
            page=page,
            query=query,
            sort=sort,
            stix_id=stix_id,
            vuln_status=vuln_status,
        )

        search_cve_request.additional_properties = d
        return search_cve_request

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

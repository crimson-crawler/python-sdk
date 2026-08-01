from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, BinaryIO, Generator, TextIO, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..models.search_kev_request_ransomware_status_type_0 import SearchKEVRequestRansomwareStatusType0
from ..types import UNSET, Unset

T = TypeVar("T", bound="SearchKEVRequest")


@_attrs_define
class SearchKEVRequest:
    """Search the Known Exploited Vulnerabilities catalog for actively exploited CVEs.

    Attributes:
        cve_id (None | str | Unset): CVE ID to check against the KEV catalog
        limit (int | Unset): Maximum number of results to return (1-100) Default: 50.
        page (int | Unset): Page number for pagination (1-indexed, max 100) Default: 1.
        ransomware_status (None | SearchKEVRequestRansomwareStatusType0 | Unset): Filter by ransomware campaign use:
            'Known' (confirmed) or 'Unknown' (unconfirmed)
    """

    cve_id: None | str | Unset = UNSET
    limit: int | Unset = 50
    page: int | Unset = 1
    ransomware_status: None | SearchKEVRequestRansomwareStatusType0 | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        cve_id: None | str | Unset
        if isinstance(self.cve_id, Unset):
            cve_id = UNSET
        else:
            cve_id = self.cve_id

        limit = self.limit

        page = self.page

        ransomware_status: None | str | Unset
        if isinstance(self.ransomware_status, Unset):
            ransomware_status = UNSET
        elif isinstance(self.ransomware_status, SearchKEVRequestRansomwareStatusType0):
            ransomware_status = self.ransomware_status.value
        else:
            ransomware_status = self.ransomware_status

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if cve_id is not UNSET:
            field_dict["cve_id"] = cve_id
        if limit is not UNSET:
            field_dict["limit"] = limit
        if page is not UNSET:
            field_dict["page"] = page
        if ransomware_status is not UNSET:
            field_dict["ransomware_status"] = ransomware_status

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)

        def _parse_cve_id(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        cve_id = _parse_cve_id(d.pop("cve_id", UNSET))

        limit = d.pop("limit", UNSET)

        page = d.pop("page", UNSET)

        def _parse_ransomware_status(data: object) -> None | SearchKEVRequestRansomwareStatusType0 | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, str):
                    raise TypeError()
                ransomware_status_type_0 = SearchKEVRequestRansomwareStatusType0(data)

                return ransomware_status_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(None | SearchKEVRequestRansomwareStatusType0 | Unset, data)

        ransomware_status = _parse_ransomware_status(d.pop("ransomware_status", UNSET))

        search_kev_request = cls(
            cve_id=cve_id,
            limit=limit,
            page=page,
            ransomware_status=ransomware_status,
        )

        search_kev_request.additional_properties = d
        return search_kev_request

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

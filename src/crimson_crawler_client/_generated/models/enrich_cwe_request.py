from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, BinaryIO, Generator, TextIO, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="EnrichCWERequest")


@_attrs_define
class EnrichCWERequest:
    """Enrich a weakness classification with linked attack patterns and their ATT&CK mappings.

    Techniques resolve from this weakness's CAPEC links, so the layer is only as complete as those
    links are: a CAPEC carrying no ATT&CK mapping contributes none, and the layers derived from
    techniques are empty with it. Some weaknesses carry no CAPECs at all.
    Supply at least one of `cwe_id` or `search`.

        Attributes:
            cwe_id (None | str | Unset): CWE identifier (e.g. CWE-79). Supply this or `search`.
            include (list[str] | Unset): Response layers to include. Replaces the default list. Allowed values: campaigns,
                capecs, cves, defend, details, detections, groups, knowledgebase, log_sources, mitigations, navigator,
                nist_controls, software, summary, techniques, tie, versions. `versions` attaches the object's KB revision
                history (`revision_history`). `details` does not gate this endpoint's own `weakness` object — it is returned
                whether or not the token is requested (the token still counts toward the include set `confidence` reports). The
                CAPEC rows behind the technique-derived layers resolve for those tokens themselves — `groups`, `software`,
                `campaigns`, `mitigations`, `detections`, `defend`, `navigator`, `nist_controls` and `tie` answer without
                `capecs` or `techniques` in the same request, and `capecs` / `techniques` are still what PUBLISH their own
                sections. `defend` reaches its countermeasures through the technique's ATT&CK mitigations — the corpus links
                D3FEND to mitigations, never directly to a technique — and reports `error: "no_mapping"` only where that join
                finds none.
            search (None | str | Unset): Text query to discover weaknesses by name or description (e.g. 'Cross-site
                Scripting') — the discovery path CWE was missing while CAPEC/F3/CLOAK all had one. Supply this or `cwe_id`.
    """

    cwe_id: None | str | Unset = UNSET
    include: list[str] | Unset = UNSET
    search: None | str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        cwe_id: None | str | Unset
        if isinstance(self.cwe_id, Unset):
            cwe_id = UNSET
        else:
            cwe_id = self.cwe_id

        include: list[str] | Unset = UNSET
        if not isinstance(self.include, Unset):
            include = self.include

        search: None | str | Unset
        if isinstance(self.search, Unset):
            search = UNSET
        else:
            search = self.search

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if cwe_id is not UNSET:
            field_dict["cwe_id"] = cwe_id
        if include is not UNSET:
            field_dict["include"] = include
        if search is not UNSET:
            field_dict["search"] = search

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)

        def _parse_cwe_id(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        cwe_id = _parse_cwe_id(d.pop("cwe_id", UNSET))

        include = cast(list[str], d.pop("include", UNSET))

        def _parse_search(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        search = _parse_search(d.pop("search", UNSET))

        enrich_cwe_request = cls(
            cwe_id=cwe_id,
            include=include,
            search=search,
        )

        enrich_cwe_request.additional_properties = d
        return enrich_cwe_request

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

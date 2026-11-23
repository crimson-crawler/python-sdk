from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, BinaryIO, Generator, TextIO, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.error_detail import ErrorDetail
    from ..models.kb_version import KBVersion
    from ..models.search_cti_response_results_item import SearchCTIResponseResultsItem


T = TypeVar("T", bound="SearchCTIResponse")


@_attrs_define
class SearchCTIResponse:
    """Cross-knowledge-base search results spanning ATT&CK, CWE, CAPEC, ATLAS, DISARM, F3, and CLOAK.

    Results are polymorphic: each object contains type-specific fields (technique_id, group_id,
    capec_id, cwe_id, etc.) plus a `_source` field identifying the knowledge base
    (e.g. "attack", "capec", "cwe", "atlas", "disarm", "f3", "cloak", "d3fend").

        Attributes:
            errors (list[ErrorDetail] | Unset): Partial failure details
            knowledgebase_versions (list[KBVersion] | Unset): Installed vs available revision for each requested source —
                opt-in via include=['kb_versions']. Read-only: it reports which KB revision answered, it does not upgrade
                anything.
            results (list[SearchCTIResponseResultsItem] | Unset): Matching objects from requested knowledge bases, each
                tagged with _source
    """

    errors: list[ErrorDetail] | Unset = UNSET
    knowledgebase_versions: list[KBVersion] | Unset = UNSET
    results: list[SearchCTIResponseResultsItem] | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        from ..models.error_detail import ErrorDetail  # noqa: PLC0415
        from ..models.kb_version import KBVersion  # noqa: PLC0415
        from ..models.search_cti_response_results_item import SearchCTIResponseResultsItem  # noqa: PLC0415

        errors: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.errors, Unset):
            errors = []
            for errors_item_data in self.errors:
                errors_item = errors_item_data.to_dict()
                errors.append(errors_item)

        knowledgebase_versions: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.knowledgebase_versions, Unset):
            knowledgebase_versions = []
            for knowledgebase_versions_item_data in self.knowledgebase_versions:
                knowledgebase_versions_item = knowledgebase_versions_item_data.to_dict()
                knowledgebase_versions.append(knowledgebase_versions_item)

        results: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.results, Unset):
            results = []
            for results_item_data in self.results:
                results_item = results_item_data.to_dict()
                results.append(results_item)

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if errors is not UNSET:
            field_dict["errors"] = errors
        if knowledgebase_versions is not UNSET:
            field_dict["knowledgebase_versions"] = knowledgebase_versions
        if results is not UNSET:
            field_dict["results"] = results

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.error_detail import ErrorDetail  # noqa: PLC0415
        from ..models.kb_version import KBVersion  # noqa: PLC0415
        from ..models.search_cti_response_results_item import SearchCTIResponseResultsItem  # noqa: PLC0415

        d = dict(src_dict)
        _errors = d.pop("errors", UNSET)
        errors: list[ErrorDetail] | Unset = UNSET
        if _errors is not UNSET:
            errors = []
            for errors_item_data in _errors:
                errors_item = ErrorDetail.from_dict(errors_item_data)

                errors.append(errors_item)

        _knowledgebase_versions = d.pop("knowledgebase_versions", UNSET)
        knowledgebase_versions: list[KBVersion] | Unset = UNSET
        if _knowledgebase_versions is not UNSET:
            knowledgebase_versions = []
            for knowledgebase_versions_item_data in _knowledgebase_versions:
                knowledgebase_versions_item = KBVersion.from_dict(knowledgebase_versions_item_data)

                knowledgebase_versions.append(knowledgebase_versions_item)

        _results = d.pop("results", UNSET)
        results: list[SearchCTIResponseResultsItem] | Unset = UNSET
        if _results is not UNSET:
            results = []
            for results_item_data in _results:
                results_item = SearchCTIResponseResultsItem.from_dict(results_item_data)

                results.append(results_item)

        search_cti_response = cls(
            errors=errors,
            knowledgebase_versions=knowledgebase_versions,
            results=results,
        )

        search_cti_response.additional_properties = d
        return search_cti_response

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

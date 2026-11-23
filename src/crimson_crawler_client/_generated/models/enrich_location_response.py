from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, BinaryIO, Generator, TextIO, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.error_detail import ErrorDetail
    from ..models.knowledgebase_result import KnowledgebaseResult
    from ..models.location_detail import LocationDetail


T = TypeVar("T", bound="EnrichLocationResponse")


@_attrs_define
class EnrichLocationResponse:
    """Geographic location enrichment — the location profile plus knowledge-base context.

    Attributes:
        errors (list[ErrorDetail] | Unset): Partial failure details
        identifier_resolved (bool | None | Unset): Whether a direct-lookup identifier resolved to a record. `false`
            means the id was not found, so every layer below is empty for that reason rather than because the record exists
            and has no data — the two were previously indistinguishable. `null` when the request used `search` instead of an
            id, where an empty result is a legitimate no-match.
        knowledgebase (list[KnowledgebaseResult] | Unset): Related intelligence from the knowledge base
        location (LocationDetail | None | Unset): Location threat profile (when looked up by ID)
        search_results (list[LocationDetail] | Unset): Matching locations (when searched by text)
        summary (None | str | Unset): AI-generated summary of the geographic threat profile
    """

    errors: list[ErrorDetail] | Unset = UNSET
    identifier_resolved: bool | None | Unset = UNSET
    knowledgebase: list[KnowledgebaseResult] | Unset = UNSET
    location: LocationDetail | None | Unset = UNSET
    search_results: list[LocationDetail] | Unset = UNSET
    summary: None | str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        from ..models.error_detail import ErrorDetail  # noqa: PLC0415
        from ..models.knowledgebase_result import KnowledgebaseResult  # noqa: PLC0415
        from ..models.location_detail import LocationDetail  # noqa: PLC0415

        errors: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.errors, Unset):
            errors = []
            for errors_item_data in self.errors:
                errors_item = errors_item_data.to_dict()
                errors.append(errors_item)

        identifier_resolved: bool | None | Unset
        if isinstance(self.identifier_resolved, Unset):
            identifier_resolved = UNSET
        else:
            identifier_resolved = self.identifier_resolved

        knowledgebase: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.knowledgebase, Unset):
            knowledgebase = []
            for knowledgebase_item_data in self.knowledgebase:
                knowledgebase_item = knowledgebase_item_data.to_dict()
                knowledgebase.append(knowledgebase_item)

        location: dict[str, Any] | None | Unset
        if isinstance(self.location, Unset):
            location = UNSET
        elif isinstance(self.location, LocationDetail):
            location = self.location.to_dict()
        else:
            location = self.location

        search_results: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.search_results, Unset):
            search_results = []
            for search_results_item_data in self.search_results:
                search_results_item = search_results_item_data.to_dict()
                search_results.append(search_results_item)

        summary: None | str | Unset
        if isinstance(self.summary, Unset):
            summary = UNSET
        else:
            summary = self.summary

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if errors is not UNSET:
            field_dict["errors"] = errors
        if identifier_resolved is not UNSET:
            field_dict["identifier_resolved"] = identifier_resolved
        if knowledgebase is not UNSET:
            field_dict["knowledgebase"] = knowledgebase
        if location is not UNSET:
            field_dict["location"] = location
        if search_results is not UNSET:
            field_dict["search_results"] = search_results
        if summary is not UNSET:
            field_dict["summary"] = summary

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.error_detail import ErrorDetail  # noqa: PLC0415
        from ..models.knowledgebase_result import KnowledgebaseResult  # noqa: PLC0415
        from ..models.location_detail import LocationDetail  # noqa: PLC0415

        d = dict(src_dict)
        _errors = d.pop("errors", UNSET)
        errors: list[ErrorDetail] | Unset = UNSET
        if _errors is not UNSET:
            errors = []
            for errors_item_data in _errors:
                errors_item = ErrorDetail.from_dict(errors_item_data)

                errors.append(errors_item)

        def _parse_identifier_resolved(data: object) -> bool | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(bool | None | Unset, data)

        identifier_resolved = _parse_identifier_resolved(d.pop("identifier_resolved", UNSET))

        _knowledgebase = d.pop("knowledgebase", UNSET)
        knowledgebase: list[KnowledgebaseResult] | Unset = UNSET
        if _knowledgebase is not UNSET:
            knowledgebase = []
            for knowledgebase_item_data in _knowledgebase:
                knowledgebase_item = KnowledgebaseResult.from_dict(knowledgebase_item_data)

                knowledgebase.append(knowledgebase_item)

        def _parse_location(data: object) -> LocationDetail | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, dict):
                    raise TypeError()
                location_type_0 = LocationDetail.from_dict(data)

                return location_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(LocationDetail | None | Unset, data)

        location = _parse_location(d.pop("location", UNSET))

        _search_results = d.pop("search_results", UNSET)
        search_results: list[LocationDetail] | Unset = UNSET
        if _search_results is not UNSET:
            search_results = []
            for search_results_item_data in _search_results:
                search_results_item = LocationDetail.from_dict(search_results_item_data)

                search_results.append(search_results_item)

        def _parse_summary(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        summary = _parse_summary(d.pop("summary", UNSET))

        enrich_location_response = cls(
            errors=errors,
            identifier_resolved=identifier_resolved,
            knowledgebase=knowledgebase,
            location=location,
            search_results=search_results,
            summary=summary,
        )

        enrich_location_response.additional_properties = d
        return enrich_location_response

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

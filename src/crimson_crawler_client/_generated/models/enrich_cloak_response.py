from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, BinaryIO, Generator, TextIO, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.error_detail import ErrorDetail
    from ..models.framework_object_detail import FrameworkObjectDetail
    from ..models.knowledgebase_result import KnowledgebaseResult


T = TypeVar("T", bound="EnrichCloakResponse")


@_attrs_define
class EnrichCloakResponse:
    """Concealment technique enrichment from the CLOAK framework.

    Attributes:
        errors (list[ErrorDetail] | Unset): Partial failure details
        identifier_resolved (bool | None | Unset): Whether the direct-lookup `cloak_id` resolved to a record. `false`
            means the id was not found, so every layer below is empty for that reason rather than because the record exists
            and has no data. `null` when the request used `search` instead of an id, where an empty result is a legitimate
            no-match.
        knowledgebase (list[KnowledgebaseResult] | Unset): Related intelligence from the knowledge base
        search_results (list[FrameworkObjectDetail] | Unset): Matching objects (when searched by text)
        summary (None | str | Unset): AI-generated summary of the CLOAK technique
        technique (FrameworkObjectDetail | None | Unset): Object details (when looked up by ID)
    """

    errors: list[ErrorDetail] | Unset = UNSET
    identifier_resolved: bool | None | Unset = UNSET
    knowledgebase: list[KnowledgebaseResult] | Unset = UNSET
    search_results: list[FrameworkObjectDetail] | Unset = UNSET
    summary: None | str | Unset = UNSET
    technique: FrameworkObjectDetail | None | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        from ..models.error_detail import ErrorDetail  # noqa: PLC0415
        from ..models.framework_object_detail import FrameworkObjectDetail  # noqa: PLC0415
        from ..models.knowledgebase_result import KnowledgebaseResult  # noqa: PLC0415

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

        technique: dict[str, Any] | None | Unset
        if isinstance(self.technique, Unset):
            technique = UNSET
        elif isinstance(self.technique, FrameworkObjectDetail):
            technique = self.technique.to_dict()
        else:
            technique = self.technique

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if errors is not UNSET:
            field_dict["errors"] = errors
        if identifier_resolved is not UNSET:
            field_dict["identifier_resolved"] = identifier_resolved
        if knowledgebase is not UNSET:
            field_dict["knowledgebase"] = knowledgebase
        if search_results is not UNSET:
            field_dict["search_results"] = search_results
        if summary is not UNSET:
            field_dict["summary"] = summary
        if technique is not UNSET:
            field_dict["technique"] = technique

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.error_detail import ErrorDetail  # noqa: PLC0415
        from ..models.framework_object_detail import FrameworkObjectDetail  # noqa: PLC0415
        from ..models.knowledgebase_result import KnowledgebaseResult  # noqa: PLC0415

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

        _search_results = d.pop("search_results", UNSET)
        search_results: list[FrameworkObjectDetail] | Unset = UNSET
        if _search_results is not UNSET:
            search_results = []
            for search_results_item_data in _search_results:
                search_results_item = FrameworkObjectDetail.from_dict(search_results_item_data)

                search_results.append(search_results_item)

        def _parse_summary(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        summary = _parse_summary(d.pop("summary", UNSET))

        def _parse_technique(data: object) -> FrameworkObjectDetail | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, dict):
                    raise TypeError()
                technique_type_0 = FrameworkObjectDetail.from_dict(data)

                return technique_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(FrameworkObjectDetail | None | Unset, data)

        technique = _parse_technique(d.pop("technique", UNSET))

        enrich_cloak_response = cls(
            errors=errors,
            identifier_resolved=identifier_resolved,
            knowledgebase=knowledgebase,
            search_results=search_results,
            summary=summary,
            technique=technique,
        )

        enrich_cloak_response.additional_properties = d
        return enrich_cloak_response

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

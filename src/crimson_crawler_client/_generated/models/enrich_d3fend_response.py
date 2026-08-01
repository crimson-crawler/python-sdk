from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, BinaryIO, Generator, TextIO, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.d3fend_detail import D3FENDDetail
    from ..models.error_detail import ErrorDetail
    from ..models.knowledgebase_result import KnowledgebaseResult
    from ..models.technique_detail import TechniqueDetail
    from ..models.web_result import WebResult


T = TypeVar("T", bound="EnrichD3FENDResponse")


@_attrs_define
class EnrichD3FENDResponse:
    """D3FEND defensive technique enrichment.

    Attributes:
        d3fend (D3FENDDetail | None | Unset): Defensive technique details (when looked up by ID)
        errors (list[ErrorDetail] | Unset): Partial failure details
        knowledgebase (list[KnowledgebaseResult] | Unset): Related intelligence from the knowledge base
        related_techniques (list[TechniqueDetail] | Unset): ATT&CK techniques this defends against
        search_results (list[D3FENDDetail] | Unset): Matching defensive techniques (when searched by text)
        summary (None | str | Unset): AI-generated summary
        web (list[WebResult] | Unset): Web search results
    """

    d3fend: D3FENDDetail | None | Unset = UNSET
    errors: list[ErrorDetail] | Unset = UNSET
    knowledgebase: list[KnowledgebaseResult] | Unset = UNSET
    related_techniques: list[TechniqueDetail] | Unset = UNSET
    search_results: list[D3FENDDetail] | Unset = UNSET
    summary: None | str | Unset = UNSET
    web: list[WebResult] | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        from ..models.d3fend_detail import D3FENDDetail
        from ..models.error_detail import ErrorDetail
        from ..models.knowledgebase_result import KnowledgebaseResult
        from ..models.technique_detail import TechniqueDetail
        from ..models.web_result import WebResult

        d3fend: dict[str, Any] | None | Unset
        if isinstance(self.d3fend, Unset):
            d3fend = UNSET
        elif isinstance(self.d3fend, D3FENDDetail):
            d3fend = self.d3fend.to_dict()
        else:
            d3fend = self.d3fend

        errors: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.errors, Unset):
            errors = []
            for errors_item_data in self.errors:
                errors_item = errors_item_data.to_dict()
                errors.append(errors_item)

        knowledgebase: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.knowledgebase, Unset):
            knowledgebase = []
            for knowledgebase_item_data in self.knowledgebase:
                knowledgebase_item = knowledgebase_item_data.to_dict()
                knowledgebase.append(knowledgebase_item)

        related_techniques: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.related_techniques, Unset):
            related_techniques = []
            for related_techniques_item_data in self.related_techniques:
                related_techniques_item = related_techniques_item_data.to_dict()
                related_techniques.append(related_techniques_item)

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

        web: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.web, Unset):
            web = []
            for web_item_data in self.web:
                web_item = web_item_data.to_dict()
                web.append(web_item)

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if d3fend is not UNSET:
            field_dict["d3fend"] = d3fend
        if errors is not UNSET:
            field_dict["errors"] = errors
        if knowledgebase is not UNSET:
            field_dict["knowledgebase"] = knowledgebase
        if related_techniques is not UNSET:
            field_dict["related_techniques"] = related_techniques
        if search_results is not UNSET:
            field_dict["search_results"] = search_results
        if summary is not UNSET:
            field_dict["summary"] = summary
        if web is not UNSET:
            field_dict["web"] = web

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.d3fend_detail import D3FENDDetail
        from ..models.error_detail import ErrorDetail
        from ..models.knowledgebase_result import KnowledgebaseResult
        from ..models.technique_detail import TechniqueDetail
        from ..models.web_result import WebResult

        d = dict(src_dict)

        def _parse_d3fend(data: object) -> D3FENDDetail | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, dict):
                    raise TypeError()
                d3fend_type_0 = D3FENDDetail.from_dict(data)

                return d3fend_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(D3FENDDetail | None | Unset, data)

        d3fend = _parse_d3fend(d.pop("d3fend", UNSET))

        _errors = d.pop("errors", UNSET)
        errors: list[ErrorDetail] | Unset = UNSET
        if _errors is not UNSET:
            errors = []
            for errors_item_data in _errors:
                errors_item = ErrorDetail.from_dict(errors_item_data)

                errors.append(errors_item)

        _knowledgebase = d.pop("knowledgebase", UNSET)
        knowledgebase: list[KnowledgebaseResult] | Unset = UNSET
        if _knowledgebase is not UNSET:
            knowledgebase = []
            for knowledgebase_item_data in _knowledgebase:
                knowledgebase_item = KnowledgebaseResult.from_dict(knowledgebase_item_data)

                knowledgebase.append(knowledgebase_item)

        _related_techniques = d.pop("related_techniques", UNSET)
        related_techniques: list[TechniqueDetail] | Unset = UNSET
        if _related_techniques is not UNSET:
            related_techniques = []
            for related_techniques_item_data in _related_techniques:
                related_techniques_item = TechniqueDetail.from_dict(related_techniques_item_data)

                related_techniques.append(related_techniques_item)

        _search_results = d.pop("search_results", UNSET)
        search_results: list[D3FENDDetail] | Unset = UNSET
        if _search_results is not UNSET:
            search_results = []
            for search_results_item_data in _search_results:
                search_results_item = D3FENDDetail.from_dict(search_results_item_data)

                search_results.append(search_results_item)

        def _parse_summary(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        summary = _parse_summary(d.pop("summary", UNSET))

        _web = d.pop("web", UNSET)
        web: list[WebResult] | Unset = UNSET
        if _web is not UNSET:
            web = []
            for web_item_data in _web:
                web_item = WebResult.from_dict(web_item_data)

                web.append(web_item)

        enrich_d3fend_response = cls(
            d3fend=d3fend,
            errors=errors,
            knowledgebase=knowledgebase,
            related_techniques=related_techniques,
            search_results=search_results,
            summary=summary,
            web=web,
        )

        enrich_d3fend_response.additional_properties = d
        return enrich_d3fend_response

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

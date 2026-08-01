from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, BinaryIO, Generator, TextIO, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..models.search_d3fend_request_d3_fend_form_type_0 import SearchD3FENDRequestD3FendFormType0
from ..types import UNSET, Unset

T = TypeVar("T", bound="SearchD3FENDRequest")


@_attrs_define
class SearchD3FENDRequest:
    """Search D3FEND defensive techniques by text.

    Attributes:
        query (str): Search query
        d3fend_form (None | SearchD3FENDRequestD3FendFormType0 | Unset): Filter by D3FEND form: tactic, mitigation, sub-
            mitigation, artifact
        limit (int | Unset): Maximum results (1-100) Default: 20.
        page (int | Unset): Page number for pagination (1-indexed, max 100) Default: 1.
    """

    query: str
    d3fend_form: None | SearchD3FENDRequestD3FendFormType0 | Unset = UNSET
    limit: int | Unset = 20
    page: int | Unset = 1
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        query = self.query

        d3fend_form: None | str | Unset
        if isinstance(self.d3fend_form, Unset):
            d3fend_form = UNSET
        elif isinstance(self.d3fend_form, SearchD3FENDRequestD3FendFormType0):
            d3fend_form = self.d3fend_form.value
        else:
            d3fend_form = self.d3fend_form

        limit = self.limit

        page = self.page

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "query": query,
            }
        )
        if d3fend_form is not UNSET:
            field_dict["d3fend_form"] = d3fend_form
        if limit is not UNSET:
            field_dict["limit"] = limit
        if page is not UNSET:
            field_dict["page"] = page

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        query = d.pop("query")

        def _parse_d3fend_form(data: object) -> None | SearchD3FENDRequestD3FendFormType0 | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, str):
                    raise TypeError()
                d3fend_form_type_0 = SearchD3FENDRequestD3FendFormType0(data)

                return d3fend_form_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(None | SearchD3FENDRequestD3FendFormType0 | Unset, data)

        d3fend_form = _parse_d3fend_form(d.pop("d3fend_form", UNSET))

        limit = d.pop("limit", UNSET)

        page = d.pop("page", UNSET)

        search_d3fend_request = cls(
            query=query,
            d3fend_form=d3fend_form,
            limit=limit,
            page=page,
        )

        search_d3fend_request.additional_properties = d
        return search_d3fend_request

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

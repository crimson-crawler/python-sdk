from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, BinaryIO, Generator, TextIO, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.error_detail import ErrorDetail
    from ..models.po_c_source_summary import PoCSourceSummary


T = TypeVar("T", bound="FetchPoCSourceResponse")


@_attrs_define
class FetchPoCSourceResponse:
    """AI-assisted analysis of a public PoC repository. Raw source code is not returned.

    Attributes:
        repo_url (str): Repository URL that was analyzed
        errors (list[ErrorDetail] | Unset): Partial failure details
        summary (None | PoCSourceSummary | Unset): Structured exploit analysis. Null when the repository could not be
            read, contained no analyzable source, AI analysis was unavailable, or the output failed safety validation.
    """

    repo_url: str
    errors: list[ErrorDetail] | Unset = UNSET
    summary: None | PoCSourceSummary | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        from ..models.error_detail import ErrorDetail
        from ..models.po_c_source_summary import PoCSourceSummary

        repo_url = self.repo_url

        errors: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.errors, Unset):
            errors = []
            for errors_item_data in self.errors:
                errors_item = errors_item_data.to_dict()
                errors.append(errors_item)

        summary: dict[str, Any] | None | Unset
        if isinstance(self.summary, Unset):
            summary = UNSET
        elif isinstance(self.summary, PoCSourceSummary):
            summary = self.summary.to_dict()
        else:
            summary = self.summary

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "repo_url": repo_url,
            }
        )
        if errors is not UNSET:
            field_dict["errors"] = errors
        if summary is not UNSET:
            field_dict["summary"] = summary

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.error_detail import ErrorDetail
        from ..models.po_c_source_summary import PoCSourceSummary

        d = dict(src_dict)
        repo_url = d.pop("repo_url")

        _errors = d.pop("errors", UNSET)
        errors: list[ErrorDetail] | Unset = UNSET
        if _errors is not UNSET:
            errors = []
            for errors_item_data in _errors:
                errors_item = ErrorDetail.from_dict(errors_item_data)

                errors.append(errors_item)

        def _parse_summary(data: object) -> None | PoCSourceSummary | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, dict):
                    raise TypeError()
                summary_type_0 = PoCSourceSummary.from_dict(data)

                return summary_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(None | PoCSourceSummary | Unset, data)

        summary = _parse_summary(d.pop("summary", UNSET))

        fetch_po_c_source_response = cls(
            repo_url=repo_url,
            errors=errors,
            summary=summary,
        )

        fetch_po_c_source_response.additional_properties = d
        return fetch_po_c_source_response

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

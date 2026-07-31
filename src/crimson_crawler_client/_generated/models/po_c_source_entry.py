from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, BinaryIO, Generator, TextIO, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.po_c_source_summary import PoCSourceSummary


T = TypeVar("T", bound="PoCSourceEntry")


@_attrs_define
class PoCSourceEntry:
    """AI-assisted analysis of a public PoC repository. Raw source code is not returned.

    Attributes:
        repo_url (str | Unset): GitHub repository URL that was analyzed Default: ''.
        summary (None | PoCSourceSummary | Unset): Structured exploit analysis (null on fetch failure or empty source)
    """

    repo_url: str | Unset = ""
    summary: None | PoCSourceSummary | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        from ..models.po_c_source_summary import PoCSourceSummary

        repo_url = self.repo_url

        summary: dict[str, Any] | None | Unset
        if isinstance(self.summary, Unset):
            summary = UNSET
        elif isinstance(self.summary, PoCSourceSummary):
            summary = self.summary.to_dict()
        else:
            summary = self.summary

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if repo_url is not UNSET:
            field_dict["repo_url"] = repo_url
        if summary is not UNSET:
            field_dict["summary"] = summary

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.po_c_source_summary import PoCSourceSummary

        d = dict(src_dict)
        repo_url = d.pop("repo_url", UNSET)

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

        po_c_source_entry = cls(
            repo_url=repo_url,
            summary=summary,
        )

        po_c_source_entry.additional_properties = d
        return po_c_source_entry

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

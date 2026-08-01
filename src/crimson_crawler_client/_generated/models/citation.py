from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, BinaryIO, Generator, TextIO, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.admiralty_grade import AdmiraltyGrade


T = TypeVar("T", bound="Citation")


@_attrs_define
class Citation:
    """One graded claim traced to its deterministic source.

    Attributes:
        claim (str): The assertion being supported
        source (str): Public name of the intelligence source supporting the claim
        grade (AdmiraltyGrade | None | Unset): Admiralty grade for this claim's source
        source_url (None | str | Unset): Reference URL for the source, when available
    """

    claim: str
    source: str
    grade: AdmiraltyGrade | None | Unset = UNSET
    source_url: None | str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        from ..models.admiralty_grade import AdmiraltyGrade

        claim = self.claim

        source = self.source

        grade: dict[str, Any] | None | Unset
        if isinstance(self.grade, Unset):
            grade = UNSET
        elif isinstance(self.grade, AdmiraltyGrade):
            grade = self.grade.to_dict()
        else:
            grade = self.grade

        source_url: None | str | Unset
        if isinstance(self.source_url, Unset):
            source_url = UNSET
        else:
            source_url = self.source_url

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "claim": claim,
                "source": source,
            }
        )
        if grade is not UNSET:
            field_dict["grade"] = grade
        if source_url is not UNSET:
            field_dict["source_url"] = source_url

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.admiralty_grade import AdmiraltyGrade

        d = dict(src_dict)
        claim = d.pop("claim")

        source = d.pop("source")

        def _parse_grade(data: object) -> AdmiraltyGrade | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, dict):
                    raise TypeError()
                grade_type_0 = AdmiraltyGrade.from_dict(data)

                return grade_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(AdmiraltyGrade | None | Unset, data)

        grade = _parse_grade(d.pop("grade", UNSET))

        def _parse_source_url(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        source_url = _parse_source_url(d.pop("source_url", UNSET))

        citation = cls(
            claim=claim,
            source=source,
            grade=grade,
            source_url=source_url,
        )

        citation.additional_properties = d
        return citation

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

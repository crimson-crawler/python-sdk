from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, BinaryIO, Generator, TextIO, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..models.coverage_gap_kind import CoverageGapKind
from ..types import UNSET, Unset

T = TypeVar("T", bound="CoverageGap")


@_attrs_define
class CoverageGap:
    """Structured "what we DON'T know" entry surfaced at the report root.

    Each kind is a pure derivation from existing structured fields on the references — no
    invented signals. Analysts must see coverage gaps before they trust the report; this
    surface promotes the previously-buried ``source_corroboration.caveats`` strings into a
    typed list the UI can render as a dedicated panel.

        Attributes:
            kind (CoverageGapKind): Coverage-gap category
            message (str): One-sentence analyst-facing description
            affected_ref_ids (list[str] | Unset): Stable reference IDs (from ArtifactEnrichmentReference.id) affected by
                this gap
            count (int | Unset): How many references this gap touches Default: 0.
    """

    kind: CoverageGapKind
    message: str
    affected_ref_ids: list[str] | Unset = UNSET
    count: int | Unset = 0
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        kind = self.kind.value

        message = self.message

        affected_ref_ids: list[str] | Unset = UNSET
        if not isinstance(self.affected_ref_ids, Unset):
            affected_ref_ids = self.affected_ref_ids

        count = self.count

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "kind": kind,
                "message": message,
            }
        )
        if affected_ref_ids is not UNSET:
            field_dict["affected_ref_ids"] = affected_ref_ids
        if count is not UNSET:
            field_dict["count"] = count

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        kind = CoverageGapKind(d.pop("kind"))

        message = d.pop("message")

        affected_ref_ids = cast(list[str], d.pop("affected_ref_ids", UNSET))

        count = d.pop("count", UNSET)

        coverage_gap = cls(
            kind=kind,
            message=message,
            affected_ref_ids=affected_ref_ids,
            count=count,
        )

        coverage_gap.additional_properties = d
        return coverage_gap

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

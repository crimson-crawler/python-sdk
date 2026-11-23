from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, BinaryIO, Generator, TextIO, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.capec_detail import CAPECDetail


T = TypeVar("T", bound="CVEContextCatalogAttackPatterns")


@_attrs_define
class CVEContextCatalogAttackPatterns:
    """CAPEC patterns keyed by catalogue ID"""

    additional_properties: dict[str, CAPECDetail] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        from ..models.capec_detail import CAPECDetail  # noqa: PLC0415

        field_dict: dict[str, Any] = {}
        for prop_name, prop in self.additional_properties.items():
            field_dict[prop_name] = prop.to_dict()

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.capec_detail import CAPECDetail  # noqa: PLC0415

        d = dict(src_dict)
        cve_context_catalog_attack_patterns = cls()

        from ..models.capec_detail_skills_required import CAPECDetailSkillsRequired  # noqa: PLC0415
        from ..models.capec_related_ids import CAPECRelatedIds  # noqa: PLC0415
        from ..models.cve_reference import CVEReference  # noqa: PLC0415
        from ..models.revision_entry import RevisionEntry  # noqa: PLC0415

        additional_properties = {}
        for prop_name, prop_dict in d.items():
            additional_property = CAPECDetail.from_dict(prop_dict)

            additional_properties[prop_name] = additional_property

        cve_context_catalog_attack_patterns.additional_properties = additional_properties
        return cve_context_catalog_attack_patterns

    @property
    def additional_keys(self) -> list[str]:
        return list(self.additional_properties.keys())

    def __getitem__(self, key: str) -> CAPECDetail:
        return self.additional_properties[key]

    def __setitem__(self, key: str, value: CAPECDetail) -> None:
        self.additional_properties[key] = value

    def __delitem__(self, key: str) -> None:
        del self.additional_properties[key]

    def __contains__(self, key: str) -> bool:
        return key in self.additional_properties

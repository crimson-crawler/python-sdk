from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, BinaryIO, Generator, TextIO, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.technique_detail import TechniqueDetail


T = TypeVar("T", bound="CVEContextCatalogTechniques")


@_attrs_define
class CVEContextCatalogTechniques:
    """ATT&CK techniques keyed by catalogue ID"""

    additional_properties: dict[str, TechniqueDetail] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        from ..models.technique_detail import TechniqueDetail  # noqa: PLC0415

        field_dict: dict[str, Any] = {}
        for prop_name, prop in self.additional_properties.items():
            field_dict[prop_name] = prop.to_dict()

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.technique_detail import TechniqueDetail  # noqa: PLC0415

        d = dict(src_dict)
        cve_context_catalog_techniques = cls()

        additional_properties = {}
        for prop_name, prop_dict in d.items():
            additional_property = TechniqueDetail.from_dict(prop_dict)

            additional_properties[prop_name] = additional_property

        cve_context_catalog_techniques.additional_properties = additional_properties
        return cve_context_catalog_techniques

    @property
    def additional_keys(self) -> list[str]:
        return list(self.additional_properties.keys())

    def __getitem__(self, key: str) -> TechniqueDetail:
        return self.additional_properties[key]

    def __setitem__(self, key: str, value: TechniqueDetail) -> None:
        self.additional_properties[key] = value

    def __delitem__(self, key: str) -> None:
        del self.additional_properties[key]

    def __contains__(self, key: str) -> bool:
        return key in self.additional_properties

from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, BinaryIO, Generator, TextIO, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.cve_context_catalog_attack_patterns import CVEContextCatalogAttackPatterns
    from ..models.cve_context_catalog_mitigations import CVEContextCatalogMitigations
    from ..models.cve_context_catalog_techniques import CVEContextCatalogTechniques
    from ..models.cve_context_catalog_weaknesses import CVEContextCatalogWeaknesses


T = TypeVar("T", bound="CVEContextCatalog")


@_attrs_define
class CVEContextCatalog:
    """Page-local shared CVE context, keyed by identifier with suffixes for differing versions.

    Attributes:
        attack_patterns (CVEContextCatalogAttackPatterns | Unset): CAPEC patterns keyed by catalogue ID
        mitigations (CVEContextCatalogMitigations | Unset): ATT&CK mitigations keyed by catalogue ID
        techniques (CVEContextCatalogTechniques | Unset): ATT&CK techniques keyed by catalogue ID
        weaknesses (CVEContextCatalogWeaknesses | Unset): CWE weaknesses keyed by catalogue ID
    """

    attack_patterns: CVEContextCatalogAttackPatterns | Unset = UNSET
    mitigations: CVEContextCatalogMitigations | Unset = UNSET
    techniques: CVEContextCatalogTechniques | Unset = UNSET
    weaknesses: CVEContextCatalogWeaknesses | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        from ..models.cve_context_catalog_attack_patterns import CVEContextCatalogAttackPatterns  # noqa: PLC0415
        from ..models.cve_context_catalog_mitigations import CVEContextCatalogMitigations  # noqa: PLC0415
        from ..models.cve_context_catalog_techniques import CVEContextCatalogTechniques  # noqa: PLC0415
        from ..models.cve_context_catalog_weaknesses import CVEContextCatalogWeaknesses  # noqa: PLC0415

        attack_patterns: dict[str, Any] | Unset = UNSET
        if not isinstance(self.attack_patterns, Unset):
            attack_patterns = self.attack_patterns.to_dict()

        mitigations: dict[str, Any] | Unset = UNSET
        if not isinstance(self.mitigations, Unset):
            mitigations = self.mitigations.to_dict()

        techniques: dict[str, Any] | Unset = UNSET
        if not isinstance(self.techniques, Unset):
            techniques = self.techniques.to_dict()

        weaknesses: dict[str, Any] | Unset = UNSET
        if not isinstance(self.weaknesses, Unset):
            weaknesses = self.weaknesses.to_dict()

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if attack_patterns is not UNSET:
            field_dict["attack_patterns"] = attack_patterns
        if mitigations is not UNSET:
            field_dict["mitigations"] = mitigations
        if techniques is not UNSET:
            field_dict["techniques"] = techniques
        if weaknesses is not UNSET:
            field_dict["weaknesses"] = weaknesses

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.cve_context_catalog_attack_patterns import CVEContextCatalogAttackPatterns  # noqa: PLC0415
        from ..models.cve_context_catalog_mitigations import CVEContextCatalogMitigations  # noqa: PLC0415
        from ..models.cve_context_catalog_techniques import CVEContextCatalogTechniques  # noqa: PLC0415
        from ..models.cve_context_catalog_weaknesses import CVEContextCatalogWeaknesses  # noqa: PLC0415

        d = dict(src_dict)
        _attack_patterns = d.pop("attack_patterns", UNSET)
        attack_patterns: CVEContextCatalogAttackPatterns | Unset
        if isinstance(_attack_patterns, Unset):
            attack_patterns = UNSET
        else:
            attack_patterns = CVEContextCatalogAttackPatterns.from_dict(_attack_patterns)

        _mitigations = d.pop("mitigations", UNSET)
        mitigations: CVEContextCatalogMitigations | Unset
        if isinstance(_mitigations, Unset):
            mitigations = UNSET
        else:
            mitigations = CVEContextCatalogMitigations.from_dict(_mitigations)

        _techniques = d.pop("techniques", UNSET)
        techniques: CVEContextCatalogTechniques | Unset
        if isinstance(_techniques, Unset):
            techniques = UNSET
        else:
            techniques = CVEContextCatalogTechniques.from_dict(_techniques)

        _weaknesses = d.pop("weaknesses", UNSET)
        weaknesses: CVEContextCatalogWeaknesses | Unset
        if isinstance(_weaknesses, Unset):
            weaknesses = UNSET
        else:
            weaknesses = CVEContextCatalogWeaknesses.from_dict(_weaknesses)

        cve_context_catalog = cls(
            attack_patterns=attack_patterns,
            mitigations=mitigations,
            techniques=techniques,
            weaknesses=weaknesses,
        )

        cve_context_catalog.additional_properties = d
        return cve_context_catalog

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

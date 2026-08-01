from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, BinaryIO, Generator, TextIO, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.cwe_detail_related_weaknesses_item import CWEDetailRelatedWeaknessesItem


T = TypeVar("T", bound="CWEDetail")


@_attrs_define
class CWEDetail:
    """Common Weakness Enumeration - the root cause vulnerability class.

    Attributes:
        cwe_id (str): CWE identifier (e.g. CWE-79)
        abstraction (None | str | Unset): CWE abstraction level (Base, Class, Pillar, Variant, Compound)
        capec_ids (list[str] | Unset): Linked CAPEC attack pattern IDs
        contributors (list[str] | Unset): Contributors listed in x_mitre_contributors
        deprecated (bool | Unset): True if MITRE marked this CWE deprecated Default: False.
        description (None | str | Unset): Detailed weakness description
        is_generic (bool | Unset): True for broad CWE pillars, classes, and placeholder values that do not provide a
            CVE-specific root cause. Technique mappings derived only from a generic CWE can overlap across unrelated CVEs.
            Check `techniques_provenance` or use `techniques_scope=specific` when precision matters more than recall.
            Default: False.
        linked_techniques (list[str] | Unset): Directly linked ATT&CK technique IDs
        name (None | str | Unset): Weakness name (e.g. 'Cross-site Scripting')
        related_weaknesses (list[CWEDetailRelatedWeaknessesItem] | Unset): Parent/child CWE hierarchy references (nature
            + cwe_id)
        revoked (bool | Unset): True if MITRE has revoked this CWE Default: False.
        status (None | str | Unset): CWE lifecycle status (Draft, Stable, Deprecated, Obsolete)
        url (None | str | Unset): Reference URL for full CWE details
        version (None | str | Unset): MITRE object version (x_mitre_version)
    """

    cwe_id: str
    abstraction: None | str | Unset = UNSET
    capec_ids: list[str] | Unset = UNSET
    contributors: list[str] | Unset = UNSET
    deprecated: bool | Unset = False
    description: None | str | Unset = UNSET
    is_generic: bool | Unset = False
    linked_techniques: list[str] | Unset = UNSET
    name: None | str | Unset = UNSET
    related_weaknesses: list[CWEDetailRelatedWeaknessesItem] | Unset = UNSET
    revoked: bool | Unset = False
    status: None | str | Unset = UNSET
    url: None | str | Unset = UNSET
    version: None | str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        from ..models.cwe_detail_related_weaknesses_item import CWEDetailRelatedWeaknessesItem

        cwe_id = self.cwe_id

        abstraction: None | str | Unset
        if isinstance(self.abstraction, Unset):
            abstraction = UNSET
        else:
            abstraction = self.abstraction

        capec_ids: list[str] | Unset = UNSET
        if not isinstance(self.capec_ids, Unset):
            capec_ids = self.capec_ids

        contributors: list[str] | Unset = UNSET
        if not isinstance(self.contributors, Unset):
            contributors = self.contributors

        deprecated = self.deprecated

        description: None | str | Unset
        if isinstance(self.description, Unset):
            description = UNSET
        else:
            description = self.description

        is_generic = self.is_generic

        linked_techniques: list[str] | Unset = UNSET
        if not isinstance(self.linked_techniques, Unset):
            linked_techniques = self.linked_techniques

        name: None | str | Unset
        if isinstance(self.name, Unset):
            name = UNSET
        else:
            name = self.name

        related_weaknesses: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.related_weaknesses, Unset):
            related_weaknesses = []
            for related_weaknesses_item_data in self.related_weaknesses:
                related_weaknesses_item = related_weaknesses_item_data.to_dict()
                related_weaknesses.append(related_weaknesses_item)

        revoked = self.revoked

        status: None | str | Unset
        if isinstance(self.status, Unset):
            status = UNSET
        else:
            status = self.status

        url: None | str | Unset
        if isinstance(self.url, Unset):
            url = UNSET
        else:
            url = self.url

        version: None | str | Unset
        if isinstance(self.version, Unset):
            version = UNSET
        else:
            version = self.version

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "cwe_id": cwe_id,
            }
        )
        if abstraction is not UNSET:
            field_dict["abstraction"] = abstraction
        if capec_ids is not UNSET:
            field_dict["capec_ids"] = capec_ids
        if contributors is not UNSET:
            field_dict["contributors"] = contributors
        if deprecated is not UNSET:
            field_dict["deprecated"] = deprecated
        if description is not UNSET:
            field_dict["description"] = description
        if is_generic is not UNSET:
            field_dict["is_generic"] = is_generic
        if linked_techniques is not UNSET:
            field_dict["linked_techniques"] = linked_techniques
        if name is not UNSET:
            field_dict["name"] = name
        if related_weaknesses is not UNSET:
            field_dict["related_weaknesses"] = related_weaknesses
        if revoked is not UNSET:
            field_dict["revoked"] = revoked
        if status is not UNSET:
            field_dict["status"] = status
        if url is not UNSET:
            field_dict["url"] = url
        if version is not UNSET:
            field_dict["version"] = version

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.cwe_detail_related_weaknesses_item import CWEDetailRelatedWeaknessesItem

        d = dict(src_dict)
        cwe_id = d.pop("cwe_id")

        def _parse_abstraction(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        abstraction = _parse_abstraction(d.pop("abstraction", UNSET))

        capec_ids = cast(list[str], d.pop("capec_ids", UNSET))

        contributors = cast(list[str], d.pop("contributors", UNSET))

        deprecated = d.pop("deprecated", UNSET)

        def _parse_description(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        description = _parse_description(d.pop("description", UNSET))

        is_generic = d.pop("is_generic", UNSET)

        linked_techniques = cast(list[str], d.pop("linked_techniques", UNSET))

        def _parse_name(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        name = _parse_name(d.pop("name", UNSET))

        _related_weaknesses = d.pop("related_weaknesses", UNSET)
        related_weaknesses: list[CWEDetailRelatedWeaknessesItem] | Unset = UNSET
        if _related_weaknesses is not UNSET:
            related_weaknesses = []
            for related_weaknesses_item_data in _related_weaknesses:
                related_weaknesses_item = CWEDetailRelatedWeaknessesItem.from_dict(related_weaknesses_item_data)

                related_weaknesses.append(related_weaknesses_item)

        revoked = d.pop("revoked", UNSET)

        def _parse_status(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        status = _parse_status(d.pop("status", UNSET))

        def _parse_url(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        url = _parse_url(d.pop("url", UNSET))

        def _parse_version(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        version = _parse_version(d.pop("version", UNSET))

        cwe_detail = cls(
            cwe_id=cwe_id,
            abstraction=abstraction,
            capec_ids=capec_ids,
            contributors=contributors,
            deprecated=deprecated,
            description=description,
            is_generic=is_generic,
            linked_techniques=linked_techniques,
            name=name,
            related_weaknesses=related_weaknesses,
            revoked=revoked,
            status=status,
            url=url,
            version=version,
        )

        cwe_detail.additional_properties = d
        return cwe_detail

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

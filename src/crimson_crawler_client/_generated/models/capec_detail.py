from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, BinaryIO, Generator, TextIO, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="CAPECDetail")


@_attrs_define
class CAPECDetail:
    """Common Attack Pattern Enumeration - how a weakness is exploited in practice.

    Attributes:
        capec_id (str): CAPEC identifier (e.g. CAPEC-66)
        abstraction (None | str | Unset): Abstraction level (Meta, Standard, Detailed)
        capec_mitigations (list[str] | Unset): Recommended mitigations from the CAPEC framework
        consequences (list[str] | Unset): Potential consequences if this attack pattern succeeds
        contributors (list[str] | Unset): Contributors listed in x_mitre_contributors
        deprecated (bool | Unset): True if MITRE marked this CAPEC deprecated Default: False.
        description (None | str | Unset): Detailed attack pattern description
        domains (list[str] | Unset): Applicable domains (e.g. Software, Communications)
        likelihood (None | str | Unset): Attack likelihood: high, medium, or low
        linked_cwes (list[str] | Unset): Related CWE weakness IDs
        linked_techniques (list[str] | Unset): Linked ATT&CK technique IDs
        name (None | str | Unset): Attack pattern name
        prerequisites (list[str] | Unset): Prerequisites for executing this attack pattern
        resources_required (list[str] | Unset): Resources required to execute this attack
        revoked (bool | Unset): True if MITRE has revoked this CAPEC Default: False.
        severity (None | str | Unset): Typical severity: low, medium, high
        status (None | str | Unset): CAPEC status (Draft, Stable, etc.)
        url (None | str | Unset): Reference URL for full CAPEC details
        version (None | str | Unset): MITRE object version (x_mitre_version)
    """

    capec_id: str
    abstraction: None | str | Unset = UNSET
    capec_mitigations: list[str] | Unset = UNSET
    consequences: list[str] | Unset = UNSET
    contributors: list[str] | Unset = UNSET
    deprecated: bool | Unset = False
    description: None | str | Unset = UNSET
    domains: list[str] | Unset = UNSET
    likelihood: None | str | Unset = UNSET
    linked_cwes: list[str] | Unset = UNSET
    linked_techniques: list[str] | Unset = UNSET
    name: None | str | Unset = UNSET
    prerequisites: list[str] | Unset = UNSET
    resources_required: list[str] | Unset = UNSET
    revoked: bool | Unset = False
    severity: None | str | Unset = UNSET
    status: None | str | Unset = UNSET
    url: None | str | Unset = UNSET
    version: None | str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        capec_id = self.capec_id

        abstraction: None | str | Unset
        if isinstance(self.abstraction, Unset):
            abstraction = UNSET
        else:
            abstraction = self.abstraction

        capec_mitigations: list[str] | Unset = UNSET
        if not isinstance(self.capec_mitigations, Unset):
            capec_mitigations = self.capec_mitigations

        consequences: list[str] | Unset = UNSET
        if not isinstance(self.consequences, Unset):
            consequences = self.consequences

        contributors: list[str] | Unset = UNSET
        if not isinstance(self.contributors, Unset):
            contributors = self.contributors

        deprecated = self.deprecated

        description: None | str | Unset
        if isinstance(self.description, Unset):
            description = UNSET
        else:
            description = self.description

        domains: list[str] | Unset = UNSET
        if not isinstance(self.domains, Unset):
            domains = self.domains

        likelihood: None | str | Unset
        if isinstance(self.likelihood, Unset):
            likelihood = UNSET
        else:
            likelihood = self.likelihood

        linked_cwes: list[str] | Unset = UNSET
        if not isinstance(self.linked_cwes, Unset):
            linked_cwes = self.linked_cwes

        linked_techniques: list[str] | Unset = UNSET
        if not isinstance(self.linked_techniques, Unset):
            linked_techniques = self.linked_techniques

        name: None | str | Unset
        if isinstance(self.name, Unset):
            name = UNSET
        else:
            name = self.name

        prerequisites: list[str] | Unset = UNSET
        if not isinstance(self.prerequisites, Unset):
            prerequisites = self.prerequisites

        resources_required: list[str] | Unset = UNSET
        if not isinstance(self.resources_required, Unset):
            resources_required = self.resources_required

        revoked = self.revoked

        severity: None | str | Unset
        if isinstance(self.severity, Unset):
            severity = UNSET
        else:
            severity = self.severity

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
                "capec_id": capec_id,
            }
        )
        if abstraction is not UNSET:
            field_dict["abstraction"] = abstraction
        if capec_mitigations is not UNSET:
            field_dict["capec_mitigations"] = capec_mitigations
        if consequences is not UNSET:
            field_dict["consequences"] = consequences
        if contributors is not UNSET:
            field_dict["contributors"] = contributors
        if deprecated is not UNSET:
            field_dict["deprecated"] = deprecated
        if description is not UNSET:
            field_dict["description"] = description
        if domains is not UNSET:
            field_dict["domains"] = domains
        if likelihood is not UNSET:
            field_dict["likelihood"] = likelihood
        if linked_cwes is not UNSET:
            field_dict["linked_cwes"] = linked_cwes
        if linked_techniques is not UNSET:
            field_dict["linked_techniques"] = linked_techniques
        if name is not UNSET:
            field_dict["name"] = name
        if prerequisites is not UNSET:
            field_dict["prerequisites"] = prerequisites
        if resources_required is not UNSET:
            field_dict["resources_required"] = resources_required
        if revoked is not UNSET:
            field_dict["revoked"] = revoked
        if severity is not UNSET:
            field_dict["severity"] = severity
        if status is not UNSET:
            field_dict["status"] = status
        if url is not UNSET:
            field_dict["url"] = url
        if version is not UNSET:
            field_dict["version"] = version

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        capec_id = d.pop("capec_id")

        def _parse_abstraction(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        abstraction = _parse_abstraction(d.pop("abstraction", UNSET))

        capec_mitigations = cast(list[str], d.pop("capec_mitigations", UNSET))

        consequences = cast(list[str], d.pop("consequences", UNSET))

        contributors = cast(list[str], d.pop("contributors", UNSET))

        deprecated = d.pop("deprecated", UNSET)

        def _parse_description(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        description = _parse_description(d.pop("description", UNSET))

        domains = cast(list[str], d.pop("domains", UNSET))

        def _parse_likelihood(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        likelihood = _parse_likelihood(d.pop("likelihood", UNSET))

        linked_cwes = cast(list[str], d.pop("linked_cwes", UNSET))

        linked_techniques = cast(list[str], d.pop("linked_techniques", UNSET))

        def _parse_name(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        name = _parse_name(d.pop("name", UNSET))

        prerequisites = cast(list[str], d.pop("prerequisites", UNSET))

        resources_required = cast(list[str], d.pop("resources_required", UNSET))

        revoked = d.pop("revoked", UNSET)

        def _parse_severity(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        severity = _parse_severity(d.pop("severity", UNSET))

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

        capec_detail = cls(
            capec_id=capec_id,
            abstraction=abstraction,
            capec_mitigations=capec_mitigations,
            consequences=consequences,
            contributors=contributors,
            deprecated=deprecated,
            description=description,
            domains=domains,
            likelihood=likelihood,
            linked_cwes=linked_cwes,
            linked_techniques=linked_techniques,
            name=name,
            prerequisites=prerequisites,
            resources_required=resources_required,
            revoked=revoked,
            severity=severity,
            status=status,
            url=url,
            version=version,
        )

        capec_detail.additional_properties = d
        return capec_detail

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

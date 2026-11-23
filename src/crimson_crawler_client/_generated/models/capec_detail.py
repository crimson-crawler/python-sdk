from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, BinaryIO, Generator, TextIO, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.capec_detail_skills_required import CAPECDetailSkillsRequired
    from ..models.capec_related_ids import CAPECRelatedIds
    from ..models.cve_reference import CVEReference
    from ..models.revision_entry import RevisionEntry


T = TypeVar("T", bound="CAPECDetail")


@_attrs_define
class CAPECDetail:
    """Common Attack Pattern Enumeration - how a weakness is exploited in practice.

    Attributes:
        capec_id (str): CAPEC identifier (e.g. CAPEC-66)
        abstraction (None | str | Unset): Abstraction level (Meta, Standard, Detailed)
        alternate_terms (list[str] | Unset): The catalogue's own alias list for this pattern (x_capec_alternate_terms)
        can_follow (list[str] | Unset): STIX IDs of attack patterns this one can follow (x_capec_can_follow_refs; 55 of
            600 objects)
        can_precede (list[str] | Unset): STIX IDs of attack patterns this one can precede in a chain
            (x_capec_can_precede_refs; 69 of 600 catalogue objects carry one)
        capec_mitigations (list[str] | Unset): Recommended mitigations from the CAPEC framework, read off the CAPEC
            bundle's own `course-of-action` objects (linked by `mitigates`). Populated on the CAPEC-bundle surfaces
            (`/v1/enrich/capec`, and `/v1/enrich/cwe` when it falls back to a CAPEC bundle); empty when the row was
            normalised from a CVE bundle, which carries no `course-of-action` objects at all.
        child_of (list[str] | Unset): STIX IDs of the parent attack pattern(s) this specialises
        consequences (list[str] | Unset): Potential consequences if this attack pattern succeeds
        deprecated (bool | Unset): Derived from `status`: true for `Deprecated` and `Obsolete`, the two values MITRE
            retires a pattern with (57 of 1,531 objects). Read this or `status` before treating a pattern as current
            Default: False.
        description (None | str | Unset): Detailed attack pattern description
        domains (list[str] | Unset): Applicable domains (e.g. Software, Communications)
        example_instances (list[str] | Unset): Real-world instances of this attack pattern
        execution_flow (None | str | Unset): Step-by-step execution flow for this attack
        extended_description (None | str | Unset): Extended description beyond the summary
        likelihood (None | str | Unset): Attack likelihood: high, medium, or low
        linked_cwes (list[str] | Unset): Related CWE weakness IDs
        linked_techniques (list[str] | Unset): Linked ATT&CK technique IDs
        name (None | str | Unset): Attack pattern name
        parent_of (list[str] | Unset): STIX IDs of attack patterns this one is a parent of
        peer_of (list[str] | Unset): STIX IDs of attack patterns this one is a peer of (x_capec_peer_of_refs; 10 of 600
            objects)
        prerequisites (list[str] | Unset): Prerequisites for executing this attack pattern
        references (list[CVEReference] | Unset): Every other external reference on the pattern — WASC, OWASP Attacks,
            `reference_from_CAPEC` and bibliographic sources — each with its own tag text in `description`. The pattern's
            own CAPEC reference is excluded, along with the CWE and ATT&CK ones `linked_cwes` / `linked_techniques` already
            carry
        related_capec_ids (CAPECRelatedIds | None | Unset): The pattern's own CAPEC-to-CAPEC graph, resolved to CAPEC
            ids. Present on the CAPEC-bundle surfaces (`/v1/enrich/capec`, `/v1/enrich/cwe`); null on rows normalised from a
            CVE bundle, where the referenced objects are not in the payload to resolve against
        resources_required (list[str] | Unset): Resources required to execute this attack
        revision_history (list[RevisionEntry] | Unset): The object's revision history from `/objects/{id}/versions/`.
            Opt-in via include=['versions']; attached to every detail row this response returns — the endpoint's own object
            AND the rows nested in its list layers (search hits, technique-context entries), one deduped cached read per
            distinct object. Zero reads when the token is omitted.
        severity (None | str | Unset): Typical severity: low, medium, high
        skills_required (CAPECDetailSkillsRequired | Unset): Skill level required to execute this attack, keyed by level
            (e.g. {'Low': '...'})
        status (None | str | Unset): CAPEC's own lifecycle status — `Draft`, `Usable`, `Stable`, `Deprecated`,
            `Obsolete` (615 of 1,531 catalogue objects carry one). This is the authoritative lifecycle field: the corpus has
            no `revoked` or `x_mitre_deprecated` key anywhere
        url (None | str | Unset): Reference URL for full CAPEC details
        version (None | str | Unset): MITRE object version (x_capec_version)
    """

    capec_id: str
    abstraction: None | str | Unset = UNSET
    alternate_terms: list[str] | Unset = UNSET
    can_follow: list[str] | Unset = UNSET
    can_precede: list[str] | Unset = UNSET
    capec_mitigations: list[str] | Unset = UNSET
    child_of: list[str] | Unset = UNSET
    consequences: list[str] | Unset = UNSET
    deprecated: bool | Unset = False
    description: None | str | Unset = UNSET
    domains: list[str] | Unset = UNSET
    example_instances: list[str] | Unset = UNSET
    execution_flow: None | str | Unset = UNSET
    extended_description: None | str | Unset = UNSET
    likelihood: None | str | Unset = UNSET
    linked_cwes: list[str] | Unset = UNSET
    linked_techniques: list[str] | Unset = UNSET
    name: None | str | Unset = UNSET
    parent_of: list[str] | Unset = UNSET
    peer_of: list[str] | Unset = UNSET
    prerequisites: list[str] | Unset = UNSET
    references: list[CVEReference] | Unset = UNSET
    related_capec_ids: CAPECRelatedIds | None | Unset = UNSET
    resources_required: list[str] | Unset = UNSET
    revision_history: list[RevisionEntry] | Unset = UNSET
    severity: None | str | Unset = UNSET
    skills_required: CAPECDetailSkillsRequired | Unset = UNSET
    status: None | str | Unset = UNSET
    url: None | str | Unset = UNSET
    version: None | str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        from ..models.capec_detail_skills_required import CAPECDetailSkillsRequired  # noqa: PLC0415
        from ..models.capec_related_ids import CAPECRelatedIds  # noqa: PLC0415
        from ..models.cve_reference import CVEReference  # noqa: PLC0415
        from ..models.revision_entry import RevisionEntry  # noqa: PLC0415

        capec_id = self.capec_id

        abstraction: None | str | Unset
        if isinstance(self.abstraction, Unset):
            abstraction = UNSET
        else:
            abstraction = self.abstraction

        alternate_terms: list[str] | Unset = UNSET
        if not isinstance(self.alternate_terms, Unset):
            alternate_terms = self.alternate_terms

        can_follow: list[str] | Unset = UNSET
        if not isinstance(self.can_follow, Unset):
            can_follow = self.can_follow

        can_precede: list[str] | Unset = UNSET
        if not isinstance(self.can_precede, Unset):
            can_precede = self.can_precede

        capec_mitigations: list[str] | Unset = UNSET
        if not isinstance(self.capec_mitigations, Unset):
            capec_mitigations = self.capec_mitigations

        child_of: list[str] | Unset = UNSET
        if not isinstance(self.child_of, Unset):
            child_of = self.child_of

        consequences: list[str] | Unset = UNSET
        if not isinstance(self.consequences, Unset):
            consequences = self.consequences

        deprecated = self.deprecated

        description: None | str | Unset
        if isinstance(self.description, Unset):
            description = UNSET
        else:
            description = self.description

        domains: list[str] | Unset = UNSET
        if not isinstance(self.domains, Unset):
            domains = self.domains

        example_instances: list[str] | Unset = UNSET
        if not isinstance(self.example_instances, Unset):
            example_instances = self.example_instances

        execution_flow: None | str | Unset
        if isinstance(self.execution_flow, Unset):
            execution_flow = UNSET
        else:
            execution_flow = self.execution_flow

        extended_description: None | str | Unset
        if isinstance(self.extended_description, Unset):
            extended_description = UNSET
        else:
            extended_description = self.extended_description

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

        parent_of: list[str] | Unset = UNSET
        if not isinstance(self.parent_of, Unset):
            parent_of = self.parent_of

        peer_of: list[str] | Unset = UNSET
        if not isinstance(self.peer_of, Unset):
            peer_of = self.peer_of

        prerequisites: list[str] | Unset = UNSET
        if not isinstance(self.prerequisites, Unset):
            prerequisites = self.prerequisites

        references: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.references, Unset):
            references = []
            for references_item_data in self.references:
                references_item = references_item_data.to_dict()
                references.append(references_item)

        related_capec_ids: dict[str, Any] | None | Unset
        if isinstance(self.related_capec_ids, Unset):
            related_capec_ids = UNSET
        elif isinstance(self.related_capec_ids, CAPECRelatedIds):
            related_capec_ids = self.related_capec_ids.to_dict()
        else:
            related_capec_ids = self.related_capec_ids

        resources_required: list[str] | Unset = UNSET
        if not isinstance(self.resources_required, Unset):
            resources_required = self.resources_required

        revision_history: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.revision_history, Unset):
            revision_history = []
            for revision_history_item_data in self.revision_history:
                revision_history_item = revision_history_item_data.to_dict()
                revision_history.append(revision_history_item)

        severity: None | str | Unset
        if isinstance(self.severity, Unset):
            severity = UNSET
        else:
            severity = self.severity

        skills_required: dict[str, Any] | Unset = UNSET
        if not isinstance(self.skills_required, Unset):
            skills_required = self.skills_required.to_dict()

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
        if alternate_terms is not UNSET:
            field_dict["alternate_terms"] = alternate_terms
        if can_follow is not UNSET:
            field_dict["can_follow"] = can_follow
        if can_precede is not UNSET:
            field_dict["can_precede"] = can_precede
        if capec_mitigations is not UNSET:
            field_dict["capec_mitigations"] = capec_mitigations
        if child_of is not UNSET:
            field_dict["child_of"] = child_of
        if consequences is not UNSET:
            field_dict["consequences"] = consequences
        if deprecated is not UNSET:
            field_dict["deprecated"] = deprecated
        if description is not UNSET:
            field_dict["description"] = description
        if domains is not UNSET:
            field_dict["domains"] = domains
        if example_instances is not UNSET:
            field_dict["example_instances"] = example_instances
        if execution_flow is not UNSET:
            field_dict["execution_flow"] = execution_flow
        if extended_description is not UNSET:
            field_dict["extended_description"] = extended_description
        if likelihood is not UNSET:
            field_dict["likelihood"] = likelihood
        if linked_cwes is not UNSET:
            field_dict["linked_cwes"] = linked_cwes
        if linked_techniques is not UNSET:
            field_dict["linked_techniques"] = linked_techniques
        if name is not UNSET:
            field_dict["name"] = name
        if parent_of is not UNSET:
            field_dict["parent_of"] = parent_of
        if peer_of is not UNSET:
            field_dict["peer_of"] = peer_of
        if prerequisites is not UNSET:
            field_dict["prerequisites"] = prerequisites
        if references is not UNSET:
            field_dict["references"] = references
        if related_capec_ids is not UNSET:
            field_dict["related_capec_ids"] = related_capec_ids
        if resources_required is not UNSET:
            field_dict["resources_required"] = resources_required
        if revision_history is not UNSET:
            field_dict["revision_history"] = revision_history
        if severity is not UNSET:
            field_dict["severity"] = severity
        if skills_required is not UNSET:
            field_dict["skills_required"] = skills_required
        if status is not UNSET:
            field_dict["status"] = status
        if url is not UNSET:
            field_dict["url"] = url
        if version is not UNSET:
            field_dict["version"] = version

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.capec_detail_skills_required import CAPECDetailSkillsRequired  # noqa: PLC0415
        from ..models.capec_related_ids import CAPECRelatedIds  # noqa: PLC0415
        from ..models.cve_reference import CVEReference  # noqa: PLC0415
        from ..models.revision_entry import RevisionEntry  # noqa: PLC0415

        d = dict(src_dict)
        capec_id = d.pop("capec_id")

        def _parse_abstraction(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        abstraction = _parse_abstraction(d.pop("abstraction", UNSET))

        alternate_terms = cast(list[str], d.pop("alternate_terms", UNSET))

        can_follow = cast(list[str], d.pop("can_follow", UNSET))

        can_precede = cast(list[str], d.pop("can_precede", UNSET))

        capec_mitigations = cast(list[str], d.pop("capec_mitigations", UNSET))

        child_of = cast(list[str], d.pop("child_of", UNSET))

        consequences = cast(list[str], d.pop("consequences", UNSET))

        deprecated = d.pop("deprecated", UNSET)

        def _parse_description(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        description = _parse_description(d.pop("description", UNSET))

        domains = cast(list[str], d.pop("domains", UNSET))

        example_instances = cast(list[str], d.pop("example_instances", UNSET))

        def _parse_execution_flow(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        execution_flow = _parse_execution_flow(d.pop("execution_flow", UNSET))

        def _parse_extended_description(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        extended_description = _parse_extended_description(d.pop("extended_description", UNSET))

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

        parent_of = cast(list[str], d.pop("parent_of", UNSET))

        peer_of = cast(list[str], d.pop("peer_of", UNSET))

        prerequisites = cast(list[str], d.pop("prerequisites", UNSET))

        _references = d.pop("references", UNSET)
        references: list[CVEReference] | Unset = UNSET
        if _references is not UNSET:
            references = []
            for references_item_data in _references:
                references_item = CVEReference.from_dict(references_item_data)

                references.append(references_item)

        def _parse_related_capec_ids(data: object) -> CAPECRelatedIds | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, dict):
                    raise TypeError()
                related_capec_ids_type_0 = CAPECRelatedIds.from_dict(data)

                return related_capec_ids_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(CAPECRelatedIds | None | Unset, data)

        related_capec_ids = _parse_related_capec_ids(d.pop("related_capec_ids", UNSET))

        resources_required = cast(list[str], d.pop("resources_required", UNSET))

        _revision_history = d.pop("revision_history", UNSET)
        revision_history: list[RevisionEntry] | Unset = UNSET
        if _revision_history is not UNSET:
            revision_history = []
            for revision_history_item_data in _revision_history:
                revision_history_item = RevisionEntry.from_dict(revision_history_item_data)

                revision_history.append(revision_history_item)

        def _parse_severity(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        severity = _parse_severity(d.pop("severity", UNSET))

        _skills_required = d.pop("skills_required", UNSET)
        skills_required: CAPECDetailSkillsRequired | Unset
        if isinstance(_skills_required, Unset):
            skills_required = UNSET
        else:
            skills_required = CAPECDetailSkillsRequired.from_dict(_skills_required)

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
            alternate_terms=alternate_terms,
            can_follow=can_follow,
            can_precede=can_precede,
            capec_mitigations=capec_mitigations,
            child_of=child_of,
            consequences=consequences,
            deprecated=deprecated,
            description=description,
            domains=domains,
            example_instances=example_instances,
            execution_flow=execution_flow,
            extended_description=extended_description,
            likelihood=likelihood,
            linked_cwes=linked_cwes,
            linked_techniques=linked_techniques,
            name=name,
            parent_of=parent_of,
            peer_of=peer_of,
            prerequisites=prerequisites,
            references=references,
            related_capec_ids=related_capec_ids,
            resources_required=resources_required,
            revision_history=revision_history,
            severity=severity,
            skills_required=skills_required,
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

from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, BinaryIO, Generator, TextIO, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.cve_reference import CVEReference
    from ..models.cwe_detail_related_weaknesses_item import CWEDetailRelatedWeaknessesItem
    from ..models.cwe_grouping import CWEGrouping
    from ..models.revision_entry import RevisionEntry


T = TypeVar("T", bound="CWEDetail")


@_attrs_define
class CWEDetail:
    """Common Weakness Enumeration - the root cause vulnerability class.

    Attributes:
        cwe_id (str): CWE identifier (e.g. CWE-79)
        capec_ids (list[str] | Unset): Linked CAPEC attack pattern IDs
        categories (list[CWEGrouping] | Unset): CWE Categories (e.g. 'OWASP Top Ten 2021 Category A01') this weakness is
            a member of, inverse-resolved from the bundle groupings that list it. Populated on CWE-bundle surfaces.
        common_consequences (list[str] | Unset): Consequences of this weakness (CAPEC/CWE catalogue impact text)
        description (None | str | Unset): Detailed weakness description
        detection_methods (list[str] | Unset): CWE detection methodologies (e.g. 'Automated Static Analysis', 'Fuzzing',
            'Manual Analysis'). Carried by about half the CWE corpus.
        is_generic (bool | Unset): True for broad CWE pillars, classes, and placeholder values that do not provide a
            CVE-specific root cause. Technique mappings derived only from a generic CWE can overlap across unrelated CVEs.
            Check `techniques_provenance` or use `techniques_scope=specific` when precision matters more than recall.
            Default: False.
        likelihood_of_exploit (None | str | Unset): MITRE's exploit-likelihood rating for this weakness (e.g. 'High')
        linked_techniques (list[str] | Unset): Directly linked ATT&CK technique IDs
        modes_of_introduction (list[str] | Unset): Ways this weakness is introduced (CWE catalogue)
        name (None | str | Unset): Weakness name (e.g. 'Cross-site Scripting')
        references (list[CVEReference] | Unset): Every other external reference on the weakness — cross-taxonomy
            mappings (CERT C, PLOVER, Software Fault Patterns, ISA/IEC 62443, CLASP, OMG) and bibliographic sources.
            `source` distinguishes them; the object's own CWE reference is excluded.
        related_weaknesses (list[CWEDetailRelatedWeaknessesItem] | Unset): The weakness's own edges to other CWEs
            (`nature` + `cwe_id`), oriented from this weakness's side: `ChildOf` / `ParentOf` for the hierarchy plus every
            other nature the corpus carries (`related-to`, `CanPrecede`, `CanFollow` — `CWE-79` has incoming `CanPrecede`
            rows). Populated on both CWE surfaces: `/v1/enrich/cwe` reads them off the CWE bundle's own relationship
            objects, and `/v1/enrich/cve` resolves them from the weakness's `/objects/{id}/relationships/` rows when `cwe`
            is in `include`.
        revision_history (list[RevisionEntry] | Unset): The object's revision history from `/objects/{id}/versions/`.
            Opt-in via include=['versions']; attached to every detail row this response returns — the endpoint's own object
            AND the rows nested in its list layers (search hits, technique-context entries), one deduped cached read per
            distinct object. Zero reads when the token is omitted.
        revoked (bool | Unset): True if MITRE has revoked this CWE (33 of the 1,352 corpus objects carry it) Default:
            False.
        url (None | str | Unset): Reference URL for full CWE details
        views (list[CWEGrouping] | Unset): CWE Views (e.g. 'Software Development View') this weakness appears in
    """

    cwe_id: str
    capec_ids: list[str] | Unset = UNSET
    categories: list[CWEGrouping] | Unset = UNSET
    common_consequences: list[str] | Unset = UNSET
    description: None | str | Unset = UNSET
    detection_methods: list[str] | Unset = UNSET
    is_generic: bool | Unset = False
    likelihood_of_exploit: None | str | Unset = UNSET
    linked_techniques: list[str] | Unset = UNSET
    modes_of_introduction: list[str] | Unset = UNSET
    name: None | str | Unset = UNSET
    references: list[CVEReference] | Unset = UNSET
    related_weaknesses: list[CWEDetailRelatedWeaknessesItem] | Unset = UNSET
    revision_history: list[RevisionEntry] | Unset = UNSET
    revoked: bool | Unset = False
    url: None | str | Unset = UNSET
    views: list[CWEGrouping] | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        from ..models.cve_reference import CVEReference  # noqa: PLC0415
        from ..models.cwe_detail_related_weaknesses_item import CWEDetailRelatedWeaknessesItem  # noqa: PLC0415
        from ..models.cwe_grouping import CWEGrouping  # noqa: PLC0415
        from ..models.revision_entry import RevisionEntry  # noqa: PLC0415

        cwe_id = self.cwe_id

        capec_ids: list[str] | Unset = UNSET
        if not isinstance(self.capec_ids, Unset):
            capec_ids = self.capec_ids

        categories: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.categories, Unset):
            categories = []
            for categories_item_data in self.categories:
                categories_item = categories_item_data.to_dict()
                categories.append(categories_item)

        common_consequences: list[str] | Unset = UNSET
        if not isinstance(self.common_consequences, Unset):
            common_consequences = self.common_consequences

        description: None | str | Unset
        if isinstance(self.description, Unset):
            description = UNSET
        else:
            description = self.description

        detection_methods: list[str] | Unset = UNSET
        if not isinstance(self.detection_methods, Unset):
            detection_methods = self.detection_methods

        is_generic = self.is_generic

        likelihood_of_exploit: None | str | Unset
        if isinstance(self.likelihood_of_exploit, Unset):
            likelihood_of_exploit = UNSET
        else:
            likelihood_of_exploit = self.likelihood_of_exploit

        linked_techniques: list[str] | Unset = UNSET
        if not isinstance(self.linked_techniques, Unset):
            linked_techniques = self.linked_techniques

        modes_of_introduction: list[str] | Unset = UNSET
        if not isinstance(self.modes_of_introduction, Unset):
            modes_of_introduction = self.modes_of_introduction

        name: None | str | Unset
        if isinstance(self.name, Unset):
            name = UNSET
        else:
            name = self.name

        references: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.references, Unset):
            references = []
            for references_item_data in self.references:
                references_item = references_item_data.to_dict()
                references.append(references_item)

        related_weaknesses: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.related_weaknesses, Unset):
            related_weaknesses = []
            for related_weaknesses_item_data in self.related_weaknesses:
                related_weaknesses_item = related_weaknesses_item_data.to_dict()
                related_weaknesses.append(related_weaknesses_item)

        revision_history: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.revision_history, Unset):
            revision_history = []
            for revision_history_item_data in self.revision_history:
                revision_history_item = revision_history_item_data.to_dict()
                revision_history.append(revision_history_item)

        revoked = self.revoked

        url: None | str | Unset
        if isinstance(self.url, Unset):
            url = UNSET
        else:
            url = self.url

        views: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.views, Unset):
            views = []
            for views_item_data in self.views:
                views_item = views_item_data.to_dict()
                views.append(views_item)

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "cwe_id": cwe_id,
            }
        )
        if capec_ids is not UNSET:
            field_dict["capec_ids"] = capec_ids
        if categories is not UNSET:
            field_dict["categories"] = categories
        if common_consequences is not UNSET:
            field_dict["common_consequences"] = common_consequences
        if description is not UNSET:
            field_dict["description"] = description
        if detection_methods is not UNSET:
            field_dict["detection_methods"] = detection_methods
        if is_generic is not UNSET:
            field_dict["is_generic"] = is_generic
        if likelihood_of_exploit is not UNSET:
            field_dict["likelihood_of_exploit"] = likelihood_of_exploit
        if linked_techniques is not UNSET:
            field_dict["linked_techniques"] = linked_techniques
        if modes_of_introduction is not UNSET:
            field_dict["modes_of_introduction"] = modes_of_introduction
        if name is not UNSET:
            field_dict["name"] = name
        if references is not UNSET:
            field_dict["references"] = references
        if related_weaknesses is not UNSET:
            field_dict["related_weaknesses"] = related_weaknesses
        if revision_history is not UNSET:
            field_dict["revision_history"] = revision_history
        if revoked is not UNSET:
            field_dict["revoked"] = revoked
        if url is not UNSET:
            field_dict["url"] = url
        if views is not UNSET:
            field_dict["views"] = views

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.cve_reference import CVEReference  # noqa: PLC0415
        from ..models.cwe_detail_related_weaknesses_item import CWEDetailRelatedWeaknessesItem  # noqa: PLC0415
        from ..models.cwe_grouping import CWEGrouping  # noqa: PLC0415
        from ..models.revision_entry import RevisionEntry  # noqa: PLC0415

        d = dict(src_dict)
        cwe_id = d.pop("cwe_id")

        capec_ids = cast(list[str], d.pop("capec_ids", UNSET))

        _categories = d.pop("categories", UNSET)
        categories: list[CWEGrouping] | Unset = UNSET
        if _categories is not UNSET:
            categories = []
            for categories_item_data in _categories:
                categories_item = CWEGrouping.from_dict(categories_item_data)

                categories.append(categories_item)

        common_consequences = cast(list[str], d.pop("common_consequences", UNSET))

        def _parse_description(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        description = _parse_description(d.pop("description", UNSET))

        detection_methods = cast(list[str], d.pop("detection_methods", UNSET))

        is_generic = d.pop("is_generic", UNSET)

        def _parse_likelihood_of_exploit(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        likelihood_of_exploit = _parse_likelihood_of_exploit(d.pop("likelihood_of_exploit", UNSET))

        linked_techniques = cast(list[str], d.pop("linked_techniques", UNSET))

        modes_of_introduction = cast(list[str], d.pop("modes_of_introduction", UNSET))

        def _parse_name(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        name = _parse_name(d.pop("name", UNSET))

        _references = d.pop("references", UNSET)
        references: list[CVEReference] | Unset = UNSET
        if _references is not UNSET:
            references = []
            for references_item_data in _references:
                references_item = CVEReference.from_dict(references_item_data)

                references.append(references_item)

        _related_weaknesses = d.pop("related_weaknesses", UNSET)
        related_weaknesses: list[CWEDetailRelatedWeaknessesItem] | Unset = UNSET
        if _related_weaknesses is not UNSET:
            related_weaknesses = []
            for related_weaknesses_item_data in _related_weaknesses:
                related_weaknesses_item = CWEDetailRelatedWeaknessesItem.from_dict(related_weaknesses_item_data)

                related_weaknesses.append(related_weaknesses_item)

        _revision_history = d.pop("revision_history", UNSET)
        revision_history: list[RevisionEntry] | Unset = UNSET
        if _revision_history is not UNSET:
            revision_history = []
            for revision_history_item_data in _revision_history:
                revision_history_item = RevisionEntry.from_dict(revision_history_item_data)

                revision_history.append(revision_history_item)

        revoked = d.pop("revoked", UNSET)

        def _parse_url(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        url = _parse_url(d.pop("url", UNSET))

        _views = d.pop("views", UNSET)
        views: list[CWEGrouping] | Unset = UNSET
        if _views is not UNSET:
            views = []
            for views_item_data in _views:
                views_item = CWEGrouping.from_dict(views_item_data)

                views.append(views_item)

        cwe_detail = cls(
            cwe_id=cwe_id,
            capec_ids=capec_ids,
            categories=categories,
            common_consequences=common_consequences,
            description=description,
            detection_methods=detection_methods,
            is_generic=is_generic,
            likelihood_of_exploit=likelihood_of_exploit,
            linked_techniques=linked_techniques,
            modes_of_introduction=modes_of_introduction,
            name=name,
            references=references,
            related_weaknesses=related_weaknesses,
            revision_history=revision_history,
            revoked=revoked,
            url=url,
            views=views,
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

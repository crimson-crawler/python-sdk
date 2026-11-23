from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, BinaryIO, Generator, TextIO, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.revision_entry import RevisionEntry


T = TypeVar("T", bound="FrameworkObjectDetail")


@_attrs_define
class FrameworkObjectDetail:
    """Homogeneous view of a knowledge-base object from a heterogeneous STIX corpus.

    F3 and CLOAK both hold a mix of STIX types behind one id space (attack-pattern,
    x-mitre-tactic, x-mitre-matrix, tool), and each type carries its identity, kill chain,
    and link differently — so both surfaces share this one flat shape instead of exposing
    the underlying type-specific normalisation.

        Attributes:
            category (None | str | Unset): Framework classification carried on its own external reference (CLOAK: Technical
                / Behavioral / Physical)
            contributors (list[str] | Unset): Contributors credited on the object (x_mitre_contributors)
            created (None | str | Unset): When MITRE first created this object (ISO 8601)
            deprecated (bool | Unset): True if the framework marked this object deprecated Default: False.
            description (str | Unset): Object description Default: ''.
            is_subtechnique (bool | Unset): Whether this is a nested sub-technique Default: False.
            modified (None | str | Unset): When MITRE last revised this object (ISO 8601) — ATT&CK ships monthly
            name (str | Unset): Object name Default: ''.
            object_id (str | Unset): Framework ID from the object's external reference (e.g. `F1031`, `TTP-496`) Default:
                ''.
            object_marking_refs (list[str] | Unset): STIX marking-definition ids applied to this object (licence/terms)
            object_type (str | Unset): STIX object type (attack-pattern, x-mitre-tactic, tool, ...) Default: ''.
            parent_technique_id (None | str | Unset): For a sub-technique row: the id of the object it specialises. Read
                from the corpus's own `subtechnique-of` edge, so a CLOAK sub-technique is no longer a row with no family
            platforms (list[str] | Unset): Platforms the object applies to (x_mitre_platforms; carried by 123 of 132 F3
                objects)
            revision_history (list[RevisionEntry] | Unset): The object's revision history from `/objects/{id}/versions/`.
                Opt-in via include=['versions']; attached to every detail row this response returns — the endpoint's own object
                AND the rows nested in its list layers (search hits, technique-context entries), one deduped cached read per
                distinct object. Zero reads when the token is omitted.
            revoked (bool | Unset): True if the framework marked this object revoked Default: False.
            spec_version (None | str | Unset): STIX spec revision the record was normalised under
                (x_mitre_attack_spec_version, else spec_version)
            stix_id (str | Unset): STIX ID Default: ''.
            subtechnique_ids (list[str] | Unset): Ids of the sub-techniques this object declares (`subtechnique-of` edges
                pointing here)
            tactic_refs (list[str] | Unset): Matrix rows only: the ORDERED STIX ids of the tactic columns this matrix
                declares (tactic_refs) — the corpus's own statement of matrix order
            tactic_shortname (None | str | Unset): Shortname of the tactic this row belongs to (x_mitre_shortname)
            tactics (list[str] | Unset): Kill-chain phase names
            technique_ids (list[str] | Unset): Ids of the objects this one is `related-to` — the directed half of the
                framework graph, which the CLOAK/F3 corpora carry (880 and 169 edges) and no field exposed
            tool_ids (list[str] | Unset): Attack-pattern rows only: the framework's OWN tool ids this technique `uses`
                (CLOAK carries 691 such edges across 140 techniques, e.g. 'TTP-2812'). Never a name guess and never another
                corpus's software id
            tool_types (list[str] | Unset): CLOAK tool rows only: the tool's type(s), e.g. ['remote-access'] (317 of 400
                objects)
            url (str | Unset): Source URL from the framework's external reference Default: ''.
            version (None | str | Unset): The framework corpus revision this object came from (x_mitre_version) — the only
                provenance key an F3/CLOAK object carries that a consumer can date its snapshot by
    """

    category: None | str | Unset = UNSET
    contributors: list[str] | Unset = UNSET
    created: None | str | Unset = UNSET
    deprecated: bool | Unset = False
    description: str | Unset = ""
    is_subtechnique: bool | Unset = False
    modified: None | str | Unset = UNSET
    name: str | Unset = ""
    object_id: str | Unset = ""
    object_marking_refs: list[str] | Unset = UNSET
    object_type: str | Unset = ""
    parent_technique_id: None | str | Unset = UNSET
    platforms: list[str] | Unset = UNSET
    revision_history: list[RevisionEntry] | Unset = UNSET
    revoked: bool | Unset = False
    spec_version: None | str | Unset = UNSET
    stix_id: str | Unset = ""
    subtechnique_ids: list[str] | Unset = UNSET
    tactic_refs: list[str] | Unset = UNSET
    tactic_shortname: None | str | Unset = UNSET
    tactics: list[str] | Unset = UNSET
    technique_ids: list[str] | Unset = UNSET
    tool_ids: list[str] | Unset = UNSET
    tool_types: list[str] | Unset = UNSET
    url: str | Unset = ""
    version: None | str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        from ..models.revision_entry import RevisionEntry  # noqa: PLC0415

        category: None | str | Unset
        if isinstance(self.category, Unset):
            category = UNSET
        else:
            category = self.category

        contributors: list[str] | Unset = UNSET
        if not isinstance(self.contributors, Unset):
            contributors = self.contributors

        created: None | str | Unset
        if isinstance(self.created, Unset):
            created = UNSET
        else:
            created = self.created

        deprecated = self.deprecated

        description = self.description

        is_subtechnique = self.is_subtechnique

        modified: None | str | Unset
        if isinstance(self.modified, Unset):
            modified = UNSET
        else:
            modified = self.modified

        name = self.name

        object_id = self.object_id

        object_marking_refs: list[str] | Unset = UNSET
        if not isinstance(self.object_marking_refs, Unset):
            object_marking_refs = self.object_marking_refs

        object_type = self.object_type

        parent_technique_id: None | str | Unset
        if isinstance(self.parent_technique_id, Unset):
            parent_technique_id = UNSET
        else:
            parent_technique_id = self.parent_technique_id

        platforms: list[str] | Unset = UNSET
        if not isinstance(self.platforms, Unset):
            platforms = self.platforms

        revision_history: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.revision_history, Unset):
            revision_history = []
            for revision_history_item_data in self.revision_history:
                revision_history_item = revision_history_item_data.to_dict()
                revision_history.append(revision_history_item)

        revoked = self.revoked

        spec_version: None | str | Unset
        if isinstance(self.spec_version, Unset):
            spec_version = UNSET
        else:
            spec_version = self.spec_version

        stix_id = self.stix_id

        subtechnique_ids: list[str] | Unset = UNSET
        if not isinstance(self.subtechnique_ids, Unset):
            subtechnique_ids = self.subtechnique_ids

        tactic_refs: list[str] | Unset = UNSET
        if not isinstance(self.tactic_refs, Unset):
            tactic_refs = self.tactic_refs

        tactic_shortname: None | str | Unset
        if isinstance(self.tactic_shortname, Unset):
            tactic_shortname = UNSET
        else:
            tactic_shortname = self.tactic_shortname

        tactics: list[str] | Unset = UNSET
        if not isinstance(self.tactics, Unset):
            tactics = self.tactics

        technique_ids: list[str] | Unset = UNSET
        if not isinstance(self.technique_ids, Unset):
            technique_ids = self.technique_ids

        tool_ids: list[str] | Unset = UNSET
        if not isinstance(self.tool_ids, Unset):
            tool_ids = self.tool_ids

        tool_types: list[str] | Unset = UNSET
        if not isinstance(self.tool_types, Unset):
            tool_types = self.tool_types

        url = self.url

        version: None | str | Unset
        if isinstance(self.version, Unset):
            version = UNSET
        else:
            version = self.version

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if category is not UNSET:
            field_dict["category"] = category
        if contributors is not UNSET:
            field_dict["contributors"] = contributors
        if created is not UNSET:
            field_dict["created"] = created
        if deprecated is not UNSET:
            field_dict["deprecated"] = deprecated
        if description is not UNSET:
            field_dict["description"] = description
        if is_subtechnique is not UNSET:
            field_dict["is_subtechnique"] = is_subtechnique
        if modified is not UNSET:
            field_dict["modified"] = modified
        if name is not UNSET:
            field_dict["name"] = name
        if object_id is not UNSET:
            field_dict["object_id"] = object_id
        if object_marking_refs is not UNSET:
            field_dict["object_marking_refs"] = object_marking_refs
        if object_type is not UNSET:
            field_dict["object_type"] = object_type
        if parent_technique_id is not UNSET:
            field_dict["parent_technique_id"] = parent_technique_id
        if platforms is not UNSET:
            field_dict["platforms"] = platforms
        if revision_history is not UNSET:
            field_dict["revision_history"] = revision_history
        if revoked is not UNSET:
            field_dict["revoked"] = revoked
        if spec_version is not UNSET:
            field_dict["spec_version"] = spec_version
        if stix_id is not UNSET:
            field_dict["stix_id"] = stix_id
        if subtechnique_ids is not UNSET:
            field_dict["subtechnique_ids"] = subtechnique_ids
        if tactic_refs is not UNSET:
            field_dict["tactic_refs"] = tactic_refs
        if tactic_shortname is not UNSET:
            field_dict["tactic_shortname"] = tactic_shortname
        if tactics is not UNSET:
            field_dict["tactics"] = tactics
        if technique_ids is not UNSET:
            field_dict["technique_ids"] = technique_ids
        if tool_ids is not UNSET:
            field_dict["tool_ids"] = tool_ids
        if tool_types is not UNSET:
            field_dict["tool_types"] = tool_types
        if url is not UNSET:
            field_dict["url"] = url
        if version is not UNSET:
            field_dict["version"] = version

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.revision_entry import RevisionEntry  # noqa: PLC0415

        d = dict(src_dict)

        def _parse_category(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        category = _parse_category(d.pop("category", UNSET))

        contributors = cast(list[str], d.pop("contributors", UNSET))

        def _parse_created(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        created = _parse_created(d.pop("created", UNSET))

        deprecated = d.pop("deprecated", UNSET)

        description = d.pop("description", UNSET)

        is_subtechnique = d.pop("is_subtechnique", UNSET)

        def _parse_modified(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        modified = _parse_modified(d.pop("modified", UNSET))

        name = d.pop("name", UNSET)

        object_id = d.pop("object_id", UNSET)

        object_marking_refs = cast(list[str], d.pop("object_marking_refs", UNSET))

        object_type = d.pop("object_type", UNSET)

        def _parse_parent_technique_id(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        parent_technique_id = _parse_parent_technique_id(d.pop("parent_technique_id", UNSET))

        platforms = cast(list[str], d.pop("platforms", UNSET))

        _revision_history = d.pop("revision_history", UNSET)
        revision_history: list[RevisionEntry] | Unset = UNSET
        if _revision_history is not UNSET:
            revision_history = []
            for revision_history_item_data in _revision_history:
                revision_history_item = RevisionEntry.from_dict(revision_history_item_data)

                revision_history.append(revision_history_item)

        revoked = d.pop("revoked", UNSET)

        def _parse_spec_version(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        spec_version = _parse_spec_version(d.pop("spec_version", UNSET))

        stix_id = d.pop("stix_id", UNSET)

        subtechnique_ids = cast(list[str], d.pop("subtechnique_ids", UNSET))

        tactic_refs = cast(list[str], d.pop("tactic_refs", UNSET))

        def _parse_tactic_shortname(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        tactic_shortname = _parse_tactic_shortname(d.pop("tactic_shortname", UNSET))

        tactics = cast(list[str], d.pop("tactics", UNSET))

        technique_ids = cast(list[str], d.pop("technique_ids", UNSET))

        tool_ids = cast(list[str], d.pop("tool_ids", UNSET))

        tool_types = cast(list[str], d.pop("tool_types", UNSET))

        url = d.pop("url", UNSET)

        def _parse_version(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        version = _parse_version(d.pop("version", UNSET))

        framework_object_detail = cls(
            category=category,
            contributors=contributors,
            created=created,
            deprecated=deprecated,
            description=description,
            is_subtechnique=is_subtechnique,
            modified=modified,
            name=name,
            object_id=object_id,
            object_marking_refs=object_marking_refs,
            object_type=object_type,
            parent_technique_id=parent_technique_id,
            platforms=platforms,
            revision_history=revision_history,
            revoked=revoked,
            spec_version=spec_version,
            stix_id=stix_id,
            subtechnique_ids=subtechnique_ids,
            tactic_refs=tactic_refs,
            tactic_shortname=tactic_shortname,
            tactics=tactics,
            technique_ids=technique_ids,
            tool_ids=tool_ids,
            tool_types=tool_types,
            url=url,
            version=version,
        )

        framework_object_detail.additional_properties = d
        return framework_object_detail

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

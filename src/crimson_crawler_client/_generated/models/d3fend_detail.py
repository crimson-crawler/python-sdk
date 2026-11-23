from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, BinaryIO, Generator, TextIO, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.revision_entry import RevisionEntry


T = TypeVar("T", bound="D3FENDDetail")


@_attrs_define
class D3FENDDetail:
    """D3FEND defensive technique or countermeasure.

    Attributes:
        aliases (list[str] | Unset): Alternate names D3FEND has published for this technique (e.g. 'Firmware Timing
            Analysis' for 'Firmware Behavior Analysis'). Present on 148 of the 519 `course-of-action` objects in the D3FEND
            corpus; no other object type carries one.
        created (None | str | Unset): When MITRE first created this object (ISO 8601)
        d3fend_form (None | str | Unset): D3FEND form: tactic, mitigation, sub-mitigation, artifact
        d3fend_id (str | Unset): D3FEND identifier (e.g. D3-AL) Default: ''.
        deprecated (bool | Unset): True if MITRE marked this object deprecated (x_mitre_deprecated) Default: False.
        description (None | str | Unset): What this countermeasure does
        domains (list[str] | Unset): ATT&CK domain(s) this object's technique mappings are keyed to (x_mitre_domains),
            e.g. ['enterprise-attack']
        indicator_types (list[str] | Unset): Artifact rows only: D3FEND indicator types carried by the object (e.g.
            ['unknown'])
        modified (None | str | Unset): When MITRE last revised this object (ISO 8601)
        name (None | str | Unset): Defensive technique name
        object_marking_refs (list[str] | Unset): STIX marking-definition ids applied to this object (licence/terms)
        pattern (None | str | Unset): Artifact rows only: the d3f pattern naming the artifact (e.g. 'd3f:Compiler').
            Every D3FEND artifact object carries one.
        pattern_type (None | str | Unset): Artifact rows only: pattern vocabulary (always 'd3fend')
        revision_history (list[RevisionEntry] | Unset): The object's revision history from `/objects/{id}/versions/`.
            Opt-in via include=['versions']; attached to every detail row this response returns — the endpoint's own object
            AND the rows nested in its list layers (search hits, technique-context entries), one deduped cached read per
            distinct object. Zero reads when the token is omitted.
        spec_version (None | str | Unset): STIX spec revision the record was normalised under
            (x_mitre_attack_spec_version, else spec_version)
        stix_id (None | str | Unset): Unique object identifier for cross-referencing
        tactic_shortname (None | str | Unset): Tactic rows only: the D3FEND tactic's own shortname
            (`x_mitre_shortname`), the key downstream joins use (e.g. 'model', 'harden')
        url (None | str | Unset): Reference URL
        valid_from (None | str | Unset): Artifact rows only: when the indicator definition became valid (ISO 8601)
        version (None | str | Unset): MITRE object version (x_mitre_version)
    """

    aliases: list[str] | Unset = UNSET
    created: None | str | Unset = UNSET
    d3fend_form: None | str | Unset = UNSET
    d3fend_id: str | Unset = ""
    deprecated: bool | Unset = False
    description: None | str | Unset = UNSET
    domains: list[str] | Unset = UNSET
    indicator_types: list[str] | Unset = UNSET
    modified: None | str | Unset = UNSET
    name: None | str | Unset = UNSET
    object_marking_refs: list[str] | Unset = UNSET
    pattern: None | str | Unset = UNSET
    pattern_type: None | str | Unset = UNSET
    revision_history: list[RevisionEntry] | Unset = UNSET
    spec_version: None | str | Unset = UNSET
    stix_id: None | str | Unset = UNSET
    tactic_shortname: None | str | Unset = UNSET
    url: None | str | Unset = UNSET
    valid_from: None | str | Unset = UNSET
    version: None | str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        from ..models.revision_entry import RevisionEntry  # noqa: PLC0415

        aliases: list[str] | Unset = UNSET
        if not isinstance(self.aliases, Unset):
            aliases = self.aliases

        created: None | str | Unset
        if isinstance(self.created, Unset):
            created = UNSET
        else:
            created = self.created

        d3fend_form: None | str | Unset
        if isinstance(self.d3fend_form, Unset):
            d3fend_form = UNSET
        else:
            d3fend_form = self.d3fend_form

        d3fend_id = self.d3fend_id

        deprecated = self.deprecated

        description: None | str | Unset
        if isinstance(self.description, Unset):
            description = UNSET
        else:
            description = self.description

        domains: list[str] | Unset = UNSET
        if not isinstance(self.domains, Unset):
            domains = self.domains

        indicator_types: list[str] | Unset = UNSET
        if not isinstance(self.indicator_types, Unset):
            indicator_types = self.indicator_types

        modified: None | str | Unset
        if isinstance(self.modified, Unset):
            modified = UNSET
        else:
            modified = self.modified

        name: None | str | Unset
        if isinstance(self.name, Unset):
            name = UNSET
        else:
            name = self.name

        object_marking_refs: list[str] | Unset = UNSET
        if not isinstance(self.object_marking_refs, Unset):
            object_marking_refs = self.object_marking_refs

        pattern: None | str | Unset
        if isinstance(self.pattern, Unset):
            pattern = UNSET
        else:
            pattern = self.pattern

        pattern_type: None | str | Unset
        if isinstance(self.pattern_type, Unset):
            pattern_type = UNSET
        else:
            pattern_type = self.pattern_type

        revision_history: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.revision_history, Unset):
            revision_history = []
            for revision_history_item_data in self.revision_history:
                revision_history_item = revision_history_item_data.to_dict()
                revision_history.append(revision_history_item)

        spec_version: None | str | Unset
        if isinstance(self.spec_version, Unset):
            spec_version = UNSET
        else:
            spec_version = self.spec_version

        stix_id: None | str | Unset
        if isinstance(self.stix_id, Unset):
            stix_id = UNSET
        else:
            stix_id = self.stix_id

        tactic_shortname: None | str | Unset
        if isinstance(self.tactic_shortname, Unset):
            tactic_shortname = UNSET
        else:
            tactic_shortname = self.tactic_shortname

        url: None | str | Unset
        if isinstance(self.url, Unset):
            url = UNSET
        else:
            url = self.url

        valid_from: None | str | Unset
        if isinstance(self.valid_from, Unset):
            valid_from = UNSET
        else:
            valid_from = self.valid_from

        version: None | str | Unset
        if isinstance(self.version, Unset):
            version = UNSET
        else:
            version = self.version

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if aliases is not UNSET:
            field_dict["aliases"] = aliases
        if created is not UNSET:
            field_dict["created"] = created
        if d3fend_form is not UNSET:
            field_dict["d3fend_form"] = d3fend_form
        if d3fend_id is not UNSET:
            field_dict["d3fend_id"] = d3fend_id
        if deprecated is not UNSET:
            field_dict["deprecated"] = deprecated
        if description is not UNSET:
            field_dict["description"] = description
        if domains is not UNSET:
            field_dict["domains"] = domains
        if indicator_types is not UNSET:
            field_dict["indicator_types"] = indicator_types
        if modified is not UNSET:
            field_dict["modified"] = modified
        if name is not UNSET:
            field_dict["name"] = name
        if object_marking_refs is not UNSET:
            field_dict["object_marking_refs"] = object_marking_refs
        if pattern is not UNSET:
            field_dict["pattern"] = pattern
        if pattern_type is not UNSET:
            field_dict["pattern_type"] = pattern_type
        if revision_history is not UNSET:
            field_dict["revision_history"] = revision_history
        if spec_version is not UNSET:
            field_dict["spec_version"] = spec_version
        if stix_id is not UNSET:
            field_dict["stix_id"] = stix_id
        if tactic_shortname is not UNSET:
            field_dict["tactic_shortname"] = tactic_shortname
        if url is not UNSET:
            field_dict["url"] = url
        if valid_from is not UNSET:
            field_dict["valid_from"] = valid_from
        if version is not UNSET:
            field_dict["version"] = version

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.revision_entry import RevisionEntry  # noqa: PLC0415

        d = dict(src_dict)
        aliases = cast(list[str], d.pop("aliases", UNSET))

        def _parse_created(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        created = _parse_created(d.pop("created", UNSET))

        def _parse_d3fend_form(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        d3fend_form = _parse_d3fend_form(d.pop("d3fend_form", UNSET))

        d3fend_id = d.pop("d3fend_id", UNSET)

        deprecated = d.pop("deprecated", UNSET)

        def _parse_description(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        description = _parse_description(d.pop("description", UNSET))

        domains = cast(list[str], d.pop("domains", UNSET))

        indicator_types = cast(list[str], d.pop("indicator_types", UNSET))

        def _parse_modified(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        modified = _parse_modified(d.pop("modified", UNSET))

        def _parse_name(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        name = _parse_name(d.pop("name", UNSET))

        object_marking_refs = cast(list[str], d.pop("object_marking_refs", UNSET))

        def _parse_pattern(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        pattern = _parse_pattern(d.pop("pattern", UNSET))

        def _parse_pattern_type(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        pattern_type = _parse_pattern_type(d.pop("pattern_type", UNSET))

        _revision_history = d.pop("revision_history", UNSET)
        revision_history: list[RevisionEntry] | Unset = UNSET
        if _revision_history is not UNSET:
            revision_history = []
            for revision_history_item_data in _revision_history:
                revision_history_item = RevisionEntry.from_dict(revision_history_item_data)

                revision_history.append(revision_history_item)

        def _parse_spec_version(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        spec_version = _parse_spec_version(d.pop("spec_version", UNSET))

        def _parse_stix_id(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        stix_id = _parse_stix_id(d.pop("stix_id", UNSET))

        def _parse_tactic_shortname(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        tactic_shortname = _parse_tactic_shortname(d.pop("tactic_shortname", UNSET))

        def _parse_url(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        url = _parse_url(d.pop("url", UNSET))

        def _parse_valid_from(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        valid_from = _parse_valid_from(d.pop("valid_from", UNSET))

        def _parse_version(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        version = _parse_version(d.pop("version", UNSET))

        d3fend_detail = cls(
            aliases=aliases,
            created=created,
            d3fend_form=d3fend_form,
            d3fend_id=d3fend_id,
            deprecated=deprecated,
            description=description,
            domains=domains,
            indicator_types=indicator_types,
            modified=modified,
            name=name,
            object_marking_refs=object_marking_refs,
            pattern=pattern,
            pattern_type=pattern_type,
            revision_history=revision_history,
            spec_version=spec_version,
            stix_id=stix_id,
            tactic_shortname=tactic_shortname,
            url=url,
            valid_from=valid_from,
            version=version,
        )

        d3fend_detail.additional_properties = d
        return d3fend_detail

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

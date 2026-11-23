from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, BinaryIO, Generator, TextIO, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.revision_entry import RevisionEntry
    from ..models.technique_detail import TechniqueDetail


T = TypeVar("T", bound="SoftwareDetail")


@_attrs_define
class SoftwareDetail:
    """Malware or tool profile with techniques and associated threat groups.

    Attributes:
        software_id (str): ATT&CK software ID (e.g. S0154)
        aliases (list[str] | Unset): Alternative names
        capabilities (list[str] | Unset): STIX malware capabilities (e.g. 'persistence', 'exfiltration'); empty for tool
            objects
        contributors (list[str] | Unset): Contributors listed in x_mitre_contributors
        created (None | str | Unset): When MITRE first created this object (ISO 8601)
        deprecated (bool | Unset): True if MITRE marked this software deprecated Default: False.
        description (None | str | Unset): Software description and capabilities
        domains (list[str] | Unset): ATT&CK matrix/matrices this object comes from (enterprise-attack, ics-attack,
            mobile-attack)
        groups (list[str] | Unset): Threat groups known to use this software
        modified (None | str | Unset): When MITRE last revised this object (ISO 8601) — ATT&CK ships monthly
        name (None | str | Unset): Software name (e.g. 'Cobalt Strike')
        object_marking_refs (list[str] | Unset): STIX marking-definition ids applied to this object (licence/terms)
        platforms (list[str] | Unset): Targeted platforms
        revision_history (list[RevisionEntry] | Unset): The object's revision history from `/objects/{id}/versions/`.
            Opt-in via include=['versions']; attached to every detail row this response returns — the endpoint's own object
            AND the rows nested in its list layers (search hits, technique-context entries), one deduped cached read per
            distinct object. Zero reads when the token is omitted.
        revoked (bool | Unset): True if MITRE has revoked this software Default: False.
        software_type (None | str | Unset): Type: malware or tool
        spec_version (None | str | Unset): STIX spec revision the record was normalised under
            (x_mitre_attack_spec_version, else spec_version)
        techniques (list[str | TechniqueDetail] | Unset): ATT&CK techniques associated with this software
        url (None | str | Unset): Reference URL for full software details
        version (None | str | Unset): MITRE object version (x_mitre_version)
    """

    software_id: str
    aliases: list[str] | Unset = UNSET
    capabilities: list[str] | Unset = UNSET
    contributors: list[str] | Unset = UNSET
    created: None | str | Unset = UNSET
    deprecated: bool | Unset = False
    description: None | str | Unset = UNSET
    domains: list[str] | Unset = UNSET
    groups: list[str] | Unset = UNSET
    modified: None | str | Unset = UNSET
    name: None | str | Unset = UNSET
    object_marking_refs: list[str] | Unset = UNSET
    platforms: list[str] | Unset = UNSET
    revision_history: list[RevisionEntry] | Unset = UNSET
    revoked: bool | Unset = False
    software_type: None | str | Unset = UNSET
    spec_version: None | str | Unset = UNSET
    techniques: list[str | TechniqueDetail] | Unset = UNSET
    url: None | str | Unset = UNSET
    version: None | str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        from ..models.revision_entry import RevisionEntry  # noqa: PLC0415
        from ..models.technique_detail import TechniqueDetail  # noqa: PLC0415

        software_id = self.software_id

        aliases: list[str] | Unset = UNSET
        if not isinstance(self.aliases, Unset):
            aliases = self.aliases

        capabilities: list[str] | Unset = UNSET
        if not isinstance(self.capabilities, Unset):
            capabilities = self.capabilities

        contributors: list[str] | Unset = UNSET
        if not isinstance(self.contributors, Unset):
            contributors = self.contributors

        created: None | str | Unset
        if isinstance(self.created, Unset):
            created = UNSET
        else:
            created = self.created

        deprecated = self.deprecated

        description: None | str | Unset
        if isinstance(self.description, Unset):
            description = UNSET
        else:
            description = self.description

        domains: list[str] | Unset = UNSET
        if not isinstance(self.domains, Unset):
            domains = self.domains

        groups: list[str] | Unset = UNSET
        if not isinstance(self.groups, Unset):
            groups = self.groups

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

        software_type: None | str | Unset
        if isinstance(self.software_type, Unset):
            software_type = UNSET
        else:
            software_type = self.software_type

        spec_version: None | str | Unset
        if isinstance(self.spec_version, Unset):
            spec_version = UNSET
        else:
            spec_version = self.spec_version

        techniques: list[dict[str, Any] | str] | Unset = UNSET
        if not isinstance(self.techniques, Unset):
            techniques = []
            for techniques_item_data in self.techniques:
                techniques_item: dict[str, Any] | str
                if isinstance(techniques_item_data, TechniqueDetail):
                    techniques_item = techniques_item_data.to_dict()
                else:
                    techniques_item = techniques_item_data
                techniques.append(techniques_item)

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
                "software_id": software_id,
            }
        )
        if aliases is not UNSET:
            field_dict["aliases"] = aliases
        if capabilities is not UNSET:
            field_dict["capabilities"] = capabilities
        if contributors is not UNSET:
            field_dict["contributors"] = contributors
        if created is not UNSET:
            field_dict["created"] = created
        if deprecated is not UNSET:
            field_dict["deprecated"] = deprecated
        if description is not UNSET:
            field_dict["description"] = description
        if domains is not UNSET:
            field_dict["domains"] = domains
        if groups is not UNSET:
            field_dict["groups"] = groups
        if modified is not UNSET:
            field_dict["modified"] = modified
        if name is not UNSET:
            field_dict["name"] = name
        if object_marking_refs is not UNSET:
            field_dict["object_marking_refs"] = object_marking_refs
        if platforms is not UNSET:
            field_dict["platforms"] = platforms
        if revision_history is not UNSET:
            field_dict["revision_history"] = revision_history
        if revoked is not UNSET:
            field_dict["revoked"] = revoked
        if software_type is not UNSET:
            field_dict["software_type"] = software_type
        if spec_version is not UNSET:
            field_dict["spec_version"] = spec_version
        if techniques is not UNSET:
            field_dict["techniques"] = techniques
        if url is not UNSET:
            field_dict["url"] = url
        if version is not UNSET:
            field_dict["version"] = version

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.revision_entry import RevisionEntry  # noqa: PLC0415
        from ..models.technique_detail import TechniqueDetail  # noqa: PLC0415

        d = dict(src_dict)
        software_id = d.pop("software_id")

        aliases = cast(list[str], d.pop("aliases", UNSET))

        capabilities = cast(list[str], d.pop("capabilities", UNSET))

        contributors = cast(list[str], d.pop("contributors", UNSET))

        def _parse_created(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        created = _parse_created(d.pop("created", UNSET))

        deprecated = d.pop("deprecated", UNSET)

        def _parse_description(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        description = _parse_description(d.pop("description", UNSET))

        domains = cast(list[str], d.pop("domains", UNSET))

        groups = cast(list[str], d.pop("groups", UNSET))

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

        platforms = cast(list[str], d.pop("platforms", UNSET))

        _revision_history = d.pop("revision_history", UNSET)
        revision_history: list[RevisionEntry] | Unset = UNSET
        if _revision_history is not UNSET:
            revision_history = []
            for revision_history_item_data in _revision_history:
                revision_history_item = RevisionEntry.from_dict(revision_history_item_data)

                revision_history.append(revision_history_item)

        revoked = d.pop("revoked", UNSET)

        def _parse_software_type(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        software_type = _parse_software_type(d.pop("software_type", UNSET))

        def _parse_spec_version(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        spec_version = _parse_spec_version(d.pop("spec_version", UNSET))

        _techniques = d.pop("techniques", UNSET)
        techniques: list[str | TechniqueDetail] | Unset = UNSET
        if _techniques is not UNSET:
            techniques = []
            for techniques_item_data in _techniques:

                def _parse_techniques_item(data: object) -> str | TechniqueDetail:
                    try:
                        if not isinstance(data, dict):
                            raise TypeError()
                        techniques_item_type_1 = TechniqueDetail.from_dict(data)

                        return techniques_item_type_1
                    except (TypeError, ValueError, AttributeError, KeyError):
                        pass
                    return cast(str | TechniqueDetail, data)

                techniques_item = _parse_techniques_item(techniques_item_data)

                techniques.append(techniques_item)

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

        software_detail = cls(
            software_id=software_id,
            aliases=aliases,
            capabilities=capabilities,
            contributors=contributors,
            created=created,
            deprecated=deprecated,
            description=description,
            domains=domains,
            groups=groups,
            modified=modified,
            name=name,
            object_marking_refs=object_marking_refs,
            platforms=platforms,
            revision_history=revision_history,
            revoked=revoked,
            software_type=software_type,
            spec_version=spec_version,
            techniques=techniques,
            url=url,
            version=version,
        )

        software_detail.additional_properties = d
        return software_detail

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

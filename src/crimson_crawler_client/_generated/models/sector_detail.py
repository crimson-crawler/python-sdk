from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, BinaryIO, Generator, TextIO, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.hierarchy_ref import HierarchyRef
    from ..models.revision_entry import RevisionEntry


T = TypeVar("T", bound="SectorDetail")


@_attrs_define
class SectorDetail:
    """Industry sector profile — name, sub-sectors, aliases, and STIX identity class.

    Attributes:
        aliases (list[str] | Unset): Known aliases for this sector
        description (None | str | Unset): Sector threat landscape description
        identity_class (str | Unset): STIX identity_class (e.g. 'class') Default: ''.
        name (None | str | Unset): Sector name (e.g. 'Financial Services')
        parent_sectors (list[HierarchyRef] | Unset): Ancestor sectors from the sector bundle's parent chain (e.g. high-
            tech -> Technologies), so a caller can expand the `sectors[]` slugs to real objects.
        revision_history (list[RevisionEntry] | Unset): The object's revision history from `/objects/{id}/versions/`.
            Opt-in via include=['versions']; attached to every detail row this response returns — the endpoint's own object
            AND the rows nested in its list layers (search hits, technique-context entries), one deduped cached read per
            distinct object. Zero reads when the token is omitted.
        sector_id (str | Unset): Sector identifier Default: ''.
        sectors (list[str] | Unset): Sub-sector list (NACE / NAICS-style breakdown)
        stix_id (str | Unset): STIX object identifier Default: ''.
    """

    aliases: list[str] | Unset = UNSET
    description: None | str | Unset = UNSET
    identity_class: str | Unset = ""
    name: None | str | Unset = UNSET
    parent_sectors: list[HierarchyRef] | Unset = UNSET
    revision_history: list[RevisionEntry] | Unset = UNSET
    sector_id: str | Unset = ""
    sectors: list[str] | Unset = UNSET
    stix_id: str | Unset = ""
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        from ..models.hierarchy_ref import HierarchyRef  # noqa: PLC0415
        from ..models.revision_entry import RevisionEntry  # noqa: PLC0415

        aliases: list[str] | Unset = UNSET
        if not isinstance(self.aliases, Unset):
            aliases = self.aliases

        description: None | str | Unset
        if isinstance(self.description, Unset):
            description = UNSET
        else:
            description = self.description

        identity_class = self.identity_class

        name: None | str | Unset
        if isinstance(self.name, Unset):
            name = UNSET
        else:
            name = self.name

        parent_sectors: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.parent_sectors, Unset):
            parent_sectors = []
            for parent_sectors_item_data in self.parent_sectors:
                parent_sectors_item = parent_sectors_item_data.to_dict()
                parent_sectors.append(parent_sectors_item)

        revision_history: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.revision_history, Unset):
            revision_history = []
            for revision_history_item_data in self.revision_history:
                revision_history_item = revision_history_item_data.to_dict()
                revision_history.append(revision_history_item)

        sector_id = self.sector_id

        sectors: list[str] | Unset = UNSET
        if not isinstance(self.sectors, Unset):
            sectors = self.sectors

        stix_id = self.stix_id

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if aliases is not UNSET:
            field_dict["aliases"] = aliases
        if description is not UNSET:
            field_dict["description"] = description
        if identity_class is not UNSET:
            field_dict["identity_class"] = identity_class
        if name is not UNSET:
            field_dict["name"] = name
        if parent_sectors is not UNSET:
            field_dict["parent_sectors"] = parent_sectors
        if revision_history is not UNSET:
            field_dict["revision_history"] = revision_history
        if sector_id is not UNSET:
            field_dict["sector_id"] = sector_id
        if sectors is not UNSET:
            field_dict["sectors"] = sectors
        if stix_id is not UNSET:
            field_dict["stix_id"] = stix_id

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.hierarchy_ref import HierarchyRef  # noqa: PLC0415
        from ..models.revision_entry import RevisionEntry  # noqa: PLC0415

        d = dict(src_dict)
        aliases = cast(list[str], d.pop("aliases", UNSET))

        def _parse_description(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        description = _parse_description(d.pop("description", UNSET))

        identity_class = d.pop("identity_class", UNSET)

        def _parse_name(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        name = _parse_name(d.pop("name", UNSET))

        _parent_sectors = d.pop("parent_sectors", UNSET)
        parent_sectors: list[HierarchyRef] | Unset = UNSET
        if _parent_sectors is not UNSET:
            parent_sectors = []
            for parent_sectors_item_data in _parent_sectors:
                parent_sectors_item = HierarchyRef.from_dict(parent_sectors_item_data)

                parent_sectors.append(parent_sectors_item)

        _revision_history = d.pop("revision_history", UNSET)
        revision_history: list[RevisionEntry] | Unset = UNSET
        if _revision_history is not UNSET:
            revision_history = []
            for revision_history_item_data in _revision_history:
                revision_history_item = RevisionEntry.from_dict(revision_history_item_data)

                revision_history.append(revision_history_item)

        sector_id = d.pop("sector_id", UNSET)

        sectors = cast(list[str], d.pop("sectors", UNSET))

        stix_id = d.pop("stix_id", UNSET)

        sector_detail = cls(
            aliases=aliases,
            description=description,
            identity_class=identity_class,
            name=name,
            parent_sectors=parent_sectors,
            revision_history=revision_history,
            sector_id=sector_id,
            sectors=sectors,
            stix_id=stix_id,
        )

        sector_detail.additional_properties = d
        return sector_detail

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

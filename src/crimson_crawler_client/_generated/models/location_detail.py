from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, BinaryIO, Generator, TextIO, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.hierarchy_ref import HierarchyRef
    from ..models.revision_entry import RevisionEntry


T = TypeVar("T", bound="LocationDetail")


@_attrs_define
class LocationDetail:
    """Geographic location profile — country/region metadata (coordinates, location type, aliases).

    Attributes:
        aliases (list[str] | Unset): Known aliases for this location
        country (None | str | Unset): Country name
        description (None | str | Unset): Threat landscape description
        latitude (float | None | Unset): Latitude coordinate
        location_id (str | Unset): Location identifier Default: ''.
        location_type (None | str | Unset): Type of location (Country, Region, etc.)
        longitude (float | None | Unset): Longitude coordinate
        name (None | str | Unset): Country or region name
        parent_locations (list[HierarchyRef] | Unset): Ancestor locations from the location bundle's parent chain (e.g.
            US -> Northern America -> Americas), so a caller can expand the `region` slug to real objects.
        region (None | str | Unset): Geographic region
        revision_history (list[RevisionEntry] | Unset): The object's revision history from `/objects/{id}/versions/`.
            Opt-in via include=['versions']; attached to every detail row this response returns — the endpoint's own object
            AND the rows nested in its list layers (search hits, technique-context entries), one deduped cached read per
            distinct object. Zero reads when the token is omitted.
        stix_id (str | Unset): STIX object identifier Default: ''.
        url (str | Unset): External reference URL Default: ''.
    """

    aliases: list[str] | Unset = UNSET
    country: None | str | Unset = UNSET
    description: None | str | Unset = UNSET
    latitude: float | None | Unset = UNSET
    location_id: str | Unset = ""
    location_type: None | str | Unset = UNSET
    longitude: float | None | Unset = UNSET
    name: None | str | Unset = UNSET
    parent_locations: list[HierarchyRef] | Unset = UNSET
    region: None | str | Unset = UNSET
    revision_history: list[RevisionEntry] | Unset = UNSET
    stix_id: str | Unset = ""
    url: str | Unset = ""
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        from ..models.hierarchy_ref import HierarchyRef  # noqa: PLC0415
        from ..models.revision_entry import RevisionEntry  # noqa: PLC0415

        aliases: list[str] | Unset = UNSET
        if not isinstance(self.aliases, Unset):
            aliases = self.aliases

        country: None | str | Unset
        if isinstance(self.country, Unset):
            country = UNSET
        else:
            country = self.country

        description: None | str | Unset
        if isinstance(self.description, Unset):
            description = UNSET
        else:
            description = self.description

        latitude: float | None | Unset
        if isinstance(self.latitude, Unset):
            latitude = UNSET
        else:
            latitude = self.latitude

        location_id = self.location_id

        location_type: None | str | Unset
        if isinstance(self.location_type, Unset):
            location_type = UNSET
        else:
            location_type = self.location_type

        longitude: float | None | Unset
        if isinstance(self.longitude, Unset):
            longitude = UNSET
        else:
            longitude = self.longitude

        name: None | str | Unset
        if isinstance(self.name, Unset):
            name = UNSET
        else:
            name = self.name

        parent_locations: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.parent_locations, Unset):
            parent_locations = []
            for parent_locations_item_data in self.parent_locations:
                parent_locations_item = parent_locations_item_data.to_dict()
                parent_locations.append(parent_locations_item)

        region: None | str | Unset
        if isinstance(self.region, Unset):
            region = UNSET
        else:
            region = self.region

        revision_history: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.revision_history, Unset):
            revision_history = []
            for revision_history_item_data in self.revision_history:
                revision_history_item = revision_history_item_data.to_dict()
                revision_history.append(revision_history_item)

        stix_id = self.stix_id

        url = self.url

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if aliases is not UNSET:
            field_dict["aliases"] = aliases
        if country is not UNSET:
            field_dict["country"] = country
        if description is not UNSET:
            field_dict["description"] = description
        if latitude is not UNSET:
            field_dict["latitude"] = latitude
        if location_id is not UNSET:
            field_dict["location_id"] = location_id
        if location_type is not UNSET:
            field_dict["location_type"] = location_type
        if longitude is not UNSET:
            field_dict["longitude"] = longitude
        if name is not UNSET:
            field_dict["name"] = name
        if parent_locations is not UNSET:
            field_dict["parent_locations"] = parent_locations
        if region is not UNSET:
            field_dict["region"] = region
        if revision_history is not UNSET:
            field_dict["revision_history"] = revision_history
        if stix_id is not UNSET:
            field_dict["stix_id"] = stix_id
        if url is not UNSET:
            field_dict["url"] = url

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.hierarchy_ref import HierarchyRef  # noqa: PLC0415
        from ..models.revision_entry import RevisionEntry  # noqa: PLC0415

        d = dict(src_dict)
        aliases = cast(list[str], d.pop("aliases", UNSET))

        def _parse_country(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        country = _parse_country(d.pop("country", UNSET))

        def _parse_description(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        description = _parse_description(d.pop("description", UNSET))

        def _parse_latitude(data: object) -> float | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(float | None | Unset, data)

        latitude = _parse_latitude(d.pop("latitude", UNSET))

        location_id = d.pop("location_id", UNSET)

        def _parse_location_type(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        location_type = _parse_location_type(d.pop("location_type", UNSET))

        def _parse_longitude(data: object) -> float | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(float | None | Unset, data)

        longitude = _parse_longitude(d.pop("longitude", UNSET))

        def _parse_name(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        name = _parse_name(d.pop("name", UNSET))

        _parent_locations = d.pop("parent_locations", UNSET)
        parent_locations: list[HierarchyRef] | Unset = UNSET
        if _parent_locations is not UNSET:
            parent_locations = []
            for parent_locations_item_data in _parent_locations:
                parent_locations_item = HierarchyRef.from_dict(parent_locations_item_data)

                parent_locations.append(parent_locations_item)

        def _parse_region(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        region = _parse_region(d.pop("region", UNSET))

        _revision_history = d.pop("revision_history", UNSET)
        revision_history: list[RevisionEntry] | Unset = UNSET
        if _revision_history is not UNSET:
            revision_history = []
            for revision_history_item_data in _revision_history:
                revision_history_item = RevisionEntry.from_dict(revision_history_item_data)

                revision_history.append(revision_history_item)

        stix_id = d.pop("stix_id", UNSET)

        url = d.pop("url", UNSET)

        location_detail = cls(
            aliases=aliases,
            country=country,
            description=description,
            latitude=latitude,
            location_id=location_id,
            location_type=location_type,
            longitude=longitude,
            name=name,
            parent_locations=parent_locations,
            region=region,
            revision_history=revision_history,
            stix_id=stix_id,
            url=url,
        )

        location_detail.additional_properties = d
        return location_detail

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

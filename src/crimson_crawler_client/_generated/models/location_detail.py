from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, BinaryIO, Generator, TextIO, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.group_detail import GroupDetail
    from ..models.location_detail_groups_item_type_2 import LocationDetailGroupsItemType2
    from ..models.technique_detail import TechniqueDetail


T = TypeVar("T", bound="LocationDetail")


@_attrs_define
class LocationDetail:
    """Geographic threat landscape - active groups and techniques in a region.

    Attributes:
        aliases (list[str] | Unset): Known aliases for this location
        country (None | str | Unset): Country name
        description (None | str | Unset): Threat landscape description
        groups (list[GroupDetail | LocationDetailGroupsItemType2 | str] | Unset): Threat groups active in this region
        latitude (float | None | Unset): Latitude coordinate
        location_id (str | Unset): Location identifier Default: ''.
        location_type (None | str | Unset): Type of location (Country, Region, etc.)
        longitude (float | None | Unset): Longitude coordinate
        name (None | str | Unset): Country or region name
        region (None | str | Unset): Geographic region
        stix_id (str | Unset): STIX object identifier Default: ''.
        techniques (list[str | TechniqueDetail] | Unset): ATT&CK techniques observed in this region
        url (str | Unset): External reference URL Default: ''.
    """

    aliases: list[str] | Unset = UNSET
    country: None | str | Unset = UNSET
    description: None | str | Unset = UNSET
    groups: list[GroupDetail | LocationDetailGroupsItemType2 | str] | Unset = UNSET
    latitude: float | None | Unset = UNSET
    location_id: str | Unset = ""
    location_type: None | str | Unset = UNSET
    longitude: float | None | Unset = UNSET
    name: None | str | Unset = UNSET
    region: None | str | Unset = UNSET
    stix_id: str | Unset = ""
    techniques: list[str | TechniqueDetail] | Unset = UNSET
    url: str | Unset = ""
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        from ..models.group_detail import GroupDetail
        from ..models.location_detail_groups_item_type_2 import LocationDetailGroupsItemType2
        from ..models.technique_detail import TechniqueDetail

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

        groups: list[dict[str, Any] | str] | Unset = UNSET
        if not isinstance(self.groups, Unset):
            groups = []
            for groups_item_data in self.groups:
                groups_item: dict[str, Any] | str
                if isinstance(groups_item_data, GroupDetail):
                    groups_item = groups_item_data.to_dict()
                elif isinstance(groups_item_data, LocationDetailGroupsItemType2):
                    groups_item = groups_item_data.to_dict()
                else:
                    groups_item = groups_item_data
                groups.append(groups_item)

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

        region: None | str | Unset
        if isinstance(self.region, Unset):
            region = UNSET
        else:
            region = self.region

        stix_id = self.stix_id

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
        if groups is not UNSET:
            field_dict["groups"] = groups
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
        if region is not UNSET:
            field_dict["region"] = region
        if stix_id is not UNSET:
            field_dict["stix_id"] = stix_id
        if techniques is not UNSET:
            field_dict["techniques"] = techniques
        if url is not UNSET:
            field_dict["url"] = url

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.group_detail import GroupDetail
        from ..models.location_detail_groups_item_type_2 import LocationDetailGroupsItemType2
        from ..models.technique_detail import TechniqueDetail

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

        _groups = d.pop("groups", UNSET)
        groups: list[GroupDetail | LocationDetailGroupsItemType2 | str] | Unset = UNSET
        if _groups is not UNSET:
            groups = []
            for groups_item_data in _groups:

                def _parse_groups_item(data: object) -> GroupDetail | LocationDetailGroupsItemType2 | str:
                    try:
                        if not isinstance(data, dict):
                            raise TypeError()
                        groups_item_type_1 = GroupDetail.from_dict(data)

                        return groups_item_type_1
                    except (TypeError, ValueError, AttributeError, KeyError):
                        pass
                    try:
                        if not isinstance(data, dict):
                            raise TypeError()
                        groups_item_type_2 = LocationDetailGroupsItemType2.from_dict(data)

                        return groups_item_type_2
                    except (TypeError, ValueError, AttributeError, KeyError):
                        pass
                    return cast(GroupDetail | LocationDetailGroupsItemType2 | str, data)

                groups_item = _parse_groups_item(groups_item_data)

                groups.append(groups_item)

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

        def _parse_region(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        region = _parse_region(d.pop("region", UNSET))

        stix_id = d.pop("stix_id", UNSET)

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

        url = d.pop("url", UNSET)

        location_detail = cls(
            aliases=aliases,
            country=country,
            description=description,
            groups=groups,
            latitude=latitude,
            location_id=location_id,
            location_type=location_type,
            longitude=longitude,
            name=name,
            region=region,
            stix_id=stix_id,
            techniques=techniques,
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

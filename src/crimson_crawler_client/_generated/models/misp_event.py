from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, BinaryIO, Generator, TextIO, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.galaxy_data import GalaxyData
    from ..models.misp_attribute import MISPAttribute
    from ..models.misp_event_galaxies_item import MISPEventGalaxiesItem
    from ..models.misp_feed_hit import MISPFeedHit


T = TypeVar("T", bound="MISPEvent")


@_attrs_define
class MISPEvent:
    """Threat intelligence event from a connected MISP feed.

    Attributes:
        analysis (str | Unset): Analysis state: 0=Initial, 1=Ongoing, 2=Complete Default: ''.
        attribute_count (int | Unset): Number of indicators in this event Default: 0.
        attributes (list[MISPAttribute] | Unset): Indicators in this event (populated for detail lookups)
        date (str | Unset): Event date (YYYY-MM-DD) Default: ''.
        feed_hits (list[MISPFeedHit] | Unset): Deduplicated feed correlations aggregated from all attributes in this
            event
        galaxies (list[MISPEventGalaxiesItem] | Unset): Threat context tags attached to this event
        galaxy_data (GalaxyData | None | Unset): Extracted technique IDs, threat actors, and malware
        id (str | Unset): MISP event ID Default: ''.
        info (str | Unset): Event title or description Default: ''.
        org (str | Unset): Originating organization name Default: ''.
        related_event_ids (list[str] | Unset): IDs of cross-referenced related events
        tag_names (list[str] | Unset): Tags attached to this event
        threat_level_id (str | Unset): Threat level: 1=High, 2=Medium, 3=Low, 4=Undefined Default: ''.
        timestamp (str | Unset): Unix timestamp of last modification Default: ''.
    """

    analysis: str | Unset = ""
    attribute_count: int | Unset = 0
    attributes: list[MISPAttribute] | Unset = UNSET
    date: str | Unset = ""
    feed_hits: list[MISPFeedHit] | Unset = UNSET
    galaxies: list[MISPEventGalaxiesItem] | Unset = UNSET
    galaxy_data: GalaxyData | None | Unset = UNSET
    id: str | Unset = ""
    info: str | Unset = ""
    org: str | Unset = ""
    related_event_ids: list[str] | Unset = UNSET
    tag_names: list[str] | Unset = UNSET
    threat_level_id: str | Unset = ""
    timestamp: str | Unset = ""
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        from ..models.galaxy_data import GalaxyData
        from ..models.misp_attribute import MISPAttribute
        from ..models.misp_event_galaxies_item import MISPEventGalaxiesItem
        from ..models.misp_feed_hit import MISPFeedHit

        analysis = self.analysis

        attribute_count = self.attribute_count

        attributes: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.attributes, Unset):
            attributes = []
            for attributes_item_data in self.attributes:
                attributes_item = attributes_item_data.to_dict()
                attributes.append(attributes_item)

        date = self.date

        feed_hits: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.feed_hits, Unset):
            feed_hits = []
            for feed_hits_item_data in self.feed_hits:
                feed_hits_item = feed_hits_item_data.to_dict()
                feed_hits.append(feed_hits_item)

        galaxies: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.galaxies, Unset):
            galaxies = []
            for galaxies_item_data in self.galaxies:
                galaxies_item = galaxies_item_data.to_dict()
                galaxies.append(galaxies_item)

        galaxy_data: dict[str, Any] | None | Unset
        if isinstance(self.galaxy_data, Unset):
            galaxy_data = UNSET
        elif isinstance(self.galaxy_data, GalaxyData):
            galaxy_data = self.galaxy_data.to_dict()
        else:
            galaxy_data = self.galaxy_data

        id = self.id

        info = self.info

        org = self.org

        related_event_ids: list[str] | Unset = UNSET
        if not isinstance(self.related_event_ids, Unset):
            related_event_ids = self.related_event_ids

        tag_names: list[str] | Unset = UNSET
        if not isinstance(self.tag_names, Unset):
            tag_names = self.tag_names

        threat_level_id = self.threat_level_id

        timestamp = self.timestamp

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if analysis is not UNSET:
            field_dict["analysis"] = analysis
        if attribute_count is not UNSET:
            field_dict["attribute_count"] = attribute_count
        if attributes is not UNSET:
            field_dict["attributes"] = attributes
        if date is not UNSET:
            field_dict["date"] = date
        if feed_hits is not UNSET:
            field_dict["feed_hits"] = feed_hits
        if galaxies is not UNSET:
            field_dict["galaxies"] = galaxies
        if galaxy_data is not UNSET:
            field_dict["galaxy_data"] = galaxy_data
        if id is not UNSET:
            field_dict["id"] = id
        if info is not UNSET:
            field_dict["info"] = info
        if org is not UNSET:
            field_dict["org"] = org
        if related_event_ids is not UNSET:
            field_dict["related_event_ids"] = related_event_ids
        if tag_names is not UNSET:
            field_dict["tag_names"] = tag_names
        if threat_level_id is not UNSET:
            field_dict["threat_level_id"] = threat_level_id
        if timestamp is not UNSET:
            field_dict["timestamp"] = timestamp

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.galaxy_data import GalaxyData
        from ..models.misp_attribute import MISPAttribute
        from ..models.misp_event_galaxies_item import MISPEventGalaxiesItem
        from ..models.misp_feed_hit import MISPFeedHit

        d = dict(src_dict)
        analysis = d.pop("analysis", UNSET)

        attribute_count = d.pop("attribute_count", UNSET)

        _attributes = d.pop("attributes", UNSET)
        attributes: list[MISPAttribute] | Unset = UNSET
        if _attributes is not UNSET:
            attributes = []
            for attributes_item_data in _attributes:
                attributes_item = MISPAttribute.from_dict(attributes_item_data)

                attributes.append(attributes_item)

        date = d.pop("date", UNSET)

        _feed_hits = d.pop("feed_hits", UNSET)
        feed_hits: list[MISPFeedHit] | Unset = UNSET
        if _feed_hits is not UNSET:
            feed_hits = []
            for feed_hits_item_data in _feed_hits:
                feed_hits_item = MISPFeedHit.from_dict(feed_hits_item_data)

                feed_hits.append(feed_hits_item)

        _galaxies = d.pop("galaxies", UNSET)
        galaxies: list[MISPEventGalaxiesItem] | Unset = UNSET
        if _galaxies is not UNSET:
            galaxies = []
            for galaxies_item_data in _galaxies:
                galaxies_item = MISPEventGalaxiesItem.from_dict(galaxies_item_data)

                galaxies.append(galaxies_item)

        def _parse_galaxy_data(data: object) -> GalaxyData | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, dict):
                    raise TypeError()
                galaxy_data_type_0 = GalaxyData.from_dict(data)

                return galaxy_data_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(GalaxyData | None | Unset, data)

        galaxy_data = _parse_galaxy_data(d.pop("galaxy_data", UNSET))

        id = d.pop("id", UNSET)

        info = d.pop("info", UNSET)

        org = d.pop("org", UNSET)

        related_event_ids = cast(list[str], d.pop("related_event_ids", UNSET))

        tag_names = cast(list[str], d.pop("tag_names", UNSET))

        threat_level_id = d.pop("threat_level_id", UNSET)

        timestamp = d.pop("timestamp", UNSET)

        misp_event = cls(
            analysis=analysis,
            attribute_count=attribute_count,
            attributes=attributes,
            date=date,
            feed_hits=feed_hits,
            galaxies=galaxies,
            galaxy_data=galaxy_data,
            id=id,
            info=info,
            org=org,
            related_event_ids=related_event_ids,
            tag_names=tag_names,
            threat_level_id=threat_level_id,
            timestamp=timestamp,
        )

        misp_event.additional_properties = d
        return misp_event

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

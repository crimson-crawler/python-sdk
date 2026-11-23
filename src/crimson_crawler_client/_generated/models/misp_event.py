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
    from ..models.misp_event_stats import MISPEventStats
    from ..models.misp_feed_hit import MISPFeedHit
    from ..models.misp_object import MISPObject
    from ..models.misp_sighting import MISPSighting
    from ..models.misp_tag import MISPTag


T = TypeVar("T", bound="MISPEvent")


@_attrs_define
class MISPEvent:
    """Threat intelligence event from a connected MISP feed.

    Attributes:
        analysis (str | Unset): Analysis state: 0=Initial, 1=Ongoing, 2=Complete Default: ''.
        attribute_count (int | Unset): Number of indicators in this event Default: 0.
        attributes (list[MISPAttribute] | Unset): Indicators in this event (populated for detail lookups)
        date (str | Unset): Event date (YYYY-MM-DD) Default: ''.
        distribution (None | str | Unset): MISP sharing scope: 0=org-only, 1=community, 2=connected communities, 3=all
            communities
        feed_hits (list[MISPFeedHit] | Unset): Deduplicated feed correlations aggregated from all attributes in this
            event
        first_publication (str | Unset): When the event was first published Default: ''.
        galaxies (list[MISPEventGalaxiesItem] | Unset): Threat context tags attached to this event
        galaxy_data (GalaxyData | None | Unset): Extracted technique IDs, threat actors, and malware
        id (str | Unset): MISP event ID Default: ''.
        info (str | Unset): Event title or description Default: ''.
        objects (list[MISPObject] | Unset): Composite objects grouping this event's attributes into structured records
        org (str | Unset): Originating (creating) organization name Default: ''.
        owning_org (None | str | Unset): Organization that hosts this event on the queried instance — distinct from
            `org` (the creator) on 399 of 400 events
        published (bool | Unset): Whether the event has been published Default: False.
        related_event_ids (list[str] | Unset): IDs of cross-referenced related events
        sighting_count (int | Unset): Sightings across this event's attributes. The MISP EVENT scope attaches no
            `Sighting` key (measured: 0 occurrences on /events/restSearch and /events/view, with and without
            includeCorrelations/includeSightings), so this is joined from one bounded Attribute-scope call per event page;
            it stays 0 when that join is skipped or fails. Default: 0.
        sightings (list[MISPSighting] | Unset): This event's real, deduplicated sighting records — both carriers (the
            per-attribute inline arrays and `/sightings/index/{id}`), merged on the sighting's own id. Only when 'sightings'
            is in include. An empty list means no analyst has recorded an observation, which is the normal state of a
            mirrored deployment: this platform never writes a sighting.
        stats (MISPEventStats | None | Unset): The event's composition (attributes by category, objects by name,
            attachments, reports) from `/events/viewEventStats`. Only when 'stats' is in include; null when the event was
            not found.
        tag_count (int | None | Unset): Number of event tags when summarized; null when not counted
        tag_names (list[str] | Unset): Tags attached to this event
        tags (list[MISPTag] | Unset): Tags with their metadata (see `tag_names` for names only)
        threat_level_id (str | Unset): Threat level: 1=High, 2=Medium, 3=Low, 4=Undefined Default: ''.
        timestamp (str | Unset): Unix timestamp of last modification Default: ''.
        uuid (str | Unset): MISP event UUID Default: ''.
    """

    analysis: str | Unset = ""
    attribute_count: int | Unset = 0
    attributes: list[MISPAttribute] | Unset = UNSET
    date: str | Unset = ""
    distribution: None | str | Unset = UNSET
    feed_hits: list[MISPFeedHit] | Unset = UNSET
    first_publication: str | Unset = ""
    galaxies: list[MISPEventGalaxiesItem] | Unset = UNSET
    galaxy_data: GalaxyData | None | Unset = UNSET
    id: str | Unset = ""
    info: str | Unset = ""
    objects: list[MISPObject] | Unset = UNSET
    org: str | Unset = ""
    owning_org: None | str | Unset = UNSET
    published: bool | Unset = False
    related_event_ids: list[str] | Unset = UNSET
    sighting_count: int | Unset = 0
    sightings: list[MISPSighting] | Unset = UNSET
    stats: MISPEventStats | None | Unset = UNSET
    tag_count: int | None | Unset = UNSET
    tag_names: list[str] | Unset = UNSET
    tags: list[MISPTag] | Unset = UNSET
    threat_level_id: str | Unset = ""
    timestamp: str | Unset = ""
    uuid: str | Unset = ""
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        from ..models.galaxy_data import GalaxyData  # noqa: PLC0415
        from ..models.misp_attribute import MISPAttribute  # noqa: PLC0415
        from ..models.misp_event_galaxies_item import MISPEventGalaxiesItem  # noqa: PLC0415
        from ..models.misp_event_stats import MISPEventStats  # noqa: PLC0415
        from ..models.misp_feed_hit import MISPFeedHit  # noqa: PLC0415
        from ..models.misp_object import MISPObject  # noqa: PLC0415
        from ..models.misp_sighting import MISPSighting  # noqa: PLC0415
        from ..models.misp_tag import MISPTag  # noqa: PLC0415

        analysis = self.analysis

        attribute_count = self.attribute_count

        attributes: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.attributes, Unset):
            attributes = []
            for attributes_item_data in self.attributes:
                attributes_item = attributes_item_data.to_dict()
                attributes.append(attributes_item)

        date = self.date

        distribution: None | str | Unset
        if isinstance(self.distribution, Unset):
            distribution = UNSET
        else:
            distribution = self.distribution

        feed_hits: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.feed_hits, Unset):
            feed_hits = []
            for feed_hits_item_data in self.feed_hits:
                feed_hits_item = feed_hits_item_data.to_dict()
                feed_hits.append(feed_hits_item)

        first_publication = self.first_publication

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

        objects: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.objects, Unset):
            objects = []
            for objects_item_data in self.objects:
                objects_item = objects_item_data.to_dict()
                objects.append(objects_item)

        org = self.org

        owning_org: None | str | Unset
        if isinstance(self.owning_org, Unset):
            owning_org = UNSET
        else:
            owning_org = self.owning_org

        published = self.published

        related_event_ids: list[str] | Unset = UNSET
        if not isinstance(self.related_event_ids, Unset):
            related_event_ids = self.related_event_ids

        sighting_count = self.sighting_count

        sightings: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.sightings, Unset):
            sightings = []
            for sightings_item_data in self.sightings:
                sightings_item = sightings_item_data.to_dict()
                sightings.append(sightings_item)

        stats: dict[str, Any] | None | Unset
        if isinstance(self.stats, Unset):
            stats = UNSET
        elif isinstance(self.stats, MISPEventStats):
            stats = self.stats.to_dict()
        else:
            stats = self.stats

        tag_count: int | None | Unset
        if isinstance(self.tag_count, Unset):
            tag_count = UNSET
        else:
            tag_count = self.tag_count

        tag_names: list[str] | Unset = UNSET
        if not isinstance(self.tag_names, Unset):
            tag_names = self.tag_names

        tags: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.tags, Unset):
            tags = []
            for tags_item_data in self.tags:
                tags_item = tags_item_data.to_dict()
                tags.append(tags_item)

        threat_level_id = self.threat_level_id

        timestamp = self.timestamp

        uuid = self.uuid

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
        if distribution is not UNSET:
            field_dict["distribution"] = distribution
        if feed_hits is not UNSET:
            field_dict["feed_hits"] = feed_hits
        if first_publication is not UNSET:
            field_dict["first_publication"] = first_publication
        if galaxies is not UNSET:
            field_dict["galaxies"] = galaxies
        if galaxy_data is not UNSET:
            field_dict["galaxy_data"] = galaxy_data
        if id is not UNSET:
            field_dict["id"] = id
        if info is not UNSET:
            field_dict["info"] = info
        if objects is not UNSET:
            field_dict["objects"] = objects
        if org is not UNSET:
            field_dict["org"] = org
        if owning_org is not UNSET:
            field_dict["owning_org"] = owning_org
        if published is not UNSET:
            field_dict["published"] = published
        if related_event_ids is not UNSET:
            field_dict["related_event_ids"] = related_event_ids
        if sighting_count is not UNSET:
            field_dict["sighting_count"] = sighting_count
        if sightings is not UNSET:
            field_dict["sightings"] = sightings
        if stats is not UNSET:
            field_dict["stats"] = stats
        if tag_count is not UNSET:
            field_dict["tag_count"] = tag_count
        if tag_names is not UNSET:
            field_dict["tag_names"] = tag_names
        if tags is not UNSET:
            field_dict["tags"] = tags
        if threat_level_id is not UNSET:
            field_dict["threat_level_id"] = threat_level_id
        if timestamp is not UNSET:
            field_dict["timestamp"] = timestamp
        if uuid is not UNSET:
            field_dict["uuid"] = uuid

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.galaxy_data import GalaxyData  # noqa: PLC0415
        from ..models.misp_attribute import MISPAttribute  # noqa: PLC0415
        from ..models.misp_event_galaxies_item import MISPEventGalaxiesItem  # noqa: PLC0415
        from ..models.misp_event_stats import MISPEventStats  # noqa: PLC0415
        from ..models.misp_feed_hit import MISPFeedHit  # noqa: PLC0415
        from ..models.misp_object import MISPObject  # noqa: PLC0415
        from ..models.misp_sighting import MISPSighting  # noqa: PLC0415
        from ..models.misp_tag import MISPTag  # noqa: PLC0415

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

        def _parse_distribution(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        distribution = _parse_distribution(d.pop("distribution", UNSET))

        _feed_hits = d.pop("feed_hits", UNSET)
        feed_hits: list[MISPFeedHit] | Unset = UNSET
        if _feed_hits is not UNSET:
            feed_hits = []
            for feed_hits_item_data in _feed_hits:
                feed_hits_item = MISPFeedHit.from_dict(feed_hits_item_data)

                feed_hits.append(feed_hits_item)

        first_publication = d.pop("first_publication", UNSET)

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

        _objects = d.pop("objects", UNSET)
        objects: list[MISPObject] | Unset = UNSET
        if _objects is not UNSET:
            objects = []
            for objects_item_data in _objects:
                objects_item = MISPObject.from_dict(objects_item_data)

                objects.append(objects_item)

        org = d.pop("org", UNSET)

        def _parse_owning_org(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        owning_org = _parse_owning_org(d.pop("owning_org", UNSET))

        published = d.pop("published", UNSET)

        related_event_ids = cast(list[str], d.pop("related_event_ids", UNSET))

        sighting_count = d.pop("sighting_count", UNSET)

        _sightings = d.pop("sightings", UNSET)
        sightings: list[MISPSighting] | Unset = UNSET
        if _sightings is not UNSET:
            sightings = []
            for sightings_item_data in _sightings:
                sightings_item = MISPSighting.from_dict(sightings_item_data)

                sightings.append(sightings_item)

        def _parse_stats(data: object) -> MISPEventStats | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, dict):
                    raise TypeError()
                stats_type_0 = MISPEventStats.from_dict(data)

                return stats_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(MISPEventStats | None | Unset, data)

        stats = _parse_stats(d.pop("stats", UNSET))

        def _parse_tag_count(data: object) -> int | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(int | None | Unset, data)

        tag_count = _parse_tag_count(d.pop("tag_count", UNSET))

        tag_names = cast(list[str], d.pop("tag_names", UNSET))

        _tags = d.pop("tags", UNSET)
        tags: list[MISPTag] | Unset = UNSET
        if _tags is not UNSET:
            tags = []
            for tags_item_data in _tags:
                tags_item = MISPTag.from_dict(tags_item_data)

                tags.append(tags_item)

        threat_level_id = d.pop("threat_level_id", UNSET)

        timestamp = d.pop("timestamp", UNSET)

        uuid = d.pop("uuid", UNSET)

        misp_event = cls(
            analysis=analysis,
            attribute_count=attribute_count,
            attributes=attributes,
            date=date,
            distribution=distribution,
            feed_hits=feed_hits,
            first_publication=first_publication,
            galaxies=galaxies,
            galaxy_data=galaxy_data,
            id=id,
            info=info,
            objects=objects,
            org=org,
            owning_org=owning_org,
            published=published,
            related_event_ids=related_event_ids,
            sighting_count=sighting_count,
            sightings=sightings,
            stats=stats,
            tag_count=tag_count,
            tag_names=tag_names,
            tags=tags,
            threat_level_id=threat_level_id,
            timestamp=timestamp,
            uuid=uuid,
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

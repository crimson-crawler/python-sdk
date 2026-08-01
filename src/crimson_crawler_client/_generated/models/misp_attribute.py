from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, BinaryIO, Generator, TextIO, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.misp_feed_hit import MISPFeedHit
    from ..models.misp_related_attribute import MISPRelatedAttribute
    from ..models.misp_sighting import MISPSighting
    from ..models.misp_warninglist_hit import MISPWarninglistHit


T = TypeVar("T", bound="MISPAttribute")


@_attrs_define
class MISPAttribute:
    """Threat intelligence indicator with linked threat events and actor context.

    Attributes:
        type_ (str): Indicator type (e.g. ip-dst, md5, domain)
        value (str): Indicator value (IP, hash, domain, URL, etc.)
        actors (list[str] | Unset): Threat actor names associated with this indicator
        category (None | str | Unset): Indicator category (e.g. 'Network activity', 'Payload delivery')
        comment (str | Unset): Analyst comment on this indicator Default: ''.
        event_date (None | str | Unset): Parent threat event publish date (ISO yyyy-mm-dd)
        event_id (None | str | Unset): Parent threat event ID
        event_info (None | str | Unset): Parent threat event description
        feed_hits (list[MISPFeedHit] | Unset): Supplemental-feed correlations for this attribute. Populated on event
            views; attribute-only results do not include feed correlations.
        first_seen (None | str | Unset): First time this indicator was observed
        id (str | Unset): MISP attribute ID Default: ''.
        last_seen (None | str | Unset): Most recent observation of this indicator
        malware (list[str] | Unset): Malware families associated with this indicator
        related_attributes (list[MISPRelatedAttribute] | Unset): Cross-event correlations — same IOC value appearing in
            other threat events
        sighting_count (int | Unset): Total sightings on this attribute (when sightings are requested) Default: 0.
        sightings (list[MISPSighting] | Unset): Full sighting records (when sightings are requested)
        tags (list[str] | Unset): Tags attached to this attribute
        technique_ids (list[str] | Unset): ATT&CK technique IDs linked to this indicator
        threat_level (None | str | Unset): Threat level: low, medium, high, undefined
        timestamp (str | Unset): Attribute creation timestamp Default: ''.
        to_ids (bool | Unset): Whether this indicator should be used for detection Default: False.
        warninglist_hits (list[MISPWarninglistHit] | Unset): Warninglist matches identifying likely false positives or
            known-benign values
    """

    type_: str
    value: str
    actors: list[str] | Unset = UNSET
    category: None | str | Unset = UNSET
    comment: str | Unset = ""
    event_date: None | str | Unset = UNSET
    event_id: None | str | Unset = UNSET
    event_info: None | str | Unset = UNSET
    feed_hits: list[MISPFeedHit] | Unset = UNSET
    first_seen: None | str | Unset = UNSET
    id: str | Unset = ""
    last_seen: None | str | Unset = UNSET
    malware: list[str] | Unset = UNSET
    related_attributes: list[MISPRelatedAttribute] | Unset = UNSET
    sighting_count: int | Unset = 0
    sightings: list[MISPSighting] | Unset = UNSET
    tags: list[str] | Unset = UNSET
    technique_ids: list[str] | Unset = UNSET
    threat_level: None | str | Unset = UNSET
    timestamp: str | Unset = ""
    to_ids: bool | Unset = False
    warninglist_hits: list[MISPWarninglistHit] | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        from ..models.misp_feed_hit import MISPFeedHit
        from ..models.misp_related_attribute import MISPRelatedAttribute
        from ..models.misp_sighting import MISPSighting
        from ..models.misp_warninglist_hit import MISPWarninglistHit

        type_ = self.type_

        value = self.value

        actors: list[str] | Unset = UNSET
        if not isinstance(self.actors, Unset):
            actors = self.actors

        category: None | str | Unset
        if isinstance(self.category, Unset):
            category = UNSET
        else:
            category = self.category

        comment = self.comment

        event_date: None | str | Unset
        if isinstance(self.event_date, Unset):
            event_date = UNSET
        else:
            event_date = self.event_date

        event_id: None | str | Unset
        if isinstance(self.event_id, Unset):
            event_id = UNSET
        else:
            event_id = self.event_id

        event_info: None | str | Unset
        if isinstance(self.event_info, Unset):
            event_info = UNSET
        else:
            event_info = self.event_info

        feed_hits: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.feed_hits, Unset):
            feed_hits = []
            for feed_hits_item_data in self.feed_hits:
                feed_hits_item = feed_hits_item_data.to_dict()
                feed_hits.append(feed_hits_item)

        first_seen: None | str | Unset
        if isinstance(self.first_seen, Unset):
            first_seen = UNSET
        else:
            first_seen = self.first_seen

        id = self.id

        last_seen: None | str | Unset
        if isinstance(self.last_seen, Unset):
            last_seen = UNSET
        else:
            last_seen = self.last_seen

        malware: list[str] | Unset = UNSET
        if not isinstance(self.malware, Unset):
            malware = self.malware

        related_attributes: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.related_attributes, Unset):
            related_attributes = []
            for related_attributes_item_data in self.related_attributes:
                related_attributes_item = related_attributes_item_data.to_dict()
                related_attributes.append(related_attributes_item)

        sighting_count = self.sighting_count

        sightings: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.sightings, Unset):
            sightings = []
            for sightings_item_data in self.sightings:
                sightings_item = sightings_item_data.to_dict()
                sightings.append(sightings_item)

        tags: list[str] | Unset = UNSET
        if not isinstance(self.tags, Unset):
            tags = self.tags

        technique_ids: list[str] | Unset = UNSET
        if not isinstance(self.technique_ids, Unset):
            technique_ids = self.technique_ids

        threat_level: None | str | Unset
        if isinstance(self.threat_level, Unset):
            threat_level = UNSET
        else:
            threat_level = self.threat_level

        timestamp = self.timestamp

        to_ids = self.to_ids

        warninglist_hits: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.warninglist_hits, Unset):
            warninglist_hits = []
            for warninglist_hits_item_data in self.warninglist_hits:
                warninglist_hits_item = warninglist_hits_item_data.to_dict()
                warninglist_hits.append(warninglist_hits_item)

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "type": type_,
                "value": value,
            }
        )
        if actors is not UNSET:
            field_dict["actors"] = actors
        if category is not UNSET:
            field_dict["category"] = category
        if comment is not UNSET:
            field_dict["comment"] = comment
        if event_date is not UNSET:
            field_dict["event_date"] = event_date
        if event_id is not UNSET:
            field_dict["event_id"] = event_id
        if event_info is not UNSET:
            field_dict["event_info"] = event_info
        if feed_hits is not UNSET:
            field_dict["feed_hits"] = feed_hits
        if first_seen is not UNSET:
            field_dict["first_seen"] = first_seen
        if id is not UNSET:
            field_dict["id"] = id
        if last_seen is not UNSET:
            field_dict["last_seen"] = last_seen
        if malware is not UNSET:
            field_dict["malware"] = malware
        if related_attributes is not UNSET:
            field_dict["related_attributes"] = related_attributes
        if sighting_count is not UNSET:
            field_dict["sighting_count"] = sighting_count
        if sightings is not UNSET:
            field_dict["sightings"] = sightings
        if tags is not UNSET:
            field_dict["tags"] = tags
        if technique_ids is not UNSET:
            field_dict["technique_ids"] = technique_ids
        if threat_level is not UNSET:
            field_dict["threat_level"] = threat_level
        if timestamp is not UNSET:
            field_dict["timestamp"] = timestamp
        if to_ids is not UNSET:
            field_dict["to_ids"] = to_ids
        if warninglist_hits is not UNSET:
            field_dict["warninglist_hits"] = warninglist_hits

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.misp_feed_hit import MISPFeedHit
        from ..models.misp_related_attribute import MISPRelatedAttribute
        from ..models.misp_sighting import MISPSighting
        from ..models.misp_warninglist_hit import MISPWarninglistHit

        d = dict(src_dict)
        type_ = d.pop("type")

        value = d.pop("value")

        actors = cast(list[str], d.pop("actors", UNSET))

        def _parse_category(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        category = _parse_category(d.pop("category", UNSET))

        comment = d.pop("comment", UNSET)

        def _parse_event_date(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        event_date = _parse_event_date(d.pop("event_date", UNSET))

        def _parse_event_id(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        event_id = _parse_event_id(d.pop("event_id", UNSET))

        def _parse_event_info(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        event_info = _parse_event_info(d.pop("event_info", UNSET))

        _feed_hits = d.pop("feed_hits", UNSET)
        feed_hits: list[MISPFeedHit] | Unset = UNSET
        if _feed_hits is not UNSET:
            feed_hits = []
            for feed_hits_item_data in _feed_hits:
                feed_hits_item = MISPFeedHit.from_dict(feed_hits_item_data)

                feed_hits.append(feed_hits_item)

        def _parse_first_seen(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        first_seen = _parse_first_seen(d.pop("first_seen", UNSET))

        id = d.pop("id", UNSET)

        def _parse_last_seen(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        last_seen = _parse_last_seen(d.pop("last_seen", UNSET))

        malware = cast(list[str], d.pop("malware", UNSET))

        _related_attributes = d.pop("related_attributes", UNSET)
        related_attributes: list[MISPRelatedAttribute] | Unset = UNSET
        if _related_attributes is not UNSET:
            related_attributes = []
            for related_attributes_item_data in _related_attributes:
                related_attributes_item = MISPRelatedAttribute.from_dict(related_attributes_item_data)

                related_attributes.append(related_attributes_item)

        sighting_count = d.pop("sighting_count", UNSET)

        _sightings = d.pop("sightings", UNSET)
        sightings: list[MISPSighting] | Unset = UNSET
        if _sightings is not UNSET:
            sightings = []
            for sightings_item_data in _sightings:
                sightings_item = MISPSighting.from_dict(sightings_item_data)

                sightings.append(sightings_item)

        tags = cast(list[str], d.pop("tags", UNSET))

        technique_ids = cast(list[str], d.pop("technique_ids", UNSET))

        def _parse_threat_level(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        threat_level = _parse_threat_level(d.pop("threat_level", UNSET))

        timestamp = d.pop("timestamp", UNSET)

        to_ids = d.pop("to_ids", UNSET)

        _warninglist_hits = d.pop("warninglist_hits", UNSET)
        warninglist_hits: list[MISPWarninglistHit] | Unset = UNSET
        if _warninglist_hits is not UNSET:
            warninglist_hits = []
            for warninglist_hits_item_data in _warninglist_hits:
                warninglist_hits_item = MISPWarninglistHit.from_dict(warninglist_hits_item_data)

                warninglist_hits.append(warninglist_hits_item)

        misp_attribute = cls(
            type_=type_,
            value=value,
            actors=actors,
            category=category,
            comment=comment,
            event_date=event_date,
            event_id=event_id,
            event_info=event_info,
            feed_hits=feed_hits,
            first_seen=first_seen,
            id=id,
            last_seen=last_seen,
            malware=malware,
            related_attributes=related_attributes,
            sighting_count=sighting_count,
            sightings=sightings,
            tags=tags,
            technique_ids=technique_ids,
            threat_level=threat_level,
            timestamp=timestamp,
            to_ids=to_ids,
            warninglist_hits=warninglist_hits,
        )

        misp_attribute.additional_properties = d
        return misp_attribute

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

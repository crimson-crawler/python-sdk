from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, BinaryIO, Generator, TextIO, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.cisa_campaign_indicator import CISACampaignIndicator


T = TypeVar("T", bound="CISACampaignAdvisory")


@_attrs_define
class CISACampaignAdvisory:
    """One CISA joint cybersecurity advisory (AA-series) whose STIX 2.1 bundle covers a query.

    Public-domain US Government work. The corpus stores the published bundle; this row is
    bounded metadata plus the observables, never the advisory body.

        Attributes:
            advisory_id (str): Advisory id (AAYY-NNNA), the corpus key
            title (str): Advisory title, with the leading advisory id removed
            url (str): The advisory page on cisa.gov
            actors (list[str] | Unset): Threat-actor names and aliases the bundle names
            cve_ids (list[str] | Unset): CVE ids the bundle's `vulnerability` objects name
            indicator_count (int | Unset): How many observables the bundle carries Default: 0.
            locations (list[str] | Unset): Country codes and administrative areas the bundle names
            matched_indicators (list[CISACampaignIndicator] | Unset): On an indicator query, the observables of this
                advisory that matched; empty on a CVE or technique query
            published (None | str | Unset): The STIX report's `published` timestamp, as published
            retrieved_at (str | Unset): When this codebase read it (ISO 8601) Default: ''.
            sectors (list[str] | Unset): Critical-infrastructure sectors named in the advisory title, matched against a
                fixed vocabulary (CISA's STIX carries no sector taxonomy, so this is a title match, not a source field)
            source (str | Unset): Stable source label Default: 'cisa-aa'.
            source_url (str | Unset): The advisory page URL Default: ''.
            stix_url (str | Unset): The STIX 2.1 JSON bundle this row was built from Default: ''.
            techniques (list[str] | Unset): ATT&CK technique ids the bundle's `attack-pattern` objects name
    """

    advisory_id: str
    title: str
    url: str
    actors: list[str] | Unset = UNSET
    cve_ids: list[str] | Unset = UNSET
    indicator_count: int | Unset = 0
    locations: list[str] | Unset = UNSET
    matched_indicators: list[CISACampaignIndicator] | Unset = UNSET
    published: None | str | Unset = UNSET
    retrieved_at: str | Unset = ""
    sectors: list[str] | Unset = UNSET
    source: str | Unset = "cisa-aa"
    source_url: str | Unset = ""
    stix_url: str | Unset = ""
    techniques: list[str] | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        from ..models.cisa_campaign_indicator import CISACampaignIndicator  # noqa: PLC0415

        advisory_id = self.advisory_id

        title = self.title

        url = self.url

        actors: list[str] | Unset = UNSET
        if not isinstance(self.actors, Unset):
            actors = self.actors

        cve_ids: list[str] | Unset = UNSET
        if not isinstance(self.cve_ids, Unset):
            cve_ids = self.cve_ids

        indicator_count = self.indicator_count

        locations: list[str] | Unset = UNSET
        if not isinstance(self.locations, Unset):
            locations = self.locations

        matched_indicators: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.matched_indicators, Unset):
            matched_indicators = []
            for matched_indicators_item_data in self.matched_indicators:
                matched_indicators_item = matched_indicators_item_data.to_dict()
                matched_indicators.append(matched_indicators_item)

        published: None | str | Unset
        if isinstance(self.published, Unset):
            published = UNSET
        else:
            published = self.published

        retrieved_at = self.retrieved_at

        sectors: list[str] | Unset = UNSET
        if not isinstance(self.sectors, Unset):
            sectors = self.sectors

        source = self.source

        source_url = self.source_url

        stix_url = self.stix_url

        techniques: list[str] | Unset = UNSET
        if not isinstance(self.techniques, Unset):
            techniques = self.techniques

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "advisory_id": advisory_id,
                "title": title,
                "url": url,
            }
        )
        if actors is not UNSET:
            field_dict["actors"] = actors
        if cve_ids is not UNSET:
            field_dict["cve_ids"] = cve_ids
        if indicator_count is not UNSET:
            field_dict["indicator_count"] = indicator_count
        if locations is not UNSET:
            field_dict["locations"] = locations
        if matched_indicators is not UNSET:
            field_dict["matched_indicators"] = matched_indicators
        if published is not UNSET:
            field_dict["published"] = published
        if retrieved_at is not UNSET:
            field_dict["retrieved_at"] = retrieved_at
        if sectors is not UNSET:
            field_dict["sectors"] = sectors
        if source is not UNSET:
            field_dict["source"] = source
        if source_url is not UNSET:
            field_dict["source_url"] = source_url
        if stix_url is not UNSET:
            field_dict["stix_url"] = stix_url
        if techniques is not UNSET:
            field_dict["techniques"] = techniques

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.cisa_campaign_indicator import CISACampaignIndicator  # noqa: PLC0415

        d = dict(src_dict)
        advisory_id = d.pop("advisory_id")

        title = d.pop("title")

        url = d.pop("url")

        actors = cast(list[str], d.pop("actors", UNSET))

        cve_ids = cast(list[str], d.pop("cve_ids", UNSET))

        indicator_count = d.pop("indicator_count", UNSET)

        locations = cast(list[str], d.pop("locations", UNSET))

        _matched_indicators = d.pop("matched_indicators", UNSET)
        matched_indicators: list[CISACampaignIndicator] | Unset = UNSET
        if _matched_indicators is not UNSET:
            matched_indicators = []
            for matched_indicators_item_data in _matched_indicators:
                matched_indicators_item = CISACampaignIndicator.from_dict(matched_indicators_item_data)

                matched_indicators.append(matched_indicators_item)

        def _parse_published(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        published = _parse_published(d.pop("published", UNSET))

        retrieved_at = d.pop("retrieved_at", UNSET)

        sectors = cast(list[str], d.pop("sectors", UNSET))

        source = d.pop("source", UNSET)

        source_url = d.pop("source_url", UNSET)

        stix_url = d.pop("stix_url", UNSET)

        techniques = cast(list[str], d.pop("techniques", UNSET))

        cisa_campaign_advisory = cls(
            advisory_id=advisory_id,
            title=title,
            url=url,
            actors=actors,
            cve_ids=cve_ids,
            indicator_count=indicator_count,
            locations=locations,
            matched_indicators=matched_indicators,
            published=published,
            retrieved_at=retrieved_at,
            sectors=sectors,
            source=source,
            source_url=source_url,
            stix_url=stix_url,
            techniques=techniques,
        )

        cisa_campaign_advisory.additional_properties = d
        return cisa_campaign_advisory

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

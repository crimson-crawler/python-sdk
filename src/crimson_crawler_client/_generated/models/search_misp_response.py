from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, BinaryIO, Generator, TextIO, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.error_detail import ErrorDetail
    from ..models.misp_attribute import MISPAttribute
    from ..models.misp_event import MISPEvent
    from ..models.misp_event_report import MISPEventReport
    from ..models.misp_feed_preview import MISPFeedPreview
    from ..models.misp_instance_version import MISPInstanceVersion


T = TypeVar("T", bound="SearchMISPResponse")


@_attrs_define
class SearchMISPResponse:
    """Search results from our curated MISP — matching indicators and events from its public threat feeds.

    Attributes:
        attributes (list[MISPAttribute] | Unset): Matching threat intelligence indicators
        errors (list[ErrorDetail] | Unset): Partial failure details
        event_reports (list[MISPEventReport] | Unset): Analyst-written reports for returned events. Included by default;
            an explicit include list replaces the defaults, and include=[] omits them.
        events (list[MISPEvent] | Unset): Matching event summaries; include misp_events_full or objects to return full
            event bodies
        feed_previews (list[MISPFeedPreview] | Unset): Read-only previews of the feeds the returned indicators came from
            — what each feed would import, without importing it. Only when 'feeds' is in include.
        misp_events_page_count (int | Unset): Number of event rows on this page Default: 0.
        misp_events_total (int | None | Unset): Total matching events when known; null when the source does not report a
            total
        misp_events_truncated (bool | Unset): True when event bodies on this page were reduced to summaries Default:
            False.
        misp_version (MISPInstanceVersion | None | Unset): The MISP build behind this data (`version` +
            `pymisp_recommended_version` only — the instance uuid and the calling key's permission flags are deliberately
            not projected). Only when 'version' is in include; null when the read failed, which `errors[]` reports.
        tag_names (list[str] | Unset): One page of this instance's tag NAMES (`/tags/fastIndex`), exactly as MISP stores
            them. Only when 'tags' is in include; page through it with `limit`/`page` and use `tag_names_total` for the full
            size. No per-tag metadata exists at this corpus size.
        tag_names_total (int | None | Unset): Total tags on the instance — populated with `tag_names` only.
    """

    attributes: list[MISPAttribute] | Unset = UNSET
    errors: list[ErrorDetail] | Unset = UNSET
    event_reports: list[MISPEventReport] | Unset = UNSET
    events: list[MISPEvent] | Unset = UNSET
    feed_previews: list[MISPFeedPreview] | Unset = UNSET
    misp_events_page_count: int | Unset = 0
    misp_events_total: int | None | Unset = UNSET
    misp_events_truncated: bool | Unset = False
    misp_version: MISPInstanceVersion | None | Unset = UNSET
    tag_names: list[str] | Unset = UNSET
    tag_names_total: int | None | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        from ..models.error_detail import ErrorDetail  # noqa: PLC0415
        from ..models.misp_attribute import MISPAttribute  # noqa: PLC0415
        from ..models.misp_event import MISPEvent  # noqa: PLC0415
        from ..models.misp_event_report import MISPEventReport  # noqa: PLC0415
        from ..models.misp_feed_preview import MISPFeedPreview  # noqa: PLC0415
        from ..models.misp_instance_version import MISPInstanceVersion  # noqa: PLC0415

        attributes: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.attributes, Unset):
            attributes = []
            for attributes_item_data in self.attributes:
                attributes_item = attributes_item_data.to_dict()
                attributes.append(attributes_item)

        errors: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.errors, Unset):
            errors = []
            for errors_item_data in self.errors:
                errors_item = errors_item_data.to_dict()
                errors.append(errors_item)

        event_reports: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.event_reports, Unset):
            event_reports = []
            for event_reports_item_data in self.event_reports:
                event_reports_item = event_reports_item_data.to_dict()
                event_reports.append(event_reports_item)

        events: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.events, Unset):
            events = []
            for events_item_data in self.events:
                events_item = events_item_data.to_dict()
                events.append(events_item)

        feed_previews: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.feed_previews, Unset):
            feed_previews = []
            for feed_previews_item_data in self.feed_previews:
                feed_previews_item = feed_previews_item_data.to_dict()
                feed_previews.append(feed_previews_item)

        misp_events_page_count = self.misp_events_page_count

        misp_events_total: int | None | Unset
        if isinstance(self.misp_events_total, Unset):
            misp_events_total = UNSET
        else:
            misp_events_total = self.misp_events_total

        misp_events_truncated = self.misp_events_truncated

        misp_version: dict[str, Any] | None | Unset
        if isinstance(self.misp_version, Unset):
            misp_version = UNSET
        elif isinstance(self.misp_version, MISPInstanceVersion):
            misp_version = self.misp_version.to_dict()
        else:
            misp_version = self.misp_version

        tag_names: list[str] | Unset = UNSET
        if not isinstance(self.tag_names, Unset):
            tag_names = self.tag_names

        tag_names_total: int | None | Unset
        if isinstance(self.tag_names_total, Unset):
            tag_names_total = UNSET
        else:
            tag_names_total = self.tag_names_total

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if attributes is not UNSET:
            field_dict["attributes"] = attributes
        if errors is not UNSET:
            field_dict["errors"] = errors
        if event_reports is not UNSET:
            field_dict["event_reports"] = event_reports
        if events is not UNSET:
            field_dict["events"] = events
        if feed_previews is not UNSET:
            field_dict["feed_previews"] = feed_previews
        if misp_events_page_count is not UNSET:
            field_dict["misp_events_page_count"] = misp_events_page_count
        if misp_events_total is not UNSET:
            field_dict["misp_events_total"] = misp_events_total
        if misp_events_truncated is not UNSET:
            field_dict["misp_events_truncated"] = misp_events_truncated
        if misp_version is not UNSET:
            field_dict["misp_version"] = misp_version
        if tag_names is not UNSET:
            field_dict["tag_names"] = tag_names
        if tag_names_total is not UNSET:
            field_dict["tag_names_total"] = tag_names_total

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.error_detail import ErrorDetail  # noqa: PLC0415
        from ..models.misp_attribute import MISPAttribute  # noqa: PLC0415
        from ..models.misp_event import MISPEvent  # noqa: PLC0415
        from ..models.misp_event_report import MISPEventReport  # noqa: PLC0415
        from ..models.misp_feed_preview import MISPFeedPreview  # noqa: PLC0415
        from ..models.misp_instance_version import MISPInstanceVersion  # noqa: PLC0415

        d = dict(src_dict)
        _attributes = d.pop("attributes", UNSET)
        attributes: list[MISPAttribute] | Unset = UNSET
        if _attributes is not UNSET:
            attributes = []
            for attributes_item_data in _attributes:
                attributes_item = MISPAttribute.from_dict(attributes_item_data)

                attributes.append(attributes_item)

        _errors = d.pop("errors", UNSET)
        errors: list[ErrorDetail] | Unset = UNSET
        if _errors is not UNSET:
            errors = []
            for errors_item_data in _errors:
                errors_item = ErrorDetail.from_dict(errors_item_data)

                errors.append(errors_item)

        _event_reports = d.pop("event_reports", UNSET)
        event_reports: list[MISPEventReport] | Unset = UNSET
        if _event_reports is not UNSET:
            event_reports = []
            for event_reports_item_data in _event_reports:
                event_reports_item = MISPEventReport.from_dict(event_reports_item_data)

                event_reports.append(event_reports_item)

        _events = d.pop("events", UNSET)
        events: list[MISPEvent] | Unset = UNSET
        if _events is not UNSET:
            events = []
            for events_item_data in _events:
                events_item = MISPEvent.from_dict(events_item_data)

                events.append(events_item)

        _feed_previews = d.pop("feed_previews", UNSET)
        feed_previews: list[MISPFeedPreview] | Unset = UNSET
        if _feed_previews is not UNSET:
            feed_previews = []
            for feed_previews_item_data in _feed_previews:
                feed_previews_item = MISPFeedPreview.from_dict(feed_previews_item_data)

                feed_previews.append(feed_previews_item)

        misp_events_page_count = d.pop("misp_events_page_count", UNSET)

        def _parse_misp_events_total(data: object) -> int | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(int | None | Unset, data)

        misp_events_total = _parse_misp_events_total(d.pop("misp_events_total", UNSET))

        misp_events_truncated = d.pop("misp_events_truncated", UNSET)

        def _parse_misp_version(data: object) -> MISPInstanceVersion | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, dict):
                    raise TypeError()
                misp_version_type_0 = MISPInstanceVersion.from_dict(data)

                return misp_version_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(MISPInstanceVersion | None | Unset, data)

        misp_version = _parse_misp_version(d.pop("misp_version", UNSET))

        tag_names = cast(list[str], d.pop("tag_names", UNSET))

        def _parse_tag_names_total(data: object) -> int | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(int | None | Unset, data)

        tag_names_total = _parse_tag_names_total(d.pop("tag_names_total", UNSET))

        search_misp_response = cls(
            attributes=attributes,
            errors=errors,
            event_reports=event_reports,
            events=events,
            feed_previews=feed_previews,
            misp_events_page_count=misp_events_page_count,
            misp_events_total=misp_events_total,
            misp_events_truncated=misp_events_truncated,
            misp_version=misp_version,
            tag_names=tag_names,
            tag_names_total=tag_names_total,
        )

        search_misp_response.additional_properties = d
        return search_misp_response

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

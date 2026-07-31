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


T = TypeVar("T", bound="SearchMISPResponse")


@_attrs_define
class SearchMISPResponse:
    """Organization threat intelligence search results - matching indicators and events from your connected feed.

    Attributes:
        attributes (list[MISPAttribute] | Unset): Matching threat intelligence indicators
        errors (list[ErrorDetail] | Unset): Partial failure details
        events (list[MISPEvent] | Unset): Matching threat events
    """

    attributes: list[MISPAttribute] | Unset = UNSET
    errors: list[ErrorDetail] | Unset = UNSET
    events: list[MISPEvent] | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        from ..models.error_detail import ErrorDetail
        from ..models.misp_attribute import MISPAttribute
        from ..models.misp_event import MISPEvent

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

        events: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.events, Unset):
            events = []
            for events_item_data in self.events:
                events_item = events_item_data.to_dict()
                events.append(events_item)

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if attributes is not UNSET:
            field_dict["attributes"] = attributes
        if errors is not UNSET:
            field_dict["errors"] = errors
        if events is not UNSET:
            field_dict["events"] = events

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.error_detail import ErrorDetail
        from ..models.misp_attribute import MISPAttribute
        from ..models.misp_event import MISPEvent

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

        _events = d.pop("events", UNSET)
        events: list[MISPEvent] | Unset = UNSET
        if _events is not UNSET:
            events = []
            for events_item_data in _events:
                events_item = MISPEvent.from_dict(events_item_data)

                events.append(events_item)

        search_misp_response = cls(
            attributes=attributes,
            errors=errors,
            events=events,
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

from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, BinaryIO, Generator, TextIO, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="EventEnrichmentRequest")


@_attrs_define
class EventEnrichmentRequest:
    """Event Enricher — submit a raw security/log event for async indicator enrichment.

    The reactive (event-driven) counterpart to the Artifact + Inventory Enrichers: hand it a raw
    security event (a Defender XDR / Sentinel alert, a SIEM/EDR log line, any JSON or text) and the
    enrichment runs in the background — it extracts the indicators (CVEs / ATT&CK techniques / IOCs /
    products) the same deterministic way the Artifact Enricher does, enriches each against the
    authoritative CTI sources, and aggregates a per-event threat verdict. A SOC platform submits an
    alert here instead of looping the single `/v1/enrich/*` endpoints itself.

        Attributes:
            event (str): The raw event — a Defender/Sentinel alert JSON, a log line, or any text. Indicators are extracted
                server-side (callers stringify structured events).
            event_id (None | str | Unset): Optional caller-side event identifier, echoed back on the result (for
                correlation).
    """

    event: str
    event_id: None | str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        event = self.event

        event_id: None | str | Unset
        if isinstance(self.event_id, Unset):
            event_id = UNSET
        else:
            event_id = self.event_id

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "event": event,
            }
        )
        if event_id is not UNSET:
            field_dict["event_id"] = event_id

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        event = d.pop("event")

        def _parse_event_id(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        event_id = _parse_event_id(d.pop("event_id", UNSET))

        event_enrichment_request = cls(
            event=event,
            event_id=event_id,
        )

        event_enrichment_request.additional_properties = d
        return event_enrichment_request

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

from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, BinaryIO, Generator, TextIO, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..models.event_indicator_status import EventIndicatorStatus
from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.error_detail import ErrorDetail
    from ..models.event_indicator_enrichment_type_0 import EventIndicatorEnrichmentType0


T = TypeVar("T", bound="EventIndicator")


@_attrs_define
class EventIndicator:
    """One indicator extracted from an event + its enrichment outcome.

    Attributes:
        type_ (str): Reference type: cve / ioc / technique / product / cwe / capec / group / software / campaign / atlas
            / disarm / package
        value (str): The indicator value (CVE id, IP/hash/domain, technique id, …)
        enrichment (EventIndicatorEnrichmentType0 | None | Unset): The indicator's enrichment payload (the matching
            enrich/* response, triage-trimmed)
        errors (list[ErrorDetail] | Unset): Per-indicator partial-failure details
        ioc_type (None | str | Unset): IOC sub-type when type=='ioc' (ip-dst / domain / sha256 / …)
        kev (bool | Unset): CVE indicators: whether it is CISA-KEV-listed Default: False.
        score (float | None | Unset): Per-indicator score — CVE weaponization (0–100), IOC normalized threat score
            (0–1), else null. Read `verdict` for the grade, not this.
        status (EventIndicatorStatus | Unset): 'ok' or 'error' — 'error' means the indicator's enrichment failed
            Default: EventIndicatorStatus.OK.
        verdict (None | str | Unset): Per-indicator severity verdict: critical > high > medium > low > info. CVE: KEV-
            listed → critical; a Metasploit module floors it at high; else weaponization bands (≥85 critical, ≥70 high, ≥40
            medium, else low). IOC: the enrich/ioc response's own computed `threat_level` (critical/high/medium/low) mapped
            1:1, falling back to its `threat_assessment.verdict` when absent. Null for non-scored types.
        weaponized (bool | Unset): CVE indicators: whether a Metasploit module exists (ready-to-run exploit code)
            Default: False.
    """

    type_: str
    value: str
    enrichment: EventIndicatorEnrichmentType0 | None | Unset = UNSET
    errors: list[ErrorDetail] | Unset = UNSET
    ioc_type: None | str | Unset = UNSET
    kev: bool | Unset = False
    score: float | None | Unset = UNSET
    status: EventIndicatorStatus | Unset = EventIndicatorStatus.OK
    verdict: None | str | Unset = UNSET
    weaponized: bool | Unset = False
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        from ..models.error_detail import ErrorDetail  # noqa: PLC0415
        from ..models.event_indicator_enrichment_type_0 import EventIndicatorEnrichmentType0  # noqa: PLC0415

        type_ = self.type_

        value = self.value

        enrichment: dict[str, Any] | None | Unset
        if isinstance(self.enrichment, Unset):
            enrichment = UNSET
        elif isinstance(self.enrichment, EventIndicatorEnrichmentType0):
            enrichment = self.enrichment.to_dict()
        else:
            enrichment = self.enrichment

        errors: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.errors, Unset):
            errors = []
            for errors_item_data in self.errors:
                errors_item = errors_item_data.to_dict()
                errors.append(errors_item)

        ioc_type: None | str | Unset
        if isinstance(self.ioc_type, Unset):
            ioc_type = UNSET
        else:
            ioc_type = self.ioc_type

        kev = self.kev

        score: float | None | Unset
        if isinstance(self.score, Unset):
            score = UNSET
        else:
            score = self.score

        status: str | Unset = UNSET
        if not isinstance(self.status, Unset):
            status = self.status.value

        verdict: None | str | Unset
        if isinstance(self.verdict, Unset):
            verdict = UNSET
        else:
            verdict = self.verdict

        weaponized = self.weaponized

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "type": type_,
                "value": value,
            }
        )
        if enrichment is not UNSET:
            field_dict["enrichment"] = enrichment
        if errors is not UNSET:
            field_dict["errors"] = errors
        if ioc_type is not UNSET:
            field_dict["ioc_type"] = ioc_type
        if kev is not UNSET:
            field_dict["kev"] = kev
        if score is not UNSET:
            field_dict["score"] = score
        if status is not UNSET:
            field_dict["status"] = status
        if verdict is not UNSET:
            field_dict["verdict"] = verdict
        if weaponized is not UNSET:
            field_dict["weaponized"] = weaponized

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.error_detail import ErrorDetail  # noqa: PLC0415
        from ..models.event_indicator_enrichment_type_0 import EventIndicatorEnrichmentType0  # noqa: PLC0415

        d = dict(src_dict)
        type_ = d.pop("type")

        value = d.pop("value")

        def _parse_enrichment(data: object) -> EventIndicatorEnrichmentType0 | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, dict):
                    raise TypeError()
                enrichment_type_0 = EventIndicatorEnrichmentType0.from_dict(data)

                return enrichment_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(EventIndicatorEnrichmentType0 | None | Unset, data)

        enrichment = _parse_enrichment(d.pop("enrichment", UNSET))

        _errors = d.pop("errors", UNSET)
        errors: list[ErrorDetail] | Unset = UNSET
        if _errors is not UNSET:
            errors = []
            for errors_item_data in _errors:
                errors_item = ErrorDetail.from_dict(errors_item_data)

                errors.append(errors_item)

        def _parse_ioc_type(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        ioc_type = _parse_ioc_type(d.pop("ioc_type", UNSET))

        kev = d.pop("kev", UNSET)

        def _parse_score(data: object) -> float | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(float | None | Unset, data)

        score = _parse_score(d.pop("score", UNSET))

        _status = d.pop("status", UNSET)
        status: EventIndicatorStatus | Unset
        if isinstance(_status, Unset):
            status = UNSET
        else:
            status = EventIndicatorStatus(_status)

        def _parse_verdict(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        verdict = _parse_verdict(d.pop("verdict", UNSET))

        weaponized = d.pop("weaponized", UNSET)

        event_indicator = cls(
            type_=type_,
            value=value,
            enrichment=enrichment,
            errors=errors,
            ioc_type=ioc_type,
            kev=kev,
            score=score,
            status=status,
            verdict=verdict,
            weaponized=weaponized,
        )

        event_indicator.additional_properties = d
        return event_indicator

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

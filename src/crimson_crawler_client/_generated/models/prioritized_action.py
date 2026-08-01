from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, BinaryIO, Generator, TextIO, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..models.prioritized_action_effort_type_0 import PrioritizedActionEffortType0
from ..types import UNSET, Unset

T = TypeVar("T", bound="PrioritizedAction")


@_attrs_define
class PrioritizedAction:
    """One ranked action in the report's prioritized worklist.

    Attributes:
        action (str): PATCH / BLOCK / WATCH / INFO
        type_ (str): Reference type
        value (str): Reference value (CVE, product, IOC, technique)
        effort (None | PrioritizedActionEffortType0 | Unset): Estimated remediation effort — derived only from existing
            structured signals. ``low`` when KEV-listed (vendor patch confirmed available per CISA's KEV listing criterion)
            or when the action is BLOCK (firewall rule). ``medium`` when the CVE affects multiple distinct CPEs (broader
            patch rollout). ``None`` when we lack the signal to estimate honestly — we never invent ``high``.
        reason (str | Unset): One-line deterministic rationale Default: ''.
        ref_id (None | str | Unset): Stable reference ID this action targets (matches ArtifactEnrichmentReference.id)
        score (float | None | Unset): 0-100 priority score
        sla (None | str | Unset): Remediation deadline (CISA KEV due date) when present
        ssvc_decision (None | str | Unset): SSVC decision band, when applicable
    """

    action: str
    type_: str
    value: str
    effort: None | PrioritizedActionEffortType0 | Unset = UNSET
    reason: str | Unset = ""
    ref_id: None | str | Unset = UNSET
    score: float | None | Unset = UNSET
    sla: None | str | Unset = UNSET
    ssvc_decision: None | str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        action = self.action

        type_ = self.type_

        value = self.value

        effort: None | str | Unset
        if isinstance(self.effort, Unset):
            effort = UNSET
        elif isinstance(self.effort, PrioritizedActionEffortType0):
            effort = self.effort.value
        else:
            effort = self.effort

        reason = self.reason

        ref_id: None | str | Unset
        if isinstance(self.ref_id, Unset):
            ref_id = UNSET
        else:
            ref_id = self.ref_id

        score: float | None | Unset
        if isinstance(self.score, Unset):
            score = UNSET
        else:
            score = self.score

        sla: None | str | Unset
        if isinstance(self.sla, Unset):
            sla = UNSET
        else:
            sla = self.sla

        ssvc_decision: None | str | Unset
        if isinstance(self.ssvc_decision, Unset):
            ssvc_decision = UNSET
        else:
            ssvc_decision = self.ssvc_decision

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "action": action,
                "type": type_,
                "value": value,
            }
        )
        if effort is not UNSET:
            field_dict["effort"] = effort
        if reason is not UNSET:
            field_dict["reason"] = reason
        if ref_id is not UNSET:
            field_dict["ref_id"] = ref_id
        if score is not UNSET:
            field_dict["score"] = score
        if sla is not UNSET:
            field_dict["sla"] = sla
        if ssvc_decision is not UNSET:
            field_dict["ssvc_decision"] = ssvc_decision

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        action = d.pop("action")

        type_ = d.pop("type")

        value = d.pop("value")

        def _parse_effort(data: object) -> None | PrioritizedActionEffortType0 | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, str):
                    raise TypeError()
                effort_type_0 = PrioritizedActionEffortType0(data)

                return effort_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(None | PrioritizedActionEffortType0 | Unset, data)

        effort = _parse_effort(d.pop("effort", UNSET))

        reason = d.pop("reason", UNSET)

        def _parse_ref_id(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        ref_id = _parse_ref_id(d.pop("ref_id", UNSET))

        def _parse_score(data: object) -> float | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(float | None | Unset, data)

        score = _parse_score(d.pop("score", UNSET))

        def _parse_sla(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        sla = _parse_sla(d.pop("sla", UNSET))

        def _parse_ssvc_decision(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        ssvc_decision = _parse_ssvc_decision(d.pop("ssvc_decision", UNSET))

        prioritized_action = cls(
            action=action,
            type_=type_,
            value=value,
            effort=effort,
            reason=reason,
            ref_id=ref_id,
            score=score,
            sla=sla,
            ssvc_decision=ssvc_decision,
        )

        prioritized_action.additional_properties = d
        return prioritized_action

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

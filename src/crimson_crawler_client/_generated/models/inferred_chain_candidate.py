from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, BinaryIO, Generator, Literal, TextIO, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="InferredChainCandidate")


@_attrs_define
class InferredChainCandidate:
    """AI-proposed ATT&CK technique candidate. Low-confidence analyst hint,
    never authoritative, never consumed by other enrichments.
    For human review only.

        Attributes:
            candidate_technique_id (str): Proposed ATT&CK technique ID. May be incorrect. Do not fan out to downstream
                enrichment. Format: T#### or T####.### (sub-technique).
            rationale (str): One-sentence explanation of why this candidate was proposed based on the input observation.
            confidence (Literal['low'] | Unset): Always 'low'. AI-proposed candidates are never high-confidence. Default:
                'low'.
            source (Literal['llm_inference'] | Unset): Always 'llm_inference'. Distinguishes AI-proposed candidates from
                deterministic technique IDs in the `techniques[]` array. Default: 'llm_inference'.
            tactic_class (None | str | Unset): Likely ATT&CK tactic the candidate belongs to.
    """

    candidate_technique_id: str
    rationale: str
    confidence: Literal["low"] | Unset = "low"
    source: Literal["llm_inference"] | Unset = "llm_inference"
    tactic_class: None | str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        candidate_technique_id = self.candidate_technique_id

        rationale = self.rationale

        confidence = self.confidence

        source = self.source

        tactic_class: None | str | Unset
        if isinstance(self.tactic_class, Unset):
            tactic_class = UNSET
        else:
            tactic_class = self.tactic_class

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "candidate_technique_id": candidate_technique_id,
                "rationale": rationale,
            }
        )
        if confidence is not UNSET:
            field_dict["confidence"] = confidence
        if source is not UNSET:
            field_dict["source"] = source
        if tactic_class is not UNSET:
            field_dict["tactic_class"] = tactic_class

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        candidate_technique_id = d.pop("candidate_technique_id")

        rationale = d.pop("rationale")

        confidence = cast(Literal["low"] | Unset, d.pop("confidence", UNSET))
        if confidence != "low" and not isinstance(confidence, Unset):
            raise ValueError(f"confidence must match const 'low', got '{confidence}'")

        source = cast(Literal["llm_inference"] | Unset, d.pop("source", UNSET))
        if source != "llm_inference" and not isinstance(source, Unset):
            raise ValueError(f"source must match const 'llm_inference', got '{source}'")

        def _parse_tactic_class(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        tactic_class = _parse_tactic_class(d.pop("tactic_class", UNSET))

        inferred_chain_candidate = cls(
            candidate_technique_id=candidate_technique_id,
            rationale=rationale,
            confidence=confidence,
            source=source,
            tactic_class=tactic_class,
        )

        inferred_chain_candidate.additional_properties = d
        return inferred_chain_candidate

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

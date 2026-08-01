from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, BinaryIO, Generator, TextIO, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..models.key_judgment_confidence_type_0 import KeyJudgmentConfidenceType0
from ..models.key_judgment_likelihood_type_0 import KeyJudgmentLikelihoodType0
from ..types import UNSET, Unset

T = TypeVar("T", bound="KeyJudgment")


@_attrs_define
class KeyJudgment:
    """Finished-intel Key Judgment.

    `likelihood` and `confidence` are deterministic buckets derived from weaponization, KEV, and EPSS.

        Attributes:
            statement (str): The judgment, in one sentence
            confidence (KeyJudgmentConfidenceType0 | None | Unset): Analytic confidence (deterministic, multi-source
                corroboration)
            drivers (list[str] | Unset): Signals that drove the judgment
            likelihood (KeyJudgmentLikelihoodType0 | None | Unset): ICD-203 Words-of-Estimative-Probability band
                (deterministic)
    """

    statement: str
    confidence: KeyJudgmentConfidenceType0 | None | Unset = UNSET
    drivers: list[str] | Unset = UNSET
    likelihood: KeyJudgmentLikelihoodType0 | None | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        statement = self.statement

        confidence: None | str | Unset
        if isinstance(self.confidence, Unset):
            confidence = UNSET
        elif isinstance(self.confidence, KeyJudgmentConfidenceType0):
            confidence = self.confidence.value
        else:
            confidence = self.confidence

        drivers: list[str] | Unset = UNSET
        if not isinstance(self.drivers, Unset):
            drivers = self.drivers

        likelihood: None | str | Unset
        if isinstance(self.likelihood, Unset):
            likelihood = UNSET
        elif isinstance(self.likelihood, KeyJudgmentLikelihoodType0):
            likelihood = self.likelihood.value
        else:
            likelihood = self.likelihood

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "statement": statement,
            }
        )
        if confidence is not UNSET:
            field_dict["confidence"] = confidence
        if drivers is not UNSET:
            field_dict["drivers"] = drivers
        if likelihood is not UNSET:
            field_dict["likelihood"] = likelihood

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        statement = d.pop("statement")

        def _parse_confidence(data: object) -> KeyJudgmentConfidenceType0 | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, str):
                    raise TypeError()
                confidence_type_0 = KeyJudgmentConfidenceType0(data)

                return confidence_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(KeyJudgmentConfidenceType0 | None | Unset, data)

        confidence = _parse_confidence(d.pop("confidence", UNSET))

        drivers = cast(list[str], d.pop("drivers", UNSET))

        def _parse_likelihood(data: object) -> KeyJudgmentLikelihoodType0 | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, str):
                    raise TypeError()
                likelihood_type_0 = KeyJudgmentLikelihoodType0(data)

                return likelihood_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(KeyJudgmentLikelihoodType0 | None | Unset, data)

        likelihood = _parse_likelihood(d.pop("likelihood", UNSET))

        key_judgment = cls(
            statement=statement,
            confidence=confidence,
            drivers=drivers,
            likelihood=likelihood,
        )

        key_judgment.additional_properties = d
        return key_judgment

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

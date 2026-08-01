from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, BinaryIO, Generator, TextIO, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="Confidence")


@_attrs_define
class Confidence:
    """Importance-weighted enrichment completeness indicator.

    Attributes:
        chain_tiers_reached (int | Unset): Number of the 5 deterministic CVE→CWE→CAPEC→ATT&CK chain tiers that produced
            data (+0.03 per tier, capped +0.15) Default: 0.
        corroborating_sources (int | Unset): Independent intelligence sources that corroborated the primary finding
            Default: 1.
        data_quality (str | Unset): Quality bucket derived from completeness and source presence: `none`, `low`,
            `moderate`, or `high`. `none` means no requested layer returned data; `low` means some data resolved with
            limited completeness or corroboration. Default: 'low'.
        error_count (int | Unset): Number of source errors encountered Default: 0.
        has_cna_primary_cvss (bool | Unset): True when the CVSS score came from a CNA (authoritative) source — holds
            confidence even when NVD reads 'Awaiting Analysis' Default: False.
        score (float | Unset): Confidence score (0.0-1.0) Default: 0.0.
        sources_queried (int | Unset): Number of intelligence sources queried Default: 0.
        sources_responded (int | Unset): Number of source requests that completed successfully. A successful request can
            still return no matching data; use `data_quality` to distinguish that case. Default: 0.
    """

    chain_tiers_reached: int | Unset = 0
    corroborating_sources: int | Unset = 1
    data_quality: str | Unset = "low"
    error_count: int | Unset = 0
    has_cna_primary_cvss: bool | Unset = False
    score: float | Unset = 0.0
    sources_queried: int | Unset = 0
    sources_responded: int | Unset = 0
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        chain_tiers_reached = self.chain_tiers_reached

        corroborating_sources = self.corroborating_sources

        data_quality = self.data_quality

        error_count = self.error_count

        has_cna_primary_cvss = self.has_cna_primary_cvss

        score = self.score

        sources_queried = self.sources_queried

        sources_responded = self.sources_responded

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if chain_tiers_reached is not UNSET:
            field_dict["chain_tiers_reached"] = chain_tiers_reached
        if corroborating_sources is not UNSET:
            field_dict["corroborating_sources"] = corroborating_sources
        if data_quality is not UNSET:
            field_dict["data_quality"] = data_quality
        if error_count is not UNSET:
            field_dict["error_count"] = error_count
        if has_cna_primary_cvss is not UNSET:
            field_dict["has_cna_primary_cvss"] = has_cna_primary_cvss
        if score is not UNSET:
            field_dict["score"] = score
        if sources_queried is not UNSET:
            field_dict["sources_queried"] = sources_queried
        if sources_responded is not UNSET:
            field_dict["sources_responded"] = sources_responded

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        chain_tiers_reached = d.pop("chain_tiers_reached", UNSET)

        corroborating_sources = d.pop("corroborating_sources", UNSET)

        data_quality = d.pop("data_quality", UNSET)

        error_count = d.pop("error_count", UNSET)

        has_cna_primary_cvss = d.pop("has_cna_primary_cvss", UNSET)

        score = d.pop("score", UNSET)

        sources_queried = d.pop("sources_queried", UNSET)

        sources_responded = d.pop("sources_responded", UNSET)

        confidence = cls(
            chain_tiers_reached=chain_tiers_reached,
            corroborating_sources=corroborating_sources,
            data_quality=data_quality,
            error_count=error_count,
            has_cna_primary_cvss=has_cna_primary_cvss,
            score=score,
            sources_queried=sources_queried,
            sources_responded=sources_responded,
        )

        confidence.additional_properties = d
        return confidence

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

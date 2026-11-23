from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, BinaryIO, Generator, TextIO, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..models.vulnrichment_status import VulnrichmentStatus
from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.vulnrichment_adp_ssvc_type_0 import VulnrichmentAdpSsvcType0


T = TypeVar("T", bound="Vulnrichment")


@_attrs_define
class Vulnrichment:
    """CWE, KEV and SSVC information from a Vulnrichment record.

    `adp_ssvc` is a provider's raw SSVC content; it never overwrites the
    deployment's own `ssvc` decision.

        Attributes:
            cve_id (str): CVE the record belongs to
            source_url (str): The CISA Vulnrichment record URL
            status (VulnrichmentStatus): ok | stale | unavailable | auth_required | terms_not_accepted
            adp_sources (list[str] | Unset): ADP provider short names
            adp_ssvc (None | Unset | VulnrichmentAdpSsvcType0): ADP provider's SSVC content, verbatim
            cwe_ids (list[str] | Unset): CWE ids the CNA and ADP containers name
            error (None | str | Unset): Sanitized failure reason (unavailable rows only)
            kev (bool | None | Unset): Whether the record carries a CISA KEV metric
            licence (str | Unset): CISA repository is CC0; contributor terms are unconfirmed Default: 'mixed/unknown'.
            retrieved_at (str | Unset): When this codebase read it (ISO 8601) Default: ''.
            source (str | Unset): Stable source label Default: 'cisa_vulnrichment'.
    """

    cve_id: str
    source_url: str
    status: VulnrichmentStatus
    adp_sources: list[str] | Unset = UNSET
    adp_ssvc: None | Unset | VulnrichmentAdpSsvcType0 = UNSET
    cwe_ids: list[str] | Unset = UNSET
    error: None | str | Unset = UNSET
    kev: bool | None | Unset = UNSET
    licence: str | Unset = "mixed/unknown"
    retrieved_at: str | Unset = ""
    source: str | Unset = "cisa_vulnrichment"
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        from ..models.vulnrichment_adp_ssvc_type_0 import VulnrichmentAdpSsvcType0  # noqa: PLC0415

        cve_id = self.cve_id

        source_url = self.source_url

        status = self.status.value

        adp_sources: list[str] | Unset = UNSET
        if not isinstance(self.adp_sources, Unset):
            adp_sources = self.adp_sources

        adp_ssvc: dict[str, Any] | None | Unset
        if isinstance(self.adp_ssvc, Unset):
            adp_ssvc = UNSET
        elif isinstance(self.adp_ssvc, VulnrichmentAdpSsvcType0):
            adp_ssvc = self.adp_ssvc.to_dict()
        else:
            adp_ssvc = self.adp_ssvc

        cwe_ids: list[str] | Unset = UNSET
        if not isinstance(self.cwe_ids, Unset):
            cwe_ids = self.cwe_ids

        error: None | str | Unset
        if isinstance(self.error, Unset):
            error = UNSET
        else:
            error = self.error

        kev: bool | None | Unset
        if isinstance(self.kev, Unset):
            kev = UNSET
        else:
            kev = self.kev

        licence = self.licence

        retrieved_at = self.retrieved_at

        source = self.source

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "cve_id": cve_id,
                "source_url": source_url,
                "status": status,
            }
        )
        if adp_sources is not UNSET:
            field_dict["adp_sources"] = adp_sources
        if adp_ssvc is not UNSET:
            field_dict["adp_ssvc"] = adp_ssvc
        if cwe_ids is not UNSET:
            field_dict["cwe_ids"] = cwe_ids
        if error is not UNSET:
            field_dict["error"] = error
        if kev is not UNSET:
            field_dict["kev"] = kev
        if licence is not UNSET:
            field_dict["licence"] = licence
        if retrieved_at is not UNSET:
            field_dict["retrieved_at"] = retrieved_at
        if source is not UNSET:
            field_dict["source"] = source

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.vulnrichment_adp_ssvc_type_0 import VulnrichmentAdpSsvcType0  # noqa: PLC0415

        d = dict(src_dict)
        cve_id = d.pop("cve_id")

        source_url = d.pop("source_url")

        status = VulnrichmentStatus(d.pop("status"))

        adp_sources = cast(list[str], d.pop("adp_sources", UNSET))

        def _parse_adp_ssvc(data: object) -> None | Unset | VulnrichmentAdpSsvcType0:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, dict):
                    raise TypeError()
                adp_ssvc_type_0 = VulnrichmentAdpSsvcType0.from_dict(data)

                return adp_ssvc_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(None | Unset | VulnrichmentAdpSsvcType0, data)

        adp_ssvc = _parse_adp_ssvc(d.pop("adp_ssvc", UNSET))

        cwe_ids = cast(list[str], d.pop("cwe_ids", UNSET))

        def _parse_error(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        error = _parse_error(d.pop("error", UNSET))

        def _parse_kev(data: object) -> bool | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(bool | None | Unset, data)

        kev = _parse_kev(d.pop("kev", UNSET))

        licence = d.pop("licence", UNSET)

        retrieved_at = d.pop("retrieved_at", UNSET)

        source = d.pop("source", UNSET)

        vulnrichment = cls(
            cve_id=cve_id,
            source_url=source_url,
            status=status,
            adp_sources=adp_sources,
            adp_ssvc=adp_ssvc,
            cwe_ids=cwe_ids,
            error=error,
            kev=kev,
            licence=licence,
            retrieved_at=retrieved_at,
            source=source,
        )

        vulnrichment.additional_properties = d
        return vulnrichment

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

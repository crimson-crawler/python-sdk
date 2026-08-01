from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, BinaryIO, Generator, TextIO, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.cpe_product import CPEProduct
    from ..models.enrich_cve_response import EnrichCVEResponse
    from ..models.enrich_product_response_cve_fix_versions import EnrichProductResponseCveFixVersions
    from ..models.error_detail import ErrorDetail
    from ..models.nist_control_mapping import NistControlMapping
    from ..models.risk_summary import RiskSummary


T = TypeVar("T", bound="EnrichProductResponse")


@_attrs_define
class EnrichProductResponse:
    """Product vulnerability assessment - matched CVEs with per-CVE enrichment.

    Attributes:
        product (str): Searched product name
        cpe_matches (list[CPEProduct] | Unset): Matched product entries from the CPE dictionary
        cve_fix_versions (EnrichProductResponseCveFixVersions | Unset): Remediation guidance: `{cve_id: fix_version}` —
            the lowest version that resolves each CVE for this product (from the NVD `versionEndExcluding` applicability
            bound above the requested `version`). Only populated when `version` is set. A CVE is absent when NVD published
            no clean upper bound (all-versions-affected / fixed-after-unknown) — never a fabricated version.
        cves (list[EnrichCVEResponse] | Unset): Enriched CVEs affecting this product (each CVE contains its own context
            fields)
        errors (list[ErrorDetail] | Unset): Partial failure details
        highest_weaponization_score (float | None | Unset): Highest weaponization score across all matched CVEs
        likely_tactics (list[str] | None | Unset): Likely ATT&CK tactic classes for the product's vendor. These are
            analyst hints, not technique IDs or authoritative attribution.
        nist_controls (list[NistControlMapping] | Unset): NIST SP 800-53 rev 5 controls that mitigate the techniques on
            this response, via MITRE CTID. Pass-through static lookup; only populates when 'nist_controls' is in the request
            include set.
        risk_summary (None | RiskSummary | Unset): Aggregate risk statistics across all matched CVEs
        summary (None | str | Unset): AI-generated executive brief across all matched CVEs for this product
        vendor (None | str | Unset): Vendor name filter applied
        version (None | str | Unset): Version filter applied
    """

    product: str
    cpe_matches: list[CPEProduct] | Unset = UNSET
    cve_fix_versions: EnrichProductResponseCveFixVersions | Unset = UNSET
    cves: list[EnrichCVEResponse] | Unset = UNSET
    errors: list[ErrorDetail] | Unset = UNSET
    highest_weaponization_score: float | None | Unset = UNSET
    likely_tactics: list[str] | None | Unset = UNSET
    nist_controls: list[NistControlMapping] | Unset = UNSET
    risk_summary: None | RiskSummary | Unset = UNSET
    summary: None | str | Unset = UNSET
    vendor: None | str | Unset = UNSET
    version: None | str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        from ..models.cpe_product import CPEProduct
        from ..models.enrich_cve_response import EnrichCVEResponse
        from ..models.enrich_product_response_cve_fix_versions import EnrichProductResponseCveFixVersions
        from ..models.error_detail import ErrorDetail
        from ..models.nist_control_mapping import NistControlMapping
        from ..models.risk_summary import RiskSummary

        product = self.product

        cpe_matches: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.cpe_matches, Unset):
            cpe_matches = []
            for cpe_matches_item_data in self.cpe_matches:
                cpe_matches_item = cpe_matches_item_data.to_dict()
                cpe_matches.append(cpe_matches_item)

        cve_fix_versions: dict[str, Any] | Unset = UNSET
        if not isinstance(self.cve_fix_versions, Unset):
            cve_fix_versions = self.cve_fix_versions.to_dict()

        cves: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.cves, Unset):
            cves = []
            for cves_item_data in self.cves:
                cves_item = cves_item_data.to_dict()
                cves.append(cves_item)

        errors: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.errors, Unset):
            errors = []
            for errors_item_data in self.errors:
                errors_item = errors_item_data.to_dict()
                errors.append(errors_item)

        highest_weaponization_score: float | None | Unset
        if isinstance(self.highest_weaponization_score, Unset):
            highest_weaponization_score = UNSET
        else:
            highest_weaponization_score = self.highest_weaponization_score

        likely_tactics: list[str] | None | Unset
        if isinstance(self.likely_tactics, Unset):
            likely_tactics = UNSET
        elif isinstance(self.likely_tactics, list):
            likely_tactics = self.likely_tactics

        else:
            likely_tactics = self.likely_tactics

        nist_controls: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.nist_controls, Unset):
            nist_controls = []
            for nist_controls_item_data in self.nist_controls:
                nist_controls_item = nist_controls_item_data.to_dict()
                nist_controls.append(nist_controls_item)

        risk_summary: dict[str, Any] | None | Unset
        if isinstance(self.risk_summary, Unset):
            risk_summary = UNSET
        elif isinstance(self.risk_summary, RiskSummary):
            risk_summary = self.risk_summary.to_dict()
        else:
            risk_summary = self.risk_summary

        summary: None | str | Unset
        if isinstance(self.summary, Unset):
            summary = UNSET
        else:
            summary = self.summary

        vendor: None | str | Unset
        if isinstance(self.vendor, Unset):
            vendor = UNSET
        else:
            vendor = self.vendor

        version: None | str | Unset
        if isinstance(self.version, Unset):
            version = UNSET
        else:
            version = self.version

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "product": product,
            }
        )
        if cpe_matches is not UNSET:
            field_dict["cpe_matches"] = cpe_matches
        if cve_fix_versions is not UNSET:
            field_dict["cve_fix_versions"] = cve_fix_versions
        if cves is not UNSET:
            field_dict["cves"] = cves
        if errors is not UNSET:
            field_dict["errors"] = errors
        if highest_weaponization_score is not UNSET:
            field_dict["highest_weaponization_score"] = highest_weaponization_score
        if likely_tactics is not UNSET:
            field_dict["likely_tactics"] = likely_tactics
        if nist_controls is not UNSET:
            field_dict["nist_controls"] = nist_controls
        if risk_summary is not UNSET:
            field_dict["risk_summary"] = risk_summary
        if summary is not UNSET:
            field_dict["summary"] = summary
        if vendor is not UNSET:
            field_dict["vendor"] = vendor
        if version is not UNSET:
            field_dict["version"] = version

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.cpe_product import CPEProduct
        from ..models.enrich_cve_response import EnrichCVEResponse
        from ..models.enrich_product_response_cve_fix_versions import EnrichProductResponseCveFixVersions
        from ..models.error_detail import ErrorDetail
        from ..models.nist_control_mapping import NistControlMapping
        from ..models.risk_summary import RiskSummary

        d = dict(src_dict)
        product = d.pop("product")

        _cpe_matches = d.pop("cpe_matches", UNSET)
        cpe_matches: list[CPEProduct] | Unset = UNSET
        if _cpe_matches is not UNSET:
            cpe_matches = []
            for cpe_matches_item_data in _cpe_matches:
                cpe_matches_item = CPEProduct.from_dict(cpe_matches_item_data)

                cpe_matches.append(cpe_matches_item)

        _cve_fix_versions = d.pop("cve_fix_versions", UNSET)
        cve_fix_versions: EnrichProductResponseCveFixVersions | Unset
        if isinstance(_cve_fix_versions, Unset):
            cve_fix_versions = UNSET
        else:
            cve_fix_versions = EnrichProductResponseCveFixVersions.from_dict(_cve_fix_versions)

        _cves = d.pop("cves", UNSET)
        cves: list[EnrichCVEResponse] | Unset = UNSET
        if _cves is not UNSET:
            cves = []
            for cves_item_data in _cves:
                cves_item = EnrichCVEResponse.from_dict(cves_item_data)

                cves.append(cves_item)

        _errors = d.pop("errors", UNSET)
        errors: list[ErrorDetail] | Unset = UNSET
        if _errors is not UNSET:
            errors = []
            for errors_item_data in _errors:
                errors_item = ErrorDetail.from_dict(errors_item_data)

                errors.append(errors_item)

        def _parse_highest_weaponization_score(data: object) -> float | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(float | None | Unset, data)

        highest_weaponization_score = _parse_highest_weaponization_score(d.pop("highest_weaponization_score", UNSET))

        def _parse_likely_tactics(data: object) -> list[str] | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, list):
                    raise TypeError()
                likely_tactics_type_0 = cast(list[str], data)

                return likely_tactics_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(list[str] | None | Unset, data)

        likely_tactics = _parse_likely_tactics(d.pop("likely_tactics", UNSET))

        _nist_controls = d.pop("nist_controls", UNSET)
        nist_controls: list[NistControlMapping] | Unset = UNSET
        if _nist_controls is not UNSET:
            nist_controls = []
            for nist_controls_item_data in _nist_controls:
                nist_controls_item = NistControlMapping.from_dict(nist_controls_item_data)

                nist_controls.append(nist_controls_item)

        def _parse_risk_summary(data: object) -> None | RiskSummary | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, dict):
                    raise TypeError()
                risk_summary_type_0 = RiskSummary.from_dict(data)

                return risk_summary_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(None | RiskSummary | Unset, data)

        risk_summary = _parse_risk_summary(d.pop("risk_summary", UNSET))

        def _parse_summary(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        summary = _parse_summary(d.pop("summary", UNSET))

        def _parse_vendor(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        vendor = _parse_vendor(d.pop("vendor", UNSET))

        def _parse_version(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        version = _parse_version(d.pop("version", UNSET))

        enrich_product_response = cls(
            product=product,
            cpe_matches=cpe_matches,
            cve_fix_versions=cve_fix_versions,
            cves=cves,
            errors=errors,
            highest_weaponization_score=highest_weaponization_score,
            likely_tactics=likely_tactics,
            nist_controls=nist_controls,
            risk_summary=risk_summary,
            summary=summary,
            vendor=vendor,
            version=version,
        )

        enrich_product_response.additional_properties = d
        return enrich_product_response

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

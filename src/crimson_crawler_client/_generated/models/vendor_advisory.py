from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, BinaryIO, Generator, TextIO, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.vendor_advisory_affected_release import VendorAdvisoryAffectedRelease
    from ..models.vendor_advisory_bugzilla import VendorAdvisoryBugzilla
    from ..models.vendor_advisory_cvss import VendorAdvisoryCVSS
    from ..models.vendor_advisory_cvss3 import VendorAdvisoryCVSS3
    from ..models.vendor_advisory_package_state import VendorAdvisoryPackageState
    from ..models.vendor_advisory_product_status import VendorAdvisoryProductStatus
    from ..models.vendor_advisory_remediation import VendorAdvisoryRemediation


T = TypeVar("T", bound="VendorAdvisory")


@_attrs_define
class VendorAdvisory:
    """One vendor's advisory metadata for a CVE — one row per source that answered.

    A source with no advisory contributes no row. A missing or invalid copy returns `status='unavailable'`
    and an error; a valid stale copy retains its rows with `status='stale'` and its publication time in `error`.
    The source-specific blocks are populated only when the source has advisory data.

        Attributes:
            advisory_id (None | str | Unset): The source's own advisory identifier
            advisory_ids (list[str] | Unset): Red Hat: RHSA/RHBA ids carrying the fix
            advisory_status (None | str | Unset): Cisco: advisory status
            advisory_title (None | str | Unset): The source's advisory title
            affected_releases (list[VendorAdvisoryAffectedRelease] | Unset): Red Hat: fixed releases
            bug_ids (list[str] | Unset): Cisco: bug ids
            bugzilla (None | Unset | VendorAdvisoryBugzilla): Red Hat: Bugzilla record
            csaf_url (None | str | Unset): Cisco: CSAF document URL
            cves (list[str] | Unset): Cisco: CVE ids the advisory declares
            cvrf_url (None | str | Unset): Cisco: CVRF document URL
            cvss (list[VendorAdvisoryCVSS] | Unset): Microsoft: one entry per published score set
            cvss3 (None | Unset | VendorAdvisoryCVSS3): Red Hat: CVSS v3 block
            cvss_base_score (float | None | str | Unset): Cisco: CVSS base score
            cwe (list[str] | Unset): CWEs the source assigns (Red Hat publishes one, Cisco may publish several)
            description (None | str | Unset): MSRC's vulnerability description
            details (list[str] | Unset): Red Hat: detail paragraphs
            error (None | str | Unset): Sanitized failure or stale-copy detail
            mitigation (None | str | Unset): Red Hat: mitigation guidance
            package_states (list[VendorAdvisoryPackageState] | Unset): Red Hat: per-package fix states
            product_statuses (list[VendorAdvisoryProductStatus] | Unset): Microsoft: product-status groups
            products (list[str] | Unset): Cisco: affected product names
            published (None | str | Unset): Initial publication date
            references (list[str] | Unset): Red Hat: reference URLs
            remediations (list[VendorAdvisoryRemediation] | Unset): Microsoft: remediation entries
            retrieved_at (str | Unset): When this codebase read it (ISO 8601) Default: ''.
            severity (None | str | Unset): Red Hat threat severity / Cisco SIR
            source (str | Unset): Which vendor produced the row: microsoft, redhat, or cisco Default: ''.
            statement (None | str | Unset): Red Hat: official statement
            status (str | Unset): ok | stale | unavailable Default: ''.
            summary (None | str | Unset): Cisco: advisory summary
            threats (list[str] | Unset): Microsoft: threat descriptions
            title (None | str | Unset): Vulnerability title
            updated (None | str | Unset): Last update date
            url (None | str | Unset): Canonical advisory URL
            version (None | str | Unset): Cisco: advisory version
    """

    advisory_id: None | str | Unset = UNSET
    advisory_ids: list[str] | Unset = UNSET
    advisory_status: None | str | Unset = UNSET
    advisory_title: None | str | Unset = UNSET
    affected_releases: list[VendorAdvisoryAffectedRelease] | Unset = UNSET
    bug_ids: list[str] | Unset = UNSET
    bugzilla: None | Unset | VendorAdvisoryBugzilla = UNSET
    csaf_url: None | str | Unset = UNSET
    cves: list[str] | Unset = UNSET
    cvrf_url: None | str | Unset = UNSET
    cvss: list[VendorAdvisoryCVSS] | Unset = UNSET
    cvss3: None | Unset | VendorAdvisoryCVSS3 = UNSET
    cvss_base_score: float | None | str | Unset = UNSET
    cwe: list[str] | Unset = UNSET
    description: None | str | Unset = UNSET
    details: list[str] | Unset = UNSET
    error: None | str | Unset = UNSET
    mitigation: None | str | Unset = UNSET
    package_states: list[VendorAdvisoryPackageState] | Unset = UNSET
    product_statuses: list[VendorAdvisoryProductStatus] | Unset = UNSET
    products: list[str] | Unset = UNSET
    published: None | str | Unset = UNSET
    references: list[str] | Unset = UNSET
    remediations: list[VendorAdvisoryRemediation] | Unset = UNSET
    retrieved_at: str | Unset = ""
    severity: None | str | Unset = UNSET
    source: str | Unset = ""
    statement: None | str | Unset = UNSET
    status: str | Unset = ""
    summary: None | str | Unset = UNSET
    threats: list[str] | Unset = UNSET
    title: None | str | Unset = UNSET
    updated: None | str | Unset = UNSET
    url: None | str | Unset = UNSET
    version: None | str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        from ..models.vendor_advisory_affected_release import VendorAdvisoryAffectedRelease  # noqa: PLC0415
        from ..models.vendor_advisory_bugzilla import VendorAdvisoryBugzilla  # noqa: PLC0415
        from ..models.vendor_advisory_cvss import VendorAdvisoryCVSS  # noqa: PLC0415
        from ..models.vendor_advisory_cvss3 import VendorAdvisoryCVSS3  # noqa: PLC0415
        from ..models.vendor_advisory_package_state import VendorAdvisoryPackageState  # noqa: PLC0415
        from ..models.vendor_advisory_product_status import VendorAdvisoryProductStatus  # noqa: PLC0415
        from ..models.vendor_advisory_remediation import VendorAdvisoryRemediation  # noqa: PLC0415

        advisory_id: None | str | Unset
        if isinstance(self.advisory_id, Unset):
            advisory_id = UNSET
        else:
            advisory_id = self.advisory_id

        advisory_ids: list[str] | Unset = UNSET
        if not isinstance(self.advisory_ids, Unset):
            advisory_ids = self.advisory_ids

        advisory_status: None | str | Unset
        if isinstance(self.advisory_status, Unset):
            advisory_status = UNSET
        else:
            advisory_status = self.advisory_status

        advisory_title: None | str | Unset
        if isinstance(self.advisory_title, Unset):
            advisory_title = UNSET
        else:
            advisory_title = self.advisory_title

        affected_releases: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.affected_releases, Unset):
            affected_releases = []
            for affected_releases_item_data in self.affected_releases:
                affected_releases_item = affected_releases_item_data.to_dict()
                affected_releases.append(affected_releases_item)

        bug_ids: list[str] | Unset = UNSET
        if not isinstance(self.bug_ids, Unset):
            bug_ids = self.bug_ids

        bugzilla: dict[str, Any] | None | Unset
        if isinstance(self.bugzilla, Unset):
            bugzilla = UNSET
        elif isinstance(self.bugzilla, VendorAdvisoryBugzilla):
            bugzilla = self.bugzilla.to_dict()
        else:
            bugzilla = self.bugzilla

        csaf_url: None | str | Unset
        if isinstance(self.csaf_url, Unset):
            csaf_url = UNSET
        else:
            csaf_url = self.csaf_url

        cves: list[str] | Unset = UNSET
        if not isinstance(self.cves, Unset):
            cves = self.cves

        cvrf_url: None | str | Unset
        if isinstance(self.cvrf_url, Unset):
            cvrf_url = UNSET
        else:
            cvrf_url = self.cvrf_url

        cvss: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.cvss, Unset):
            cvss = []
            for cvss_item_data in self.cvss:
                cvss_item = cvss_item_data.to_dict()
                cvss.append(cvss_item)

        cvss3: dict[str, Any] | None | Unset
        if isinstance(self.cvss3, Unset):
            cvss3 = UNSET
        elif isinstance(self.cvss3, VendorAdvisoryCVSS3):
            cvss3 = self.cvss3.to_dict()
        else:
            cvss3 = self.cvss3

        cvss_base_score: float | None | str | Unset
        if isinstance(self.cvss_base_score, Unset):
            cvss_base_score = UNSET
        else:
            cvss_base_score = self.cvss_base_score

        cwe: list[str] | Unset = UNSET
        if not isinstance(self.cwe, Unset):
            cwe = self.cwe

        description: None | str | Unset
        if isinstance(self.description, Unset):
            description = UNSET
        else:
            description = self.description

        details: list[str] | Unset = UNSET
        if not isinstance(self.details, Unset):
            details = self.details

        error: None | str | Unset
        if isinstance(self.error, Unset):
            error = UNSET
        else:
            error = self.error

        mitigation: None | str | Unset
        if isinstance(self.mitigation, Unset):
            mitigation = UNSET
        else:
            mitigation = self.mitigation

        package_states: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.package_states, Unset):
            package_states = []
            for package_states_item_data in self.package_states:
                package_states_item = package_states_item_data.to_dict()
                package_states.append(package_states_item)

        product_statuses: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.product_statuses, Unset):
            product_statuses = []
            for product_statuses_item_data in self.product_statuses:
                product_statuses_item = product_statuses_item_data.to_dict()
                product_statuses.append(product_statuses_item)

        products: list[str] | Unset = UNSET
        if not isinstance(self.products, Unset):
            products = self.products

        published: None | str | Unset
        if isinstance(self.published, Unset):
            published = UNSET
        else:
            published = self.published

        references: list[str] | Unset = UNSET
        if not isinstance(self.references, Unset):
            references = self.references

        remediations: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.remediations, Unset):
            remediations = []
            for remediations_item_data in self.remediations:
                remediations_item = remediations_item_data.to_dict()
                remediations.append(remediations_item)

        retrieved_at = self.retrieved_at

        severity: None | str | Unset
        if isinstance(self.severity, Unset):
            severity = UNSET
        else:
            severity = self.severity

        source = self.source

        statement: None | str | Unset
        if isinstance(self.statement, Unset):
            statement = UNSET
        else:
            statement = self.statement

        status = self.status

        summary: None | str | Unset
        if isinstance(self.summary, Unset):
            summary = UNSET
        else:
            summary = self.summary

        threats: list[str] | Unset = UNSET
        if not isinstance(self.threats, Unset):
            threats = self.threats

        title: None | str | Unset
        if isinstance(self.title, Unset):
            title = UNSET
        else:
            title = self.title

        updated: None | str | Unset
        if isinstance(self.updated, Unset):
            updated = UNSET
        else:
            updated = self.updated

        url: None | str | Unset
        if isinstance(self.url, Unset):
            url = UNSET
        else:
            url = self.url

        version: None | str | Unset
        if isinstance(self.version, Unset):
            version = UNSET
        else:
            version = self.version

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if advisory_id is not UNSET:
            field_dict["advisory_id"] = advisory_id
        if advisory_ids is not UNSET:
            field_dict["advisory_ids"] = advisory_ids
        if advisory_status is not UNSET:
            field_dict["advisory_status"] = advisory_status
        if advisory_title is not UNSET:
            field_dict["advisory_title"] = advisory_title
        if affected_releases is not UNSET:
            field_dict["affected_releases"] = affected_releases
        if bug_ids is not UNSET:
            field_dict["bug_ids"] = bug_ids
        if bugzilla is not UNSET:
            field_dict["bugzilla"] = bugzilla
        if csaf_url is not UNSET:
            field_dict["csaf_url"] = csaf_url
        if cves is not UNSET:
            field_dict["cves"] = cves
        if cvrf_url is not UNSET:
            field_dict["cvrf_url"] = cvrf_url
        if cvss is not UNSET:
            field_dict["cvss"] = cvss
        if cvss3 is not UNSET:
            field_dict["cvss3"] = cvss3
        if cvss_base_score is not UNSET:
            field_dict["cvss_base_score"] = cvss_base_score
        if cwe is not UNSET:
            field_dict["cwe"] = cwe
        if description is not UNSET:
            field_dict["description"] = description
        if details is not UNSET:
            field_dict["details"] = details
        if error is not UNSET:
            field_dict["error"] = error
        if mitigation is not UNSET:
            field_dict["mitigation"] = mitigation
        if package_states is not UNSET:
            field_dict["package_states"] = package_states
        if product_statuses is not UNSET:
            field_dict["product_statuses"] = product_statuses
        if products is not UNSET:
            field_dict["products"] = products
        if published is not UNSET:
            field_dict["published"] = published
        if references is not UNSET:
            field_dict["references"] = references
        if remediations is not UNSET:
            field_dict["remediations"] = remediations
        if retrieved_at is not UNSET:
            field_dict["retrieved_at"] = retrieved_at
        if severity is not UNSET:
            field_dict["severity"] = severity
        if source is not UNSET:
            field_dict["source"] = source
        if statement is not UNSET:
            field_dict["statement"] = statement
        if status is not UNSET:
            field_dict["status"] = status
        if summary is not UNSET:
            field_dict["summary"] = summary
        if threats is not UNSET:
            field_dict["threats"] = threats
        if title is not UNSET:
            field_dict["title"] = title
        if updated is not UNSET:
            field_dict["updated"] = updated
        if url is not UNSET:
            field_dict["url"] = url
        if version is not UNSET:
            field_dict["version"] = version

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.vendor_advisory_affected_release import VendorAdvisoryAffectedRelease  # noqa: PLC0415
        from ..models.vendor_advisory_bugzilla import VendorAdvisoryBugzilla  # noqa: PLC0415
        from ..models.vendor_advisory_cvss import VendorAdvisoryCVSS  # noqa: PLC0415
        from ..models.vendor_advisory_cvss3 import VendorAdvisoryCVSS3  # noqa: PLC0415
        from ..models.vendor_advisory_package_state import VendorAdvisoryPackageState  # noqa: PLC0415
        from ..models.vendor_advisory_product_status import VendorAdvisoryProductStatus  # noqa: PLC0415
        from ..models.vendor_advisory_remediation import VendorAdvisoryRemediation  # noqa: PLC0415

        d = dict(src_dict)

        def _parse_advisory_id(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        advisory_id = _parse_advisory_id(d.pop("advisory_id", UNSET))

        advisory_ids = cast(list[str], d.pop("advisory_ids", UNSET))

        def _parse_advisory_status(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        advisory_status = _parse_advisory_status(d.pop("advisory_status", UNSET))

        def _parse_advisory_title(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        advisory_title = _parse_advisory_title(d.pop("advisory_title", UNSET))

        _affected_releases = d.pop("affected_releases", UNSET)
        affected_releases: list[VendorAdvisoryAffectedRelease] | Unset = UNSET
        if _affected_releases is not UNSET:
            affected_releases = []
            for affected_releases_item_data in _affected_releases:
                affected_releases_item = VendorAdvisoryAffectedRelease.from_dict(affected_releases_item_data)

                affected_releases.append(affected_releases_item)

        bug_ids = cast(list[str], d.pop("bug_ids", UNSET))

        def _parse_bugzilla(data: object) -> None | Unset | VendorAdvisoryBugzilla:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, dict):
                    raise TypeError()
                bugzilla_type_0 = VendorAdvisoryBugzilla.from_dict(data)

                return bugzilla_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(None | Unset | VendorAdvisoryBugzilla, data)

        bugzilla = _parse_bugzilla(d.pop("bugzilla", UNSET))

        def _parse_csaf_url(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        csaf_url = _parse_csaf_url(d.pop("csaf_url", UNSET))

        cves = cast(list[str], d.pop("cves", UNSET))

        def _parse_cvrf_url(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        cvrf_url = _parse_cvrf_url(d.pop("cvrf_url", UNSET))

        _cvss = d.pop("cvss", UNSET)
        cvss: list[VendorAdvisoryCVSS] | Unset = UNSET
        if _cvss is not UNSET:
            cvss = []
            for cvss_item_data in _cvss:
                cvss_item = VendorAdvisoryCVSS.from_dict(cvss_item_data)

                cvss.append(cvss_item)

        def _parse_cvss3(data: object) -> None | Unset | VendorAdvisoryCVSS3:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, dict):
                    raise TypeError()
                cvss3_type_0 = VendorAdvisoryCVSS3.from_dict(data)

                return cvss3_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(None | Unset | VendorAdvisoryCVSS3, data)

        cvss3 = _parse_cvss3(d.pop("cvss3", UNSET))

        def _parse_cvss_base_score(data: object) -> float | None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(float | None | str | Unset, data)

        cvss_base_score = _parse_cvss_base_score(d.pop("cvss_base_score", UNSET))

        cwe = cast(list[str], d.pop("cwe", UNSET))

        def _parse_description(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        description = _parse_description(d.pop("description", UNSET))

        details = cast(list[str], d.pop("details", UNSET))

        def _parse_error(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        error = _parse_error(d.pop("error", UNSET))

        def _parse_mitigation(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        mitigation = _parse_mitigation(d.pop("mitigation", UNSET))

        _package_states = d.pop("package_states", UNSET)
        package_states: list[VendorAdvisoryPackageState] | Unset = UNSET
        if _package_states is not UNSET:
            package_states = []
            for package_states_item_data in _package_states:
                package_states_item = VendorAdvisoryPackageState.from_dict(package_states_item_data)

                package_states.append(package_states_item)

        _product_statuses = d.pop("product_statuses", UNSET)
        product_statuses: list[VendorAdvisoryProductStatus] | Unset = UNSET
        if _product_statuses is not UNSET:
            product_statuses = []
            for product_statuses_item_data in _product_statuses:
                product_statuses_item = VendorAdvisoryProductStatus.from_dict(product_statuses_item_data)

                product_statuses.append(product_statuses_item)

        products = cast(list[str], d.pop("products", UNSET))

        def _parse_published(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        published = _parse_published(d.pop("published", UNSET))

        references = cast(list[str], d.pop("references", UNSET))

        _remediations = d.pop("remediations", UNSET)
        remediations: list[VendorAdvisoryRemediation] | Unset = UNSET
        if _remediations is not UNSET:
            remediations = []
            for remediations_item_data in _remediations:
                remediations_item = VendorAdvisoryRemediation.from_dict(remediations_item_data)

                remediations.append(remediations_item)

        retrieved_at = d.pop("retrieved_at", UNSET)

        def _parse_severity(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        severity = _parse_severity(d.pop("severity", UNSET))

        source = d.pop("source", UNSET)

        def _parse_statement(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        statement = _parse_statement(d.pop("statement", UNSET))

        status = d.pop("status", UNSET)

        def _parse_summary(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        summary = _parse_summary(d.pop("summary", UNSET))

        threats = cast(list[str], d.pop("threats", UNSET))

        def _parse_title(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        title = _parse_title(d.pop("title", UNSET))

        def _parse_updated(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        updated = _parse_updated(d.pop("updated", UNSET))

        def _parse_url(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        url = _parse_url(d.pop("url", UNSET))

        def _parse_version(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        version = _parse_version(d.pop("version", UNSET))

        vendor_advisory = cls(
            advisory_id=advisory_id,
            advisory_ids=advisory_ids,
            advisory_status=advisory_status,
            advisory_title=advisory_title,
            affected_releases=affected_releases,
            bug_ids=bug_ids,
            bugzilla=bugzilla,
            csaf_url=csaf_url,
            cves=cves,
            cvrf_url=cvrf_url,
            cvss=cvss,
            cvss3=cvss3,
            cvss_base_score=cvss_base_score,
            cwe=cwe,
            description=description,
            details=details,
            error=error,
            mitigation=mitigation,
            package_states=package_states,
            product_statuses=product_statuses,
            products=products,
            published=published,
            references=references,
            remediations=remediations,
            retrieved_at=retrieved_at,
            severity=severity,
            source=source,
            statement=statement,
            status=status,
            summary=summary,
            threats=threats,
            title=title,
            updated=updated,
            url=url,
            version=version,
        )

        vendor_advisory.additional_properties = d
        return vendor_advisory

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

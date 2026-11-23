from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, BinaryIO, Generator, TextIO, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.csaf_product_state import CSAFProductState
    from ..models.csaf_remediation import CSAFRemediation


T = TypeVar("T", bound="CSAFAdvisory")


@_attrs_define
class CSAFAdvisory:
    """One CSAF advisory document from the seeded vendor corpus.

    Attributes:
        publisher_name (str): Publisher name
        tracking_id (str): The document's tracking id (its corpus key)
        advisory_kind (str | Unset): Publisher category: vendor or coordinator republish Default: 'unknown'.
        affected_models (list[str] | Unset): Model numbers named by affected/fixed product rows
        csaf_version (str | Unset): CSAF document version Default: '2.0'.
        current_release_date (None | str | Unset): Current release date
        cve_ids (list[str] | Unset): CVE ids the document names (empty on a CVE-less advisory)
        initial_release_date (None | str | Unset): Initial release date
        product_statuses (list[CSAFProductState] | Unset): Product-status entries (capped at 200)
        product_statuses_total (int | Unset): The true product-status count, before the cap Default: 0.
        publisher_namespace (None | str | Unset): Publisher namespace
        remediations (list[CSAFRemediation] | Unset): Vendor remediations (capped at 200)
        retrieved_at (str | Unset): When this codebase read it (ISO 8601) Default: ''.
        sectors (list[str] | Unset): Critical-infrastructure sectors the document names
        source (str | Unset): Stable source label Default: 'csaf'.
        source_url (str | Unset): The document URL Default: ''.
        title (str | Unset): Advisory title Default: ''.
        tlp_label (None | str | Unset): TLP marking label the document states; null when it states none
        tracking_version (None | str | Unset): Publisher tracking version
        url (str | Unset): Canonical document URL Default: ''.
    """

    publisher_name: str
    tracking_id: str
    advisory_kind: str | Unset = "unknown"
    affected_models: list[str] | Unset = UNSET
    csaf_version: str | Unset = "2.0"
    current_release_date: None | str | Unset = UNSET
    cve_ids: list[str] | Unset = UNSET
    initial_release_date: None | str | Unset = UNSET
    product_statuses: list[CSAFProductState] | Unset = UNSET
    product_statuses_total: int | Unset = 0
    publisher_namespace: None | str | Unset = UNSET
    remediations: list[CSAFRemediation] | Unset = UNSET
    retrieved_at: str | Unset = ""
    sectors: list[str] | Unset = UNSET
    source: str | Unset = "csaf"
    source_url: str | Unset = ""
    title: str | Unset = ""
    tlp_label: None | str | Unset = UNSET
    tracking_version: None | str | Unset = UNSET
    url: str | Unset = ""
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        from ..models.csaf_product_state import CSAFProductState  # noqa: PLC0415
        from ..models.csaf_remediation import CSAFRemediation  # noqa: PLC0415

        publisher_name = self.publisher_name

        tracking_id = self.tracking_id

        advisory_kind = self.advisory_kind

        affected_models: list[str] | Unset = UNSET
        if not isinstance(self.affected_models, Unset):
            affected_models = self.affected_models

        csaf_version = self.csaf_version

        current_release_date: None | str | Unset
        if isinstance(self.current_release_date, Unset):
            current_release_date = UNSET
        else:
            current_release_date = self.current_release_date

        cve_ids: list[str] | Unset = UNSET
        if not isinstance(self.cve_ids, Unset):
            cve_ids = self.cve_ids

        initial_release_date: None | str | Unset
        if isinstance(self.initial_release_date, Unset):
            initial_release_date = UNSET
        else:
            initial_release_date = self.initial_release_date

        product_statuses: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.product_statuses, Unset):
            product_statuses = []
            for product_statuses_item_data in self.product_statuses:
                product_statuses_item = product_statuses_item_data.to_dict()
                product_statuses.append(product_statuses_item)

        product_statuses_total = self.product_statuses_total

        publisher_namespace: None | str | Unset
        if isinstance(self.publisher_namespace, Unset):
            publisher_namespace = UNSET
        else:
            publisher_namespace = self.publisher_namespace

        remediations: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.remediations, Unset):
            remediations = []
            for remediations_item_data in self.remediations:
                remediations_item = remediations_item_data.to_dict()
                remediations.append(remediations_item)

        retrieved_at = self.retrieved_at

        sectors: list[str] | Unset = UNSET
        if not isinstance(self.sectors, Unset):
            sectors = self.sectors

        source = self.source

        source_url = self.source_url

        title = self.title

        tlp_label: None | str | Unset
        if isinstance(self.tlp_label, Unset):
            tlp_label = UNSET
        else:
            tlp_label = self.tlp_label

        tracking_version: None | str | Unset
        if isinstance(self.tracking_version, Unset):
            tracking_version = UNSET
        else:
            tracking_version = self.tracking_version

        url = self.url

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "publisher_name": publisher_name,
                "tracking_id": tracking_id,
            }
        )
        if advisory_kind is not UNSET:
            field_dict["advisory_kind"] = advisory_kind
        if affected_models is not UNSET:
            field_dict["affected_models"] = affected_models
        if csaf_version is not UNSET:
            field_dict["csaf_version"] = csaf_version
        if current_release_date is not UNSET:
            field_dict["current_release_date"] = current_release_date
        if cve_ids is not UNSET:
            field_dict["cve_ids"] = cve_ids
        if initial_release_date is not UNSET:
            field_dict["initial_release_date"] = initial_release_date
        if product_statuses is not UNSET:
            field_dict["product_statuses"] = product_statuses
        if product_statuses_total is not UNSET:
            field_dict["product_statuses_total"] = product_statuses_total
        if publisher_namespace is not UNSET:
            field_dict["publisher_namespace"] = publisher_namespace
        if remediations is not UNSET:
            field_dict["remediations"] = remediations
        if retrieved_at is not UNSET:
            field_dict["retrieved_at"] = retrieved_at
        if sectors is not UNSET:
            field_dict["sectors"] = sectors
        if source is not UNSET:
            field_dict["source"] = source
        if source_url is not UNSET:
            field_dict["source_url"] = source_url
        if title is not UNSET:
            field_dict["title"] = title
        if tlp_label is not UNSET:
            field_dict["tlp_label"] = tlp_label
        if tracking_version is not UNSET:
            field_dict["tracking_version"] = tracking_version
        if url is not UNSET:
            field_dict["url"] = url

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.csaf_product_state import CSAFProductState  # noqa: PLC0415
        from ..models.csaf_remediation import CSAFRemediation  # noqa: PLC0415

        d = dict(src_dict)
        publisher_name = d.pop("publisher_name")

        tracking_id = d.pop("tracking_id")

        advisory_kind = d.pop("advisory_kind", UNSET)

        affected_models = cast(list[str], d.pop("affected_models", UNSET))

        csaf_version = d.pop("csaf_version", UNSET)

        def _parse_current_release_date(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        current_release_date = _parse_current_release_date(d.pop("current_release_date", UNSET))

        cve_ids = cast(list[str], d.pop("cve_ids", UNSET))

        def _parse_initial_release_date(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        initial_release_date = _parse_initial_release_date(d.pop("initial_release_date", UNSET))

        _product_statuses = d.pop("product_statuses", UNSET)
        product_statuses: list[CSAFProductState] | Unset = UNSET
        if _product_statuses is not UNSET:
            product_statuses = []
            for product_statuses_item_data in _product_statuses:
                product_statuses_item = CSAFProductState.from_dict(product_statuses_item_data)

                product_statuses.append(product_statuses_item)

        product_statuses_total = d.pop("product_statuses_total", UNSET)

        def _parse_publisher_namespace(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        publisher_namespace = _parse_publisher_namespace(d.pop("publisher_namespace", UNSET))

        _remediations = d.pop("remediations", UNSET)
        remediations: list[CSAFRemediation] | Unset = UNSET
        if _remediations is not UNSET:
            remediations = []
            for remediations_item_data in _remediations:
                remediations_item = CSAFRemediation.from_dict(remediations_item_data)

                remediations.append(remediations_item)

        retrieved_at = d.pop("retrieved_at", UNSET)

        sectors = cast(list[str], d.pop("sectors", UNSET))

        source = d.pop("source", UNSET)

        source_url = d.pop("source_url", UNSET)

        title = d.pop("title", UNSET)

        def _parse_tlp_label(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        tlp_label = _parse_tlp_label(d.pop("tlp_label", UNSET))

        def _parse_tracking_version(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        tracking_version = _parse_tracking_version(d.pop("tracking_version", UNSET))

        url = d.pop("url", UNSET)

        csaf_advisory = cls(
            publisher_name=publisher_name,
            tracking_id=tracking_id,
            advisory_kind=advisory_kind,
            affected_models=affected_models,
            csaf_version=csaf_version,
            current_release_date=current_release_date,
            cve_ids=cve_ids,
            initial_release_date=initial_release_date,
            product_statuses=product_statuses,
            product_statuses_total=product_statuses_total,
            publisher_namespace=publisher_namespace,
            remediations=remediations,
            retrieved_at=retrieved_at,
            sectors=sectors,
            source=source,
            source_url=source_url,
            title=title,
            tlp_label=tlp_label,
            tracking_version=tracking_version,
            url=url,
        )

        csaf_advisory.additional_properties = d
        return csaf_advisory

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

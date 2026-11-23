from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, BinaryIO, Generator, TextIO, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..models.ot_context_access_vector_rf_type_0 import OTContextAccessVectorRfType0
from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.et_scada_rule import ETScadaRule
    from ..models.fix_availability import FixAvailability
    from ..models.icsnpp_parser import ICSNPPParser
    from ..models.iec62443_summary import IEC62443Summary
    from ..models.kev_ot_context import KevOTContext
    from ..models.ot_sector import OTSector


T = TypeVar("T", bound="OTContext")


@_attrs_define
class OTContext:
    """Opt-in OT/RF asset context for a CVE or product (``include=['ot_context']``).

    Every field is a deterministic derivation over data the request already reads
    or a committed/seeded table; there is no LLM and no new external source.

        Attributes:
            access_vector_rf (None | OTContextAccessVectorRfType0 | Unset): RF-relevant access vector: 'adjacent' from CVSS
                AV:A, else 'network' when RF evidence exists
            fix_availability (FixAvailability | None | Unset): Vendor-fix state from CSAF product status (and endoflife.date
                on a product)
            iec_62443 (IEC62443Summary | None | Unset): ISA/IEC 62443 requirements derived from the CVE's weakness ids
            kev_ot (KevOTContext | None | Unset): KEV vendor OT classification
            network_detections (list[ETScadaRule] | Unset): Up to five ET SCADA rules, direct CVE matches first, then
                protocol matches
            network_detections_total (int | Unset): Number of distinct matching ET SCADA rules before truncation Default: 0.
            protocol_parsers (list[ICSNPPParser] | Unset): ICSNPP parser records for the identified protocols
            protocols (list[str] | Unset): OT protocol ids named by CPE/product/CSAF/Nuclei text
            rf_evidence (list[str] | Unset): The inputs that produced `access_vector_rf`
            rf_technology (list[str] | Unset): RF technology ids (cellular-5g, wifi, bluetooth, lora, gnss, …)
            sectors (list[OTSector] | Unset): Critical-infrastructure sectors, with provenance
            sources (list[str] | Unset): Every derivation source CONSULTED, with its URL — a source may answer nothing for
                this CVE
    """

    access_vector_rf: None | OTContextAccessVectorRfType0 | Unset = UNSET
    fix_availability: FixAvailability | None | Unset = UNSET
    iec_62443: IEC62443Summary | None | Unset = UNSET
    kev_ot: KevOTContext | None | Unset = UNSET
    network_detections: list[ETScadaRule] | Unset = UNSET
    network_detections_total: int | Unset = 0
    protocol_parsers: list[ICSNPPParser] | Unset = UNSET
    protocols: list[str] | Unset = UNSET
    rf_evidence: list[str] | Unset = UNSET
    rf_technology: list[str] | Unset = UNSET
    sectors: list[OTSector] | Unset = UNSET
    sources: list[str] | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        from ..models.et_scada_rule import ETScadaRule  # noqa: PLC0415
        from ..models.fix_availability import FixAvailability  # noqa: PLC0415
        from ..models.icsnpp_parser import ICSNPPParser  # noqa: PLC0415
        from ..models.iec62443_summary import IEC62443Summary  # noqa: PLC0415
        from ..models.kev_ot_context import KevOTContext  # noqa: PLC0415
        from ..models.ot_sector import OTSector  # noqa: PLC0415

        access_vector_rf: None | str | Unset
        if isinstance(self.access_vector_rf, Unset):
            access_vector_rf = UNSET
        elif isinstance(self.access_vector_rf, OTContextAccessVectorRfType0):
            access_vector_rf = self.access_vector_rf.value
        else:
            access_vector_rf = self.access_vector_rf

        fix_availability: dict[str, Any] | None | Unset
        if isinstance(self.fix_availability, Unset):
            fix_availability = UNSET
        elif isinstance(self.fix_availability, FixAvailability):
            fix_availability = self.fix_availability.to_dict()
        else:
            fix_availability = self.fix_availability

        iec_62443: dict[str, Any] | None | Unset
        if isinstance(self.iec_62443, Unset):
            iec_62443 = UNSET
        elif isinstance(self.iec_62443, IEC62443Summary):
            iec_62443 = self.iec_62443.to_dict()
        else:
            iec_62443 = self.iec_62443

        kev_ot: dict[str, Any] | None | Unset
        if isinstance(self.kev_ot, Unset):
            kev_ot = UNSET
        elif isinstance(self.kev_ot, KevOTContext):
            kev_ot = self.kev_ot.to_dict()
        else:
            kev_ot = self.kev_ot

        network_detections: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.network_detections, Unset):
            network_detections = []
            for network_detections_item_data in self.network_detections:
                network_detections_item = network_detections_item_data.to_dict()
                network_detections.append(network_detections_item)

        network_detections_total = self.network_detections_total

        protocol_parsers: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.protocol_parsers, Unset):
            protocol_parsers = []
            for protocol_parsers_item_data in self.protocol_parsers:
                protocol_parsers_item = protocol_parsers_item_data.to_dict()
                protocol_parsers.append(protocol_parsers_item)

        protocols: list[str] | Unset = UNSET
        if not isinstance(self.protocols, Unset):
            protocols = self.protocols

        rf_evidence: list[str] | Unset = UNSET
        if not isinstance(self.rf_evidence, Unset):
            rf_evidence = self.rf_evidence

        rf_technology: list[str] | Unset = UNSET
        if not isinstance(self.rf_technology, Unset):
            rf_technology = self.rf_technology

        sectors: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.sectors, Unset):
            sectors = []
            for sectors_item_data in self.sectors:
                sectors_item = sectors_item_data.to_dict()
                sectors.append(sectors_item)

        sources: list[str] | Unset = UNSET
        if not isinstance(self.sources, Unset):
            sources = self.sources

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if access_vector_rf is not UNSET:
            field_dict["access_vector_rf"] = access_vector_rf
        if fix_availability is not UNSET:
            field_dict["fix_availability"] = fix_availability
        if iec_62443 is not UNSET:
            field_dict["iec_62443"] = iec_62443
        if kev_ot is not UNSET:
            field_dict["kev_ot"] = kev_ot
        if network_detections is not UNSET:
            field_dict["network_detections"] = network_detections
        if network_detections_total is not UNSET:
            field_dict["network_detections_total"] = network_detections_total
        if protocol_parsers is not UNSET:
            field_dict["protocol_parsers"] = protocol_parsers
        if protocols is not UNSET:
            field_dict["protocols"] = protocols
        if rf_evidence is not UNSET:
            field_dict["rf_evidence"] = rf_evidence
        if rf_technology is not UNSET:
            field_dict["rf_technology"] = rf_technology
        if sectors is not UNSET:
            field_dict["sectors"] = sectors
        if sources is not UNSET:
            field_dict["sources"] = sources

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.et_scada_rule import ETScadaRule  # noqa: PLC0415
        from ..models.fix_availability import FixAvailability  # noqa: PLC0415
        from ..models.icsnpp_parser import ICSNPPParser  # noqa: PLC0415
        from ..models.iec62443_summary import IEC62443Summary  # noqa: PLC0415
        from ..models.kev_ot_context import KevOTContext  # noqa: PLC0415
        from ..models.ot_sector import OTSector  # noqa: PLC0415

        d = dict(src_dict)

        def _parse_access_vector_rf(data: object) -> None | OTContextAccessVectorRfType0 | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, str):
                    raise TypeError()
                access_vector_rf_type_0 = OTContextAccessVectorRfType0(data)

                return access_vector_rf_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(None | OTContextAccessVectorRfType0 | Unset, data)

        access_vector_rf = _parse_access_vector_rf(d.pop("access_vector_rf", UNSET))

        def _parse_fix_availability(data: object) -> FixAvailability | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, dict):
                    raise TypeError()
                fix_availability_type_0 = FixAvailability.from_dict(data)

                return fix_availability_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(FixAvailability | None | Unset, data)

        fix_availability = _parse_fix_availability(d.pop("fix_availability", UNSET))

        def _parse_iec_62443(data: object) -> IEC62443Summary | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, dict):
                    raise TypeError()
                iec_62443_type_0 = IEC62443Summary.from_dict(data)

                return iec_62443_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(IEC62443Summary | None | Unset, data)

        iec_62443 = _parse_iec_62443(d.pop("iec_62443", UNSET))

        def _parse_kev_ot(data: object) -> KevOTContext | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, dict):
                    raise TypeError()
                kev_ot_type_0 = KevOTContext.from_dict(data)

                return kev_ot_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(KevOTContext | None | Unset, data)

        kev_ot = _parse_kev_ot(d.pop("kev_ot", UNSET))

        _network_detections = d.pop("network_detections", UNSET)
        network_detections: list[ETScadaRule] | Unset = UNSET
        if _network_detections is not UNSET:
            network_detections = []
            for network_detections_item_data in _network_detections:
                network_detections_item = ETScadaRule.from_dict(network_detections_item_data)

                network_detections.append(network_detections_item)

        network_detections_total = d.pop("network_detections_total", UNSET)

        _protocol_parsers = d.pop("protocol_parsers", UNSET)
        protocol_parsers: list[ICSNPPParser] | Unset = UNSET
        if _protocol_parsers is not UNSET:
            protocol_parsers = []
            for protocol_parsers_item_data in _protocol_parsers:
                protocol_parsers_item = ICSNPPParser.from_dict(protocol_parsers_item_data)

                protocol_parsers.append(protocol_parsers_item)

        protocols = cast(list[str], d.pop("protocols", UNSET))

        rf_evidence = cast(list[str], d.pop("rf_evidence", UNSET))

        rf_technology = cast(list[str], d.pop("rf_technology", UNSET))

        _sectors = d.pop("sectors", UNSET)
        sectors: list[OTSector] | Unset = UNSET
        if _sectors is not UNSET:
            sectors = []
            for sectors_item_data in _sectors:
                sectors_item = OTSector.from_dict(sectors_item_data)

                sectors.append(sectors_item)

        sources = cast(list[str], d.pop("sources", UNSET))

        ot_context = cls(
            access_vector_rf=access_vector_rf,
            fix_availability=fix_availability,
            iec_62443=iec_62443,
            kev_ot=kev_ot,
            network_detections=network_detections,
            network_detections_total=network_detections_total,
            protocol_parsers=protocol_parsers,
            protocols=protocols,
            rf_evidence=rf_evidence,
            rf_technology=rf_technology,
            sectors=sectors,
            sources=sources,
        )

        ot_context.additional_properties = d
        return ot_context

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

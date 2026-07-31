from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, BinaryIO, Generator, TextIO, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.exploit_detail import ExploitDetail
    from ..models.inventory_mitigation import InventoryMitigation
    from ..models.inventory_technique import InventoryTechnique
    from ..models.nist_control_mapping import NistControlMapping
    from ..models.ssvc_decision import SSVCDecision


T = TypeVar("T", bound="InventoryCVE")


@_attrs_define
class InventoryCVE:
    """A CVE captured on an inventory asset, curated from the per-product enrichment.

    Carries the per-CVE detail the Inventory Manager renders in its expand panel
    (description, KEV deadline/ransomware, ATT&CK techniques + mitigations) so the async
    Inventory enrichment result is a drop-in for the UI without a second fetch.

        Attributes:
            cve_id (str): CVE identifier
            cvss_score (float | None | Unset): CVSS base score (0.0-10.0)
            description (None | str | Unset): Vulnerability description (truncated)
            epss (float | None | Unset): EPSS exploit-probability score (0.0-1.0)
            exploits (list[ExploitDetail] | Unset): Authoritative exploit records associated with this CVE; returned with
                `include=exploits`
            fixed_version (None | str | Unset): Lowest version above the asset's current version that resolves this CVE (the
                upgrade target). Derived from OSV `fixed_versions` (package assets) — None when no fix is published or the
                version can't be ordered. Never fabricated.
            kev (bool | Unset): Whether the CVE is in CISA's KEV catalog Default: False.
            kev_date_added (None | str | Unset): CISA KEV dateAdded
            kev_due (None | str | Unset): CISA KEV remediation deadline, if listed
            kev_notes (None | str | Unset): CISA KEV notes
            kev_required_action (None | str | Unset): CISA KEV requiredAction
            kev_short_description (None | str | Unset): CISA KEV shortDescription
            kev_vendor_project (None | str | Unset): CISA KEV vendorProject
            kev_vulnerability_name (None | str | Unset): CISA KEV vulnerabilityName
            mitigations (list[InventoryMitigation] | Unset): Linked ATT&CK mitigations (courses of action)
            nist_controls (list[NistControlMapping] | Unset): NIST SP 800-53 controls via the CVE's ATT&CK techniques (top
                8); include=nist_controls
            poc_count (int | Unset): Public PoC-in-GitHub repo count; include=poc Default: 0.
            ransomware (bool | Unset): KEV-flagged known ransomware campaign use Default: False.
            ssvc (None | SSVCDecision | Unset): CERT/CC Deployer SSVC decision (act-now/track/attend/defer); include=ssvc
            techniques (list[InventoryTechnique] | Unset): Linked ATT&CK techniques (id + name)
            weaponization_score (float | None | Unset): 0-100 composite attack score
    """

    cve_id: str
    cvss_score: float | None | Unset = UNSET
    description: None | str | Unset = UNSET
    epss: float | None | Unset = UNSET
    exploits: list[ExploitDetail] | Unset = UNSET
    fixed_version: None | str | Unset = UNSET
    kev: bool | Unset = False
    kev_date_added: None | str | Unset = UNSET
    kev_due: None | str | Unset = UNSET
    kev_notes: None | str | Unset = UNSET
    kev_required_action: None | str | Unset = UNSET
    kev_short_description: None | str | Unset = UNSET
    kev_vendor_project: None | str | Unset = UNSET
    kev_vulnerability_name: None | str | Unset = UNSET
    mitigations: list[InventoryMitigation] | Unset = UNSET
    nist_controls: list[NistControlMapping] | Unset = UNSET
    poc_count: int | Unset = 0
    ransomware: bool | Unset = False
    ssvc: None | SSVCDecision | Unset = UNSET
    techniques: list[InventoryTechnique] | Unset = UNSET
    weaponization_score: float | None | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        from ..models.exploit_detail import ExploitDetail
        from ..models.inventory_mitigation import InventoryMitigation
        from ..models.inventory_technique import InventoryTechnique
        from ..models.nist_control_mapping import NistControlMapping
        from ..models.ssvc_decision import SSVCDecision

        cve_id = self.cve_id

        cvss_score: float | None | Unset
        if isinstance(self.cvss_score, Unset):
            cvss_score = UNSET
        else:
            cvss_score = self.cvss_score

        description: None | str | Unset
        if isinstance(self.description, Unset):
            description = UNSET
        else:
            description = self.description

        epss: float | None | Unset
        if isinstance(self.epss, Unset):
            epss = UNSET
        else:
            epss = self.epss

        exploits: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.exploits, Unset):
            exploits = []
            for exploits_item_data in self.exploits:
                exploits_item = exploits_item_data.to_dict()
                exploits.append(exploits_item)

        fixed_version: None | str | Unset
        if isinstance(self.fixed_version, Unset):
            fixed_version = UNSET
        else:
            fixed_version = self.fixed_version

        kev = self.kev

        kev_date_added: None | str | Unset
        if isinstance(self.kev_date_added, Unset):
            kev_date_added = UNSET
        else:
            kev_date_added = self.kev_date_added

        kev_due: None | str | Unset
        if isinstance(self.kev_due, Unset):
            kev_due = UNSET
        else:
            kev_due = self.kev_due

        kev_notes: None | str | Unset
        if isinstance(self.kev_notes, Unset):
            kev_notes = UNSET
        else:
            kev_notes = self.kev_notes

        kev_required_action: None | str | Unset
        if isinstance(self.kev_required_action, Unset):
            kev_required_action = UNSET
        else:
            kev_required_action = self.kev_required_action

        kev_short_description: None | str | Unset
        if isinstance(self.kev_short_description, Unset):
            kev_short_description = UNSET
        else:
            kev_short_description = self.kev_short_description

        kev_vendor_project: None | str | Unset
        if isinstance(self.kev_vendor_project, Unset):
            kev_vendor_project = UNSET
        else:
            kev_vendor_project = self.kev_vendor_project

        kev_vulnerability_name: None | str | Unset
        if isinstance(self.kev_vulnerability_name, Unset):
            kev_vulnerability_name = UNSET
        else:
            kev_vulnerability_name = self.kev_vulnerability_name

        mitigations: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.mitigations, Unset):
            mitigations = []
            for mitigations_item_data in self.mitigations:
                mitigations_item = mitigations_item_data.to_dict()
                mitigations.append(mitigations_item)

        nist_controls: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.nist_controls, Unset):
            nist_controls = []
            for nist_controls_item_data in self.nist_controls:
                nist_controls_item = nist_controls_item_data.to_dict()
                nist_controls.append(nist_controls_item)

        poc_count = self.poc_count

        ransomware = self.ransomware

        ssvc: dict[str, Any] | None | Unset
        if isinstance(self.ssvc, Unset):
            ssvc = UNSET
        elif isinstance(self.ssvc, SSVCDecision):
            ssvc = self.ssvc.to_dict()
        else:
            ssvc = self.ssvc

        techniques: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.techniques, Unset):
            techniques = []
            for techniques_item_data in self.techniques:
                techniques_item = techniques_item_data.to_dict()
                techniques.append(techniques_item)

        weaponization_score: float | None | Unset
        if isinstance(self.weaponization_score, Unset):
            weaponization_score = UNSET
        else:
            weaponization_score = self.weaponization_score

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "cve_id": cve_id,
            }
        )
        if cvss_score is not UNSET:
            field_dict["cvss_score"] = cvss_score
        if description is not UNSET:
            field_dict["description"] = description
        if epss is not UNSET:
            field_dict["epss"] = epss
        if exploits is not UNSET:
            field_dict["exploits"] = exploits
        if fixed_version is not UNSET:
            field_dict["fixed_version"] = fixed_version
        if kev is not UNSET:
            field_dict["kev"] = kev
        if kev_date_added is not UNSET:
            field_dict["kev_date_added"] = kev_date_added
        if kev_due is not UNSET:
            field_dict["kev_due"] = kev_due
        if kev_notes is not UNSET:
            field_dict["kev_notes"] = kev_notes
        if kev_required_action is not UNSET:
            field_dict["kev_required_action"] = kev_required_action
        if kev_short_description is not UNSET:
            field_dict["kev_short_description"] = kev_short_description
        if kev_vendor_project is not UNSET:
            field_dict["kev_vendor_project"] = kev_vendor_project
        if kev_vulnerability_name is not UNSET:
            field_dict["kev_vulnerability_name"] = kev_vulnerability_name
        if mitigations is not UNSET:
            field_dict["mitigations"] = mitigations
        if nist_controls is not UNSET:
            field_dict["nist_controls"] = nist_controls
        if poc_count is not UNSET:
            field_dict["poc_count"] = poc_count
        if ransomware is not UNSET:
            field_dict["ransomware"] = ransomware
        if ssvc is not UNSET:
            field_dict["ssvc"] = ssvc
        if techniques is not UNSET:
            field_dict["techniques"] = techniques
        if weaponization_score is not UNSET:
            field_dict["weaponization_score"] = weaponization_score

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.exploit_detail import ExploitDetail
        from ..models.inventory_mitigation import InventoryMitigation
        from ..models.inventory_technique import InventoryTechnique
        from ..models.nist_control_mapping import NistControlMapping
        from ..models.ssvc_decision import SSVCDecision

        d = dict(src_dict)
        cve_id = d.pop("cve_id")

        def _parse_cvss_score(data: object) -> float | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(float | None | Unset, data)

        cvss_score = _parse_cvss_score(d.pop("cvss_score", UNSET))

        def _parse_description(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        description = _parse_description(d.pop("description", UNSET))

        def _parse_epss(data: object) -> float | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(float | None | Unset, data)

        epss = _parse_epss(d.pop("epss", UNSET))

        _exploits = d.pop("exploits", UNSET)
        exploits: list[ExploitDetail] | Unset = UNSET
        if _exploits is not UNSET:
            exploits = []
            for exploits_item_data in _exploits:
                exploits_item = ExploitDetail.from_dict(exploits_item_data)

                exploits.append(exploits_item)

        def _parse_fixed_version(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        fixed_version = _parse_fixed_version(d.pop("fixed_version", UNSET))

        kev = d.pop("kev", UNSET)

        def _parse_kev_date_added(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        kev_date_added = _parse_kev_date_added(d.pop("kev_date_added", UNSET))

        def _parse_kev_due(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        kev_due = _parse_kev_due(d.pop("kev_due", UNSET))

        def _parse_kev_notes(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        kev_notes = _parse_kev_notes(d.pop("kev_notes", UNSET))

        def _parse_kev_required_action(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        kev_required_action = _parse_kev_required_action(d.pop("kev_required_action", UNSET))

        def _parse_kev_short_description(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        kev_short_description = _parse_kev_short_description(d.pop("kev_short_description", UNSET))

        def _parse_kev_vendor_project(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        kev_vendor_project = _parse_kev_vendor_project(d.pop("kev_vendor_project", UNSET))

        def _parse_kev_vulnerability_name(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        kev_vulnerability_name = _parse_kev_vulnerability_name(d.pop("kev_vulnerability_name", UNSET))

        _mitigations = d.pop("mitigations", UNSET)
        mitigations: list[InventoryMitigation] | Unset = UNSET
        if _mitigations is not UNSET:
            mitigations = []
            for mitigations_item_data in _mitigations:
                mitigations_item = InventoryMitigation.from_dict(mitigations_item_data)

                mitigations.append(mitigations_item)

        _nist_controls = d.pop("nist_controls", UNSET)
        nist_controls: list[NistControlMapping] | Unset = UNSET
        if _nist_controls is not UNSET:
            nist_controls = []
            for nist_controls_item_data in _nist_controls:
                nist_controls_item = NistControlMapping.from_dict(nist_controls_item_data)

                nist_controls.append(nist_controls_item)

        poc_count = d.pop("poc_count", UNSET)

        ransomware = d.pop("ransomware", UNSET)

        def _parse_ssvc(data: object) -> None | SSVCDecision | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, dict):
                    raise TypeError()
                ssvc_type_0 = SSVCDecision.from_dict(data)

                return ssvc_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(None | SSVCDecision | Unset, data)

        ssvc = _parse_ssvc(d.pop("ssvc", UNSET))

        _techniques = d.pop("techniques", UNSET)
        techniques: list[InventoryTechnique] | Unset = UNSET
        if _techniques is not UNSET:
            techniques = []
            for techniques_item_data in _techniques:
                techniques_item = InventoryTechnique.from_dict(techniques_item_data)

                techniques.append(techniques_item)

        def _parse_weaponization_score(data: object) -> float | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(float | None | Unset, data)

        weaponization_score = _parse_weaponization_score(d.pop("weaponization_score", UNSET))

        inventory_cve = cls(
            cve_id=cve_id,
            cvss_score=cvss_score,
            description=description,
            epss=epss,
            exploits=exploits,
            fixed_version=fixed_version,
            kev=kev,
            kev_date_added=kev_date_added,
            kev_due=kev_due,
            kev_notes=kev_notes,
            kev_required_action=kev_required_action,
            kev_short_description=kev_short_description,
            kev_vendor_project=kev_vendor_project,
            kev_vulnerability_name=kev_vulnerability_name,
            mitigations=mitigations,
            nist_controls=nist_controls,
            poc_count=poc_count,
            ransomware=ransomware,
            ssvc=ssvc,
            techniques=techniques,
            weaponization_score=weaponization_score,
        )

        inventory_cve.additional_properties = d
        return inventory_cve

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

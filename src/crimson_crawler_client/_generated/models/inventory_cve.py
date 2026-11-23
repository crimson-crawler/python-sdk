from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, BinaryIO, Generator, TextIO, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..models.inventory_cve_techniques_provenance_type_0 import InventoryCVETechniquesProvenanceType0
from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.android_bulletin import AndroidBulletin
    from ..models.cellular_annotation import CellularAnnotation
    from ..models.cellular_core_entry import CellularCoreEntry
    from ..models.cert_fr_advisory import CertFRAdvisory
    from ..models.cisa_campaign_advisory import CISACampaignAdvisory
    from ..models.csaf_remediation import CSAFRemediation
    from ..models.cvssbt_score import CVSSBTScore
    from ..models.emb3d_threat import EMB3DThreat
    from ..models.exploit_detail import ExploitDetail
    from ..models.ics_weakness import ICSWeakness
    from ..models.iec62443_requirement import IEC62443Requirement
    from ..models.inventory_metasploit_module import InventoryMetasploitModule
    from ..models.inventory_mitigation import InventoryMitigation
    from ..models.inventory_nuclei_template import InventoryNucleiTemplate
    from ..models.inventory_technique import InventoryTechnique
    from ..models.jvn_advisory import JVNAdvisory
    from ..models.lev_estimate import LEVEstimate
    from ..models.nist_control_mapping import NistControlMapping
    from ..models.osv_advisory import OSVAdvisory
    from ..models.ot_context import OTContext
    from ..models.ot_vendor_advisory import OTVendorAdvisory
    from ..models.sigma_rule import SigmaRule
    from ..models.source_stamp import SourceStamp
    from ..models.ssvc_decision import SSVCDecision
    from ..models.vulnrichment import Vulnrichment
    from ..models.weakness_rank import WeaknessRank


T = TypeVar("T", bound="InventoryCVE")


@_attrs_define
class InventoryCVE:
    """A CVE captured on an inventory asset, curated from the per-product enrichment.

    Carries the per-CVE detail the Inventory Manager renders in its expand panel
    (description, KEV deadline/ransomware, ATT&CK techniques + mitigations) so the async
    Inventory enrichment result is a drop-in for the UI without a second fetch.

        Attributes:
            cve_id (str): CVE identifier
            android_bulletin (AndroidBulletin | None | Unset): The stored Android Security Bulletin record this CVE names
                (`ASB-A-*`), when the inventory enrichment includes `android_bulletin`.
            cellular_annotations (list[CellularAnnotation] | Unset): Rows of the 5G CVE-annotated dataset (Zenodo 17450053,
                CC-BY-4.0) for this CVE. Opt-in via the product include set; a zero-cost in-process read of the committed
                corpus.
            cellular_core_entries (list[CellularCoreEntry] | Unset): The RANsacked cellular-core implementation row for this
                CVE. Opt-in via the product include set; a zero-cost in-process read.
            certfr_advisories (list[CertFRAdvisory] | Unset): CERT-FR (ANSSI) advisories and alerts that reference this CVE,
                with the reference id, title, last revision date, canonical page URL, CVE ids, the advisory's own `scada` flag,
                affected vendors/products and its published risk descriptions — link and metadata only, never the advisory body.
                Opt-in via include=['certfr_advisories']; read from the seeded corpus. A missing corpus is []; a corrupt one is
                [] plus an `errors[]` entry (step `fetch_certfr`).
            cisa_campaigns (list[CISACampaignAdvisory] | Unset): CISA joint cybersecurity advisories (AA-series) whose STIX
                bundle names this CVE. Opt-in via the product include set; a zero-cost in-process read of the seeded corpus.
            csaf_advisory_ids (list[str] | Unset): CSAF vendor advisory tracking ids naming this CVE (opt-in via the product
                include set).
            csaf_remediations (list[CSAFRemediation] | Unset): Remediations the matching CSAF advisories publish for this
                CVE (opt-in via the include set).
            cvss_bt (CVSSBTScore | None | Unset): The cvss-bt corpus row for this CVE (Base+Threat composite, severity,
                KEV/exploit flags). Opt-in via the product include set; a stale cached CVE dict drops this signal only.
            cvss_v2_score (float | None | Unset): CVSS v2.0 base score (0.0-10.0)
            cvss_v3_score (float | None | Unset): CVSS v3.x base score (0.0-10.0)
            cvss_v3_vector (None | str | Unset): CVSS v3.x vector string (CVSS:3.1/...)
            cvss_v3_version (None | str | Unset): Which v3 revision `cvss_v3_score` holds — '3.1' or '3.0'
            cvss_v4_score (float | None | Unset): CVSS v4.0 base score (0.0-10.0)
            cvss_v4_vector (None | str | Unset): CVSS v4.0 vector string (CVSS:4.0/...)
            cwe_ids (list[str] | Unset): CWE weaknesses the CVE record names
            description (None | str | Unset): Vulnerability description, in full — consumers truncate for their own
                destination
            emb3d_threats (list[EMB3DThreat] | Unset): MITRE EMB3D embedded/hardware threats joined to this CVE's CWE ids,
                each with the countermeasures EMB3D names (`include=emb3d`). A zero-cost in-process corpus read.
            epss (float | None | Unset): EPSS exploit-probability score (0.0-1.0)
            epss_percentile (float | None | Unset): EPSS percentile (0-1): rank among all scored CVEs; not a probability
            exploits (list[ExploitDetail] | Unset): Authoritative exploit records associated with this CVE; returned with
                `include=exploits`
            fixed_version (None | str | Unset): Lowest version above the asset's current version that resolves this CVE (the
                upgrade target). Derived from OSV `fixed_versions` (package assets) — None when no fix is published or the
                version can't be ordered. Never fabricated.
            ics_weakness (list[ICSWeakness] | Unset): CWE-1358 ICS-view members among this CVE's weaknesses
                (`include=weakness_ranks`).
            iec_62443_requirements (list[IEC62443Requirement] | Unset): ISA/IEC 62443 requirement mappings for this CVE's
                weaknesses (`include=weakness_ranks`).
            jvn_advisories (list[JVNAdvisory] | Unset): JVNDB advisories referencing this CVE (link + metadata only). Opt-in
                via the product include set; a zero-cost in-process read.
            kev (bool | Unset): Whether the CVE is in CISA's KEV catalog Default: False.
            kev_cwe_ids (list[str] | Unset): Weaknesses CISA's KEV record lists for this CVE
            kev_date_added (None | str | Unset): CISA KEV dateAdded
            kev_due (None | str | Unset): CISA KEV remediation deadline, if listed
            kev_forensic_triage (None | str | Unset): CISA KEV forensicTriage ('Yes'/'No'): CISA advises forensic review,
                not just patching
            kev_notes (None | str | Unset): CISA KEV notes
            kev_required_action (None | str | Unset): CISA KEV requiredAction
            kev_short_description (None | str | Unset): CISA KEV shortDescription
            kev_vendor_project (None | str | Unset): CISA KEV vendorProject
            kev_vulnerability_name (None | str | Unset): CISA KEV vulnerabilityName
            lev (LEVEstimate | None | Unset): NIST LEV2: lower bound on the probability it was already exploited (EPSS
                history on record)
            metasploit_modules (list[InventoryMetasploitModule] | Unset): Metasploit modules naming this CVE (weaponised
                exploit availability)
            mitigations (list[InventoryMitigation] | Unset): Linked ATT&CK mitigations (courses of action)
            nist_controls (list[NistControlMapping] | Unset): NIST SP 800-53 controls via the CVE's ATT&CK techniques (top
                8); include=nist_controls
            nuclei_templates (list[InventoryNucleiTemplate] | Unset): Nuclei detection templates naming this CVE (scanner
                coverage)
            osv_advisories (list[OSVAdvisory] | None | Unset): OSV advisories for this CVE when explicitly requested
            osv_ids (list[str] | Unset): OSV.dev / GHSA advisory ids that alias this CVE (package assets — from the
                advisories already fetched for the asset)
            ot_context (None | OTContext | Unset): OT/RF context for this CVE (sectors, protocols, fix availability, KEV OT,
                RF technology, 62443). Opt-in via the product include set; derived by the nested `/v1/enrich/cve` call.
            ot_vendor_advisories (list[OTVendorAdvisory] | Unset): Direct OT/embedded vendor advisories naming this CVE —
                Rockwell Automation and MediaTek (`ot_vendor_advisories[]`), with CVE ids, CVSS scores, products and MediaTek
                chipset codes. Link and metadata only. Opt-in via include=['ot_vendor_advisories']; a zero-cost in-process read
                of the seeded corpus.
            poc_count (int | Unset): Public PoC-in-GitHub repo count; include=poc Default: 0.
            provenance (list[SourceStamp] | Unset): Which source supplied which fields, with its as-of date
            published (None | str | Unset): CVE publication date (ISO 8601)
            ransomware (bool | Unset): KEV-flagged known ransomware campaign use Default: False.
            sigma_rules (list[SigmaRule] | Unset): Sigma detection rules the committed corpus maps to this CVE's techniques.
                Opt-in via the product include set; a zero-cost in-process read.
            ssvc (None | SSVCDecision | Unset): CERT/CC Deployer SSVC decision (act-now/track/attend/defer); include=ssvc
            suppressed_by_vex (bool | Unset): True when the inventory's VEX overlay marks this CVE not_affected/fixed on
                this asset; the finding is retained (auditable) but excluded from actionable counts. Default: False.
            techniques (list[InventoryTechnique] | Unset): Linked ATT&CK techniques (id + name)
            techniques_provenance (InventoryCVETechniquesProvenanceType0 | None | Unset): How `techniques` (and so
                `mitigations`) were linked: `cwe_closure` through a specific CWE's CAPEC closure, shared by every CVE with that
                weakness; `cwe_class` through a generic CWE's closure, which applies to many unrelated CVEs; `heuristic` through
                an indirect fallback; `cve_specific` only when the CVE records no CWE.
            vex_justification (None | str | Unset): The VEX statement's justification/notes when `suppressed_by_vex` is true
                (OpenVEX `justification`, or the CSAF vulnerability notes text).
            vuln_status (None | str | Unset): NVD processing status (Analyzed, Modified, Deferred, …)
            vulnrichment (None | Unset | Vulnrichment): CISA Vulnrichment ADP data for this CVE (extra CWEs, KEV, the
                Coordinator's SSVC as `adp_ssvc`). Never written into the asset's own SSVC decision.
            weakness_ranks (list[WeaknessRank] | Unset): CWE Top 25 / OWASP Top 10 / API / LLM ranked-list positions this
                CVE's weaknesses occupy (`include=weakness_ranks`). A zero-cost in-process corpus read; a prioritization signal,
                never a scoring input.
            weaponization_score (float | None | Unset): 0-100 composite attack score
    """

    cve_id: str
    android_bulletin: AndroidBulletin | None | Unset = UNSET
    cellular_annotations: list[CellularAnnotation] | Unset = UNSET
    cellular_core_entries: list[CellularCoreEntry] | Unset = UNSET
    certfr_advisories: list[CertFRAdvisory] | Unset = UNSET
    cisa_campaigns: list[CISACampaignAdvisory] | Unset = UNSET
    csaf_advisory_ids: list[str] | Unset = UNSET
    csaf_remediations: list[CSAFRemediation] | Unset = UNSET
    cvss_bt: CVSSBTScore | None | Unset = UNSET
    cvss_v2_score: float | None | Unset = UNSET
    cvss_v3_score: float | None | Unset = UNSET
    cvss_v3_vector: None | str | Unset = UNSET
    cvss_v3_version: None | str | Unset = UNSET
    cvss_v4_score: float | None | Unset = UNSET
    cvss_v4_vector: None | str | Unset = UNSET
    cwe_ids: list[str] | Unset = UNSET
    description: None | str | Unset = UNSET
    emb3d_threats: list[EMB3DThreat] | Unset = UNSET
    epss: float | None | Unset = UNSET
    epss_percentile: float | None | Unset = UNSET
    exploits: list[ExploitDetail] | Unset = UNSET
    fixed_version: None | str | Unset = UNSET
    ics_weakness: list[ICSWeakness] | Unset = UNSET
    iec_62443_requirements: list[IEC62443Requirement] | Unset = UNSET
    jvn_advisories: list[JVNAdvisory] | Unset = UNSET
    kev: bool | Unset = False
    kev_cwe_ids: list[str] | Unset = UNSET
    kev_date_added: None | str | Unset = UNSET
    kev_due: None | str | Unset = UNSET
    kev_forensic_triage: None | str | Unset = UNSET
    kev_notes: None | str | Unset = UNSET
    kev_required_action: None | str | Unset = UNSET
    kev_short_description: None | str | Unset = UNSET
    kev_vendor_project: None | str | Unset = UNSET
    kev_vulnerability_name: None | str | Unset = UNSET
    lev: LEVEstimate | None | Unset = UNSET
    metasploit_modules: list[InventoryMetasploitModule] | Unset = UNSET
    mitigations: list[InventoryMitigation] | Unset = UNSET
    nist_controls: list[NistControlMapping] | Unset = UNSET
    nuclei_templates: list[InventoryNucleiTemplate] | Unset = UNSET
    osv_advisories: list[OSVAdvisory] | None | Unset = UNSET
    osv_ids: list[str] | Unset = UNSET
    ot_context: None | OTContext | Unset = UNSET
    ot_vendor_advisories: list[OTVendorAdvisory] | Unset = UNSET
    poc_count: int | Unset = 0
    provenance: list[SourceStamp] | Unset = UNSET
    published: None | str | Unset = UNSET
    ransomware: bool | Unset = False
    sigma_rules: list[SigmaRule] | Unset = UNSET
    ssvc: None | SSVCDecision | Unset = UNSET
    suppressed_by_vex: bool | Unset = False
    techniques: list[InventoryTechnique] | Unset = UNSET
    techniques_provenance: InventoryCVETechniquesProvenanceType0 | None | Unset = UNSET
    vex_justification: None | str | Unset = UNSET
    vuln_status: None | str | Unset = UNSET
    vulnrichment: None | Unset | Vulnrichment = UNSET
    weakness_ranks: list[WeaknessRank] | Unset = UNSET
    weaponization_score: float | None | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        from ..models.android_bulletin import AndroidBulletin  # noqa: PLC0415
        from ..models.cellular_annotation import CellularAnnotation  # noqa: PLC0415
        from ..models.cellular_core_entry import CellularCoreEntry  # noqa: PLC0415
        from ..models.cert_fr_advisory import CertFRAdvisory  # noqa: PLC0415
        from ..models.cisa_campaign_advisory import CISACampaignAdvisory  # noqa: PLC0415
        from ..models.csaf_remediation import CSAFRemediation  # noqa: PLC0415
        from ..models.cvssbt_score import CVSSBTScore  # noqa: PLC0415
        from ..models.emb3d_threat import EMB3DThreat  # noqa: PLC0415
        from ..models.exploit_detail import ExploitDetail  # noqa: PLC0415
        from ..models.ics_weakness import ICSWeakness  # noqa: PLC0415
        from ..models.iec62443_requirement import IEC62443Requirement  # noqa: PLC0415
        from ..models.inventory_metasploit_module import InventoryMetasploitModule  # noqa: PLC0415
        from ..models.inventory_mitigation import InventoryMitigation  # noqa: PLC0415
        from ..models.inventory_nuclei_template import InventoryNucleiTemplate  # noqa: PLC0415
        from ..models.inventory_technique import InventoryTechnique  # noqa: PLC0415
        from ..models.jvn_advisory import JVNAdvisory  # noqa: PLC0415
        from ..models.lev_estimate import LEVEstimate  # noqa: PLC0415
        from ..models.nist_control_mapping import NistControlMapping  # noqa: PLC0415
        from ..models.osv_advisory import OSVAdvisory  # noqa: PLC0415
        from ..models.ot_context import OTContext  # noqa: PLC0415
        from ..models.ot_vendor_advisory import OTVendorAdvisory  # noqa: PLC0415
        from ..models.sigma_rule import SigmaRule  # noqa: PLC0415
        from ..models.source_stamp import SourceStamp  # noqa: PLC0415
        from ..models.ssvc_decision import SSVCDecision  # noqa: PLC0415
        from ..models.vulnrichment import Vulnrichment  # noqa: PLC0415
        from ..models.weakness_rank import WeaknessRank  # noqa: PLC0415

        cve_id = self.cve_id

        android_bulletin: dict[str, Any] | None | Unset
        if isinstance(self.android_bulletin, Unset):
            android_bulletin = UNSET
        elif isinstance(self.android_bulletin, AndroidBulletin):
            android_bulletin = self.android_bulletin.to_dict()
        else:
            android_bulletin = self.android_bulletin

        cellular_annotations: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.cellular_annotations, Unset):
            cellular_annotations = []
            for cellular_annotations_item_data in self.cellular_annotations:
                cellular_annotations_item = cellular_annotations_item_data.to_dict()
                cellular_annotations.append(cellular_annotations_item)

        cellular_core_entries: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.cellular_core_entries, Unset):
            cellular_core_entries = []
            for cellular_core_entries_item_data in self.cellular_core_entries:
                cellular_core_entries_item = cellular_core_entries_item_data.to_dict()
                cellular_core_entries.append(cellular_core_entries_item)

        certfr_advisories: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.certfr_advisories, Unset):
            certfr_advisories = []
            for certfr_advisories_item_data in self.certfr_advisories:
                certfr_advisories_item = certfr_advisories_item_data.to_dict()
                certfr_advisories.append(certfr_advisories_item)

        cisa_campaigns: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.cisa_campaigns, Unset):
            cisa_campaigns = []
            for cisa_campaigns_item_data in self.cisa_campaigns:
                cisa_campaigns_item = cisa_campaigns_item_data.to_dict()
                cisa_campaigns.append(cisa_campaigns_item)

        csaf_advisory_ids: list[str] | Unset = UNSET
        if not isinstance(self.csaf_advisory_ids, Unset):
            csaf_advisory_ids = self.csaf_advisory_ids

        csaf_remediations: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.csaf_remediations, Unset):
            csaf_remediations = []
            for csaf_remediations_item_data in self.csaf_remediations:
                csaf_remediations_item = csaf_remediations_item_data.to_dict()
                csaf_remediations.append(csaf_remediations_item)

        cvss_bt: dict[str, Any] | None | Unset
        if isinstance(self.cvss_bt, Unset):
            cvss_bt = UNSET
        elif isinstance(self.cvss_bt, CVSSBTScore):
            cvss_bt = self.cvss_bt.to_dict()
        else:
            cvss_bt = self.cvss_bt

        cvss_v2_score: float | None | Unset
        if isinstance(self.cvss_v2_score, Unset):
            cvss_v2_score = UNSET
        else:
            cvss_v2_score = self.cvss_v2_score

        cvss_v3_score: float | None | Unset
        if isinstance(self.cvss_v3_score, Unset):
            cvss_v3_score = UNSET
        else:
            cvss_v3_score = self.cvss_v3_score

        cvss_v3_vector: None | str | Unset
        if isinstance(self.cvss_v3_vector, Unset):
            cvss_v3_vector = UNSET
        else:
            cvss_v3_vector = self.cvss_v3_vector

        cvss_v3_version: None | str | Unset
        if isinstance(self.cvss_v3_version, Unset):
            cvss_v3_version = UNSET
        else:
            cvss_v3_version = self.cvss_v3_version

        cvss_v4_score: float | None | Unset
        if isinstance(self.cvss_v4_score, Unset):
            cvss_v4_score = UNSET
        else:
            cvss_v4_score = self.cvss_v4_score

        cvss_v4_vector: None | str | Unset
        if isinstance(self.cvss_v4_vector, Unset):
            cvss_v4_vector = UNSET
        else:
            cvss_v4_vector = self.cvss_v4_vector

        cwe_ids: list[str] | Unset = UNSET
        if not isinstance(self.cwe_ids, Unset):
            cwe_ids = self.cwe_ids

        description: None | str | Unset
        if isinstance(self.description, Unset):
            description = UNSET
        else:
            description = self.description

        emb3d_threats: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.emb3d_threats, Unset):
            emb3d_threats = []
            for emb3d_threats_item_data in self.emb3d_threats:
                emb3d_threats_item = emb3d_threats_item_data.to_dict()
                emb3d_threats.append(emb3d_threats_item)

        epss: float | None | Unset
        if isinstance(self.epss, Unset):
            epss = UNSET
        else:
            epss = self.epss

        epss_percentile: float | None | Unset
        if isinstance(self.epss_percentile, Unset):
            epss_percentile = UNSET
        else:
            epss_percentile = self.epss_percentile

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

        ics_weakness: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.ics_weakness, Unset):
            ics_weakness = []
            for ics_weakness_item_data in self.ics_weakness:
                ics_weakness_item = ics_weakness_item_data.to_dict()
                ics_weakness.append(ics_weakness_item)

        iec_62443_requirements: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.iec_62443_requirements, Unset):
            iec_62443_requirements = []
            for iec_62443_requirements_item_data in self.iec_62443_requirements:
                iec_62443_requirements_item = iec_62443_requirements_item_data.to_dict()
                iec_62443_requirements.append(iec_62443_requirements_item)

        jvn_advisories: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.jvn_advisories, Unset):
            jvn_advisories = []
            for jvn_advisories_item_data in self.jvn_advisories:
                jvn_advisories_item = jvn_advisories_item_data.to_dict()
                jvn_advisories.append(jvn_advisories_item)

        kev = self.kev

        kev_cwe_ids: list[str] | Unset = UNSET
        if not isinstance(self.kev_cwe_ids, Unset):
            kev_cwe_ids = self.kev_cwe_ids

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

        kev_forensic_triage: None | str | Unset
        if isinstance(self.kev_forensic_triage, Unset):
            kev_forensic_triage = UNSET
        else:
            kev_forensic_triage = self.kev_forensic_triage

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

        lev: dict[str, Any] | None | Unset
        if isinstance(self.lev, Unset):
            lev = UNSET
        elif isinstance(self.lev, LEVEstimate):
            lev = self.lev.to_dict()
        else:
            lev = self.lev

        metasploit_modules: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.metasploit_modules, Unset):
            metasploit_modules = []
            for metasploit_modules_item_data in self.metasploit_modules:
                metasploit_modules_item = metasploit_modules_item_data.to_dict()
                metasploit_modules.append(metasploit_modules_item)

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

        nuclei_templates: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.nuclei_templates, Unset):
            nuclei_templates = []
            for nuclei_templates_item_data in self.nuclei_templates:
                nuclei_templates_item = nuclei_templates_item_data.to_dict()
                nuclei_templates.append(nuclei_templates_item)

        osv_advisories: list[dict[str, Any]] | None | Unset
        if isinstance(self.osv_advisories, Unset):
            osv_advisories = UNSET
        elif isinstance(self.osv_advisories, list):
            osv_advisories = []
            for osv_advisories_type_0_item_data in self.osv_advisories:
                osv_advisories_type_0_item = osv_advisories_type_0_item_data.to_dict()
                osv_advisories.append(osv_advisories_type_0_item)

        else:
            osv_advisories = self.osv_advisories

        osv_ids: list[str] | Unset = UNSET
        if not isinstance(self.osv_ids, Unset):
            osv_ids = self.osv_ids

        ot_context: dict[str, Any] | None | Unset
        if isinstance(self.ot_context, Unset):
            ot_context = UNSET
        elif isinstance(self.ot_context, OTContext):
            ot_context = self.ot_context.to_dict()
        else:
            ot_context = self.ot_context

        ot_vendor_advisories: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.ot_vendor_advisories, Unset):
            ot_vendor_advisories = []
            for ot_vendor_advisories_item_data in self.ot_vendor_advisories:
                ot_vendor_advisories_item = ot_vendor_advisories_item_data.to_dict()
                ot_vendor_advisories.append(ot_vendor_advisories_item)

        poc_count = self.poc_count

        provenance: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.provenance, Unset):
            provenance = []
            for provenance_item_data in self.provenance:
                provenance_item = provenance_item_data.to_dict()
                provenance.append(provenance_item)

        published: None | str | Unset
        if isinstance(self.published, Unset):
            published = UNSET
        else:
            published = self.published

        ransomware = self.ransomware

        sigma_rules: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.sigma_rules, Unset):
            sigma_rules = []
            for sigma_rules_item_data in self.sigma_rules:
                sigma_rules_item = sigma_rules_item_data.to_dict()
                sigma_rules.append(sigma_rules_item)

        ssvc: dict[str, Any] | None | Unset
        if isinstance(self.ssvc, Unset):
            ssvc = UNSET
        elif isinstance(self.ssvc, SSVCDecision):
            ssvc = self.ssvc.to_dict()
        else:
            ssvc = self.ssvc

        suppressed_by_vex = self.suppressed_by_vex

        techniques: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.techniques, Unset):
            techniques = []
            for techniques_item_data in self.techniques:
                techniques_item = techniques_item_data.to_dict()
                techniques.append(techniques_item)

        techniques_provenance: None | str | Unset
        if isinstance(self.techniques_provenance, Unset):
            techniques_provenance = UNSET
        elif isinstance(self.techniques_provenance, InventoryCVETechniquesProvenanceType0):
            techniques_provenance = self.techniques_provenance.value
        else:
            techniques_provenance = self.techniques_provenance

        vex_justification: None | str | Unset
        if isinstance(self.vex_justification, Unset):
            vex_justification = UNSET
        else:
            vex_justification = self.vex_justification

        vuln_status: None | str | Unset
        if isinstance(self.vuln_status, Unset):
            vuln_status = UNSET
        else:
            vuln_status = self.vuln_status

        vulnrichment: dict[str, Any] | None | Unset
        if isinstance(self.vulnrichment, Unset):
            vulnrichment = UNSET
        elif isinstance(self.vulnrichment, Vulnrichment):
            vulnrichment = self.vulnrichment.to_dict()
        else:
            vulnrichment = self.vulnrichment

        weakness_ranks: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.weakness_ranks, Unset):
            weakness_ranks = []
            for weakness_ranks_item_data in self.weakness_ranks:
                weakness_ranks_item = weakness_ranks_item_data.to_dict()
                weakness_ranks.append(weakness_ranks_item)

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
        if android_bulletin is not UNSET:
            field_dict["android_bulletin"] = android_bulletin
        if cellular_annotations is not UNSET:
            field_dict["cellular_annotations"] = cellular_annotations
        if cellular_core_entries is not UNSET:
            field_dict["cellular_core_entries"] = cellular_core_entries
        if certfr_advisories is not UNSET:
            field_dict["certfr_advisories"] = certfr_advisories
        if cisa_campaigns is not UNSET:
            field_dict["cisa_campaigns"] = cisa_campaigns
        if csaf_advisory_ids is not UNSET:
            field_dict["csaf_advisory_ids"] = csaf_advisory_ids
        if csaf_remediations is not UNSET:
            field_dict["csaf_remediations"] = csaf_remediations
        if cvss_bt is not UNSET:
            field_dict["cvss_bt"] = cvss_bt
        if cvss_v2_score is not UNSET:
            field_dict["cvss_v2_score"] = cvss_v2_score
        if cvss_v3_score is not UNSET:
            field_dict["cvss_v3_score"] = cvss_v3_score
        if cvss_v3_vector is not UNSET:
            field_dict["cvss_v3_vector"] = cvss_v3_vector
        if cvss_v3_version is not UNSET:
            field_dict["cvss_v3_version"] = cvss_v3_version
        if cvss_v4_score is not UNSET:
            field_dict["cvss_v4_score"] = cvss_v4_score
        if cvss_v4_vector is not UNSET:
            field_dict["cvss_v4_vector"] = cvss_v4_vector
        if cwe_ids is not UNSET:
            field_dict["cwe_ids"] = cwe_ids
        if description is not UNSET:
            field_dict["description"] = description
        if emb3d_threats is not UNSET:
            field_dict["emb3d_threats"] = emb3d_threats
        if epss is not UNSET:
            field_dict["epss"] = epss
        if epss_percentile is not UNSET:
            field_dict["epss_percentile"] = epss_percentile
        if exploits is not UNSET:
            field_dict["exploits"] = exploits
        if fixed_version is not UNSET:
            field_dict["fixed_version"] = fixed_version
        if ics_weakness is not UNSET:
            field_dict["ics_weakness"] = ics_weakness
        if iec_62443_requirements is not UNSET:
            field_dict["iec_62443_requirements"] = iec_62443_requirements
        if jvn_advisories is not UNSET:
            field_dict["jvn_advisories"] = jvn_advisories
        if kev is not UNSET:
            field_dict["kev"] = kev
        if kev_cwe_ids is not UNSET:
            field_dict["kev_cwe_ids"] = kev_cwe_ids
        if kev_date_added is not UNSET:
            field_dict["kev_date_added"] = kev_date_added
        if kev_due is not UNSET:
            field_dict["kev_due"] = kev_due
        if kev_forensic_triage is not UNSET:
            field_dict["kev_forensic_triage"] = kev_forensic_triage
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
        if lev is not UNSET:
            field_dict["lev"] = lev
        if metasploit_modules is not UNSET:
            field_dict["metasploit_modules"] = metasploit_modules
        if mitigations is not UNSET:
            field_dict["mitigations"] = mitigations
        if nist_controls is not UNSET:
            field_dict["nist_controls"] = nist_controls
        if nuclei_templates is not UNSET:
            field_dict["nuclei_templates"] = nuclei_templates
        if osv_advisories is not UNSET:
            field_dict["osv_advisories"] = osv_advisories
        if osv_ids is not UNSET:
            field_dict["osv_ids"] = osv_ids
        if ot_context is not UNSET:
            field_dict["ot_context"] = ot_context
        if ot_vendor_advisories is not UNSET:
            field_dict["ot_vendor_advisories"] = ot_vendor_advisories
        if poc_count is not UNSET:
            field_dict["poc_count"] = poc_count
        if provenance is not UNSET:
            field_dict["provenance"] = provenance
        if published is not UNSET:
            field_dict["published"] = published
        if ransomware is not UNSET:
            field_dict["ransomware"] = ransomware
        if sigma_rules is not UNSET:
            field_dict["sigma_rules"] = sigma_rules
        if ssvc is not UNSET:
            field_dict["ssvc"] = ssvc
        if suppressed_by_vex is not UNSET:
            field_dict["suppressed_by_vex"] = suppressed_by_vex
        if techniques is not UNSET:
            field_dict["techniques"] = techniques
        if techniques_provenance is not UNSET:
            field_dict["techniques_provenance"] = techniques_provenance
        if vex_justification is not UNSET:
            field_dict["vex_justification"] = vex_justification
        if vuln_status is not UNSET:
            field_dict["vuln_status"] = vuln_status
        if vulnrichment is not UNSET:
            field_dict["vulnrichment"] = vulnrichment
        if weakness_ranks is not UNSET:
            field_dict["weakness_ranks"] = weakness_ranks
        if weaponization_score is not UNSET:
            field_dict["weaponization_score"] = weaponization_score

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.android_bulletin import AndroidBulletin  # noqa: PLC0415
        from ..models.cellular_annotation import CellularAnnotation  # noqa: PLC0415
        from ..models.cellular_core_entry import CellularCoreEntry  # noqa: PLC0415
        from ..models.cert_fr_advisory import CertFRAdvisory  # noqa: PLC0415
        from ..models.cisa_campaign_advisory import CISACampaignAdvisory  # noqa: PLC0415
        from ..models.csaf_remediation import CSAFRemediation  # noqa: PLC0415
        from ..models.cvssbt_score import CVSSBTScore  # noqa: PLC0415
        from ..models.emb3d_threat import EMB3DThreat  # noqa: PLC0415
        from ..models.exploit_detail import ExploitDetail  # noqa: PLC0415
        from ..models.ics_weakness import ICSWeakness  # noqa: PLC0415
        from ..models.iec62443_requirement import IEC62443Requirement  # noqa: PLC0415
        from ..models.inventory_metasploit_module import InventoryMetasploitModule  # noqa: PLC0415
        from ..models.inventory_mitigation import InventoryMitigation  # noqa: PLC0415
        from ..models.inventory_nuclei_template import InventoryNucleiTemplate  # noqa: PLC0415
        from ..models.inventory_technique import InventoryTechnique  # noqa: PLC0415
        from ..models.jvn_advisory import JVNAdvisory  # noqa: PLC0415
        from ..models.lev_estimate import LEVEstimate  # noqa: PLC0415
        from ..models.nist_control_mapping import NistControlMapping  # noqa: PLC0415
        from ..models.osv_advisory import OSVAdvisory  # noqa: PLC0415
        from ..models.ot_context import OTContext  # noqa: PLC0415
        from ..models.ot_vendor_advisory import OTVendorAdvisory  # noqa: PLC0415
        from ..models.sigma_rule import SigmaRule  # noqa: PLC0415
        from ..models.source_stamp import SourceStamp  # noqa: PLC0415
        from ..models.ssvc_decision import SSVCDecision  # noqa: PLC0415
        from ..models.vulnrichment import Vulnrichment  # noqa: PLC0415
        from ..models.weakness_rank import WeaknessRank  # noqa: PLC0415

        d = dict(src_dict)
        cve_id = d.pop("cve_id")

        def _parse_android_bulletin(data: object) -> AndroidBulletin | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, dict):
                    raise TypeError()
                android_bulletin_type_0 = AndroidBulletin.from_dict(data)

                return android_bulletin_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(AndroidBulletin | None | Unset, data)

        android_bulletin = _parse_android_bulletin(d.pop("android_bulletin", UNSET))

        _cellular_annotations = d.pop("cellular_annotations", UNSET)
        cellular_annotations: list[CellularAnnotation] | Unset = UNSET
        if _cellular_annotations is not UNSET:
            cellular_annotations = []
            for cellular_annotations_item_data in _cellular_annotations:
                cellular_annotations_item = CellularAnnotation.from_dict(cellular_annotations_item_data)

                cellular_annotations.append(cellular_annotations_item)

        _cellular_core_entries = d.pop("cellular_core_entries", UNSET)
        cellular_core_entries: list[CellularCoreEntry] | Unset = UNSET
        if _cellular_core_entries is not UNSET:
            cellular_core_entries = []
            for cellular_core_entries_item_data in _cellular_core_entries:
                cellular_core_entries_item = CellularCoreEntry.from_dict(cellular_core_entries_item_data)

                cellular_core_entries.append(cellular_core_entries_item)

        _certfr_advisories = d.pop("certfr_advisories", UNSET)
        certfr_advisories: list[CertFRAdvisory] | Unset = UNSET
        if _certfr_advisories is not UNSET:
            certfr_advisories = []
            for certfr_advisories_item_data in _certfr_advisories:
                certfr_advisories_item = CertFRAdvisory.from_dict(certfr_advisories_item_data)

                certfr_advisories.append(certfr_advisories_item)

        _cisa_campaigns = d.pop("cisa_campaigns", UNSET)
        cisa_campaigns: list[CISACampaignAdvisory] | Unset = UNSET
        if _cisa_campaigns is not UNSET:
            cisa_campaigns = []
            for cisa_campaigns_item_data in _cisa_campaigns:
                cisa_campaigns_item = CISACampaignAdvisory.from_dict(cisa_campaigns_item_data)

                cisa_campaigns.append(cisa_campaigns_item)

        csaf_advisory_ids = cast(list[str], d.pop("csaf_advisory_ids", UNSET))

        _csaf_remediations = d.pop("csaf_remediations", UNSET)
        csaf_remediations: list[CSAFRemediation] | Unset = UNSET
        if _csaf_remediations is not UNSET:
            csaf_remediations = []
            for csaf_remediations_item_data in _csaf_remediations:
                csaf_remediations_item = CSAFRemediation.from_dict(csaf_remediations_item_data)

                csaf_remediations.append(csaf_remediations_item)

        def _parse_cvss_bt(data: object) -> CVSSBTScore | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, dict):
                    raise TypeError()
                cvss_bt_type_0 = CVSSBTScore.from_dict(data)

                return cvss_bt_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(CVSSBTScore | None | Unset, data)

        cvss_bt = _parse_cvss_bt(d.pop("cvss_bt", UNSET))

        def _parse_cvss_v2_score(data: object) -> float | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(float | None | Unset, data)

        cvss_v2_score = _parse_cvss_v2_score(d.pop("cvss_v2_score", UNSET))

        def _parse_cvss_v3_score(data: object) -> float | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(float | None | Unset, data)

        cvss_v3_score = _parse_cvss_v3_score(d.pop("cvss_v3_score", UNSET))

        def _parse_cvss_v3_vector(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        cvss_v3_vector = _parse_cvss_v3_vector(d.pop("cvss_v3_vector", UNSET))

        def _parse_cvss_v3_version(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        cvss_v3_version = _parse_cvss_v3_version(d.pop("cvss_v3_version", UNSET))

        def _parse_cvss_v4_score(data: object) -> float | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(float | None | Unset, data)

        cvss_v4_score = _parse_cvss_v4_score(d.pop("cvss_v4_score", UNSET))

        def _parse_cvss_v4_vector(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        cvss_v4_vector = _parse_cvss_v4_vector(d.pop("cvss_v4_vector", UNSET))

        cwe_ids = cast(list[str], d.pop("cwe_ids", UNSET))

        def _parse_description(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        description = _parse_description(d.pop("description", UNSET))

        _emb3d_threats = d.pop("emb3d_threats", UNSET)
        emb3d_threats: list[EMB3DThreat] | Unset = UNSET
        if _emb3d_threats is not UNSET:
            emb3d_threats = []
            for emb3d_threats_item_data in _emb3d_threats:
                emb3d_threats_item = EMB3DThreat.from_dict(emb3d_threats_item_data)

                emb3d_threats.append(emb3d_threats_item)

        def _parse_epss(data: object) -> float | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(float | None | Unset, data)

        epss = _parse_epss(d.pop("epss", UNSET))

        def _parse_epss_percentile(data: object) -> float | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(float | None | Unset, data)

        epss_percentile = _parse_epss_percentile(d.pop("epss_percentile", UNSET))

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

        _ics_weakness = d.pop("ics_weakness", UNSET)
        ics_weakness: list[ICSWeakness] | Unset = UNSET
        if _ics_weakness is not UNSET:
            ics_weakness = []
            for ics_weakness_item_data in _ics_weakness:
                ics_weakness_item = ICSWeakness.from_dict(ics_weakness_item_data)

                ics_weakness.append(ics_weakness_item)

        _iec_62443_requirements = d.pop("iec_62443_requirements", UNSET)
        iec_62443_requirements: list[IEC62443Requirement] | Unset = UNSET
        if _iec_62443_requirements is not UNSET:
            iec_62443_requirements = []
            for iec_62443_requirements_item_data in _iec_62443_requirements:
                iec_62443_requirements_item = IEC62443Requirement.from_dict(iec_62443_requirements_item_data)

                iec_62443_requirements.append(iec_62443_requirements_item)

        _jvn_advisories = d.pop("jvn_advisories", UNSET)
        jvn_advisories: list[JVNAdvisory] | Unset = UNSET
        if _jvn_advisories is not UNSET:
            jvn_advisories = []
            for jvn_advisories_item_data in _jvn_advisories:
                jvn_advisories_item = JVNAdvisory.from_dict(jvn_advisories_item_data)

                jvn_advisories.append(jvn_advisories_item)

        kev = d.pop("kev", UNSET)

        kev_cwe_ids = cast(list[str], d.pop("kev_cwe_ids", UNSET))

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

        def _parse_kev_forensic_triage(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        kev_forensic_triage = _parse_kev_forensic_triage(d.pop("kev_forensic_triage", UNSET))

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

        def _parse_lev(data: object) -> LEVEstimate | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, dict):
                    raise TypeError()
                lev_type_0 = LEVEstimate.from_dict(data)

                return lev_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(LEVEstimate | None | Unset, data)

        lev = _parse_lev(d.pop("lev", UNSET))

        _metasploit_modules = d.pop("metasploit_modules", UNSET)
        metasploit_modules: list[InventoryMetasploitModule] | Unset = UNSET
        if _metasploit_modules is not UNSET:
            metasploit_modules = []
            for metasploit_modules_item_data in _metasploit_modules:
                metasploit_modules_item = InventoryMetasploitModule.from_dict(metasploit_modules_item_data)

                metasploit_modules.append(metasploit_modules_item)

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

        _nuclei_templates = d.pop("nuclei_templates", UNSET)
        nuclei_templates: list[InventoryNucleiTemplate] | Unset = UNSET
        if _nuclei_templates is not UNSET:
            nuclei_templates = []
            for nuclei_templates_item_data in _nuclei_templates:
                nuclei_templates_item = InventoryNucleiTemplate.from_dict(nuclei_templates_item_data)

                nuclei_templates.append(nuclei_templates_item)

        def _parse_osv_advisories(data: object) -> list[OSVAdvisory] | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, list):
                    raise TypeError()
                osv_advisories_type_0 = []
                _osv_advisories_type_0 = data
                for osv_advisories_type_0_item_data in _osv_advisories_type_0:
                    osv_advisories_type_0_item = OSVAdvisory.from_dict(osv_advisories_type_0_item_data)

                    osv_advisories_type_0.append(osv_advisories_type_0_item)

                return osv_advisories_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(list[OSVAdvisory] | None | Unset, data)

        osv_advisories = _parse_osv_advisories(d.pop("osv_advisories", UNSET))

        osv_ids = cast(list[str], d.pop("osv_ids", UNSET))

        def _parse_ot_context(data: object) -> None | OTContext | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, dict):
                    raise TypeError()
                ot_context_type_0 = OTContext.from_dict(data)

                return ot_context_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(None | OTContext | Unset, data)

        ot_context = _parse_ot_context(d.pop("ot_context", UNSET))

        _ot_vendor_advisories = d.pop("ot_vendor_advisories", UNSET)
        ot_vendor_advisories: list[OTVendorAdvisory] | Unset = UNSET
        if _ot_vendor_advisories is not UNSET:
            ot_vendor_advisories = []
            for ot_vendor_advisories_item_data in _ot_vendor_advisories:
                ot_vendor_advisories_item = OTVendorAdvisory.from_dict(ot_vendor_advisories_item_data)

                ot_vendor_advisories.append(ot_vendor_advisories_item)

        poc_count = d.pop("poc_count", UNSET)

        _provenance = d.pop("provenance", UNSET)
        provenance: list[SourceStamp] | Unset = UNSET
        if _provenance is not UNSET:
            provenance = []
            for provenance_item_data in _provenance:
                provenance_item = SourceStamp.from_dict(provenance_item_data)

                provenance.append(provenance_item)

        def _parse_published(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        published = _parse_published(d.pop("published", UNSET))

        ransomware = d.pop("ransomware", UNSET)

        _sigma_rules = d.pop("sigma_rules", UNSET)
        sigma_rules: list[SigmaRule] | Unset = UNSET
        if _sigma_rules is not UNSET:
            sigma_rules = []
            for sigma_rules_item_data in _sigma_rules:
                sigma_rules_item = SigmaRule.from_dict(sigma_rules_item_data)

                sigma_rules.append(sigma_rules_item)

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

        suppressed_by_vex = d.pop("suppressed_by_vex", UNSET)

        _techniques = d.pop("techniques", UNSET)
        techniques: list[InventoryTechnique] | Unset = UNSET
        if _techniques is not UNSET:
            techniques = []
            for techniques_item_data in _techniques:
                techniques_item = InventoryTechnique.from_dict(techniques_item_data)

                techniques.append(techniques_item)

        def _parse_techniques_provenance(data: object) -> InventoryCVETechniquesProvenanceType0 | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, str):
                    raise TypeError()
                techniques_provenance_type_0 = InventoryCVETechniquesProvenanceType0(data)

                return techniques_provenance_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(InventoryCVETechniquesProvenanceType0 | None | Unset, data)

        techniques_provenance = _parse_techniques_provenance(d.pop("techniques_provenance", UNSET))

        def _parse_vex_justification(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        vex_justification = _parse_vex_justification(d.pop("vex_justification", UNSET))

        def _parse_vuln_status(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        vuln_status = _parse_vuln_status(d.pop("vuln_status", UNSET))

        def _parse_vulnrichment(data: object) -> None | Unset | Vulnrichment:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, dict):
                    raise TypeError()
                vulnrichment_type_0 = Vulnrichment.from_dict(data)

                return vulnrichment_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(None | Unset | Vulnrichment, data)

        vulnrichment = _parse_vulnrichment(d.pop("vulnrichment", UNSET))

        _weakness_ranks = d.pop("weakness_ranks", UNSET)
        weakness_ranks: list[WeaknessRank] | Unset = UNSET
        if _weakness_ranks is not UNSET:
            weakness_ranks = []
            for weakness_ranks_item_data in _weakness_ranks:
                weakness_ranks_item = WeaknessRank.from_dict(weakness_ranks_item_data)

                weakness_ranks.append(weakness_ranks_item)

        def _parse_weaponization_score(data: object) -> float | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(float | None | Unset, data)

        weaponization_score = _parse_weaponization_score(d.pop("weaponization_score", UNSET))

        inventory_cve = cls(
            cve_id=cve_id,
            android_bulletin=android_bulletin,
            cellular_annotations=cellular_annotations,
            cellular_core_entries=cellular_core_entries,
            certfr_advisories=certfr_advisories,
            cisa_campaigns=cisa_campaigns,
            csaf_advisory_ids=csaf_advisory_ids,
            csaf_remediations=csaf_remediations,
            cvss_bt=cvss_bt,
            cvss_v2_score=cvss_v2_score,
            cvss_v3_score=cvss_v3_score,
            cvss_v3_vector=cvss_v3_vector,
            cvss_v3_version=cvss_v3_version,
            cvss_v4_score=cvss_v4_score,
            cvss_v4_vector=cvss_v4_vector,
            cwe_ids=cwe_ids,
            description=description,
            emb3d_threats=emb3d_threats,
            epss=epss,
            epss_percentile=epss_percentile,
            exploits=exploits,
            fixed_version=fixed_version,
            ics_weakness=ics_weakness,
            iec_62443_requirements=iec_62443_requirements,
            jvn_advisories=jvn_advisories,
            kev=kev,
            kev_cwe_ids=kev_cwe_ids,
            kev_date_added=kev_date_added,
            kev_due=kev_due,
            kev_forensic_triage=kev_forensic_triage,
            kev_notes=kev_notes,
            kev_required_action=kev_required_action,
            kev_short_description=kev_short_description,
            kev_vendor_project=kev_vendor_project,
            kev_vulnerability_name=kev_vulnerability_name,
            lev=lev,
            metasploit_modules=metasploit_modules,
            mitigations=mitigations,
            nist_controls=nist_controls,
            nuclei_templates=nuclei_templates,
            osv_advisories=osv_advisories,
            osv_ids=osv_ids,
            ot_context=ot_context,
            ot_vendor_advisories=ot_vendor_advisories,
            poc_count=poc_count,
            provenance=provenance,
            published=published,
            ransomware=ransomware,
            sigma_rules=sigma_rules,
            ssvc=ssvc,
            suppressed_by_vex=suppressed_by_vex,
            techniques=techniques,
            techniques_provenance=techniques_provenance,
            vex_justification=vex_justification,
            vuln_status=vuln_status,
            vulnrichment=vulnrichment,
            weakness_ranks=weakness_ranks,
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

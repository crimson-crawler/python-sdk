from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, BinaryIO, Generator, TextIO, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..models.catalogued_cve_response_techniques_provenance_type_0 import CataloguedCVEResponseTechniquesProvenanceType0
from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.affected_chipset import AffectedChipset
    from ..models.affected_product import AffectedProduct
    from ..models.android_bulletin import AndroidBulletin
    from ..models.campaign_detail import CampaignDetail
    from ..models.capec_detail import CAPECDetail
    from ..models.catalogued_cve_response_catalog_refs import CataloguedCVEResponseCatalogRefs
    from ..models.catalogued_cve_response_distro_advisories_totals import CataloguedCVEResponseDistroAdvisoriesTotals
    from ..models.catalogued_cve_response_navigator_type_0 import CataloguedCVEResponseNavigatorType0
    from ..models.cellular_annotation import CellularAnnotation
    from ..models.cellular_core_entry import CellularCoreEntry
    from ..models.cert_fr_advisory import CertFRAdvisory
    from ..models.cisa_campaign_advisory import CISACampaignAdvisory
    from ..models.confidence import Confidence
    from ..models.csaf_advisory import CSAFAdvisory
    from ..models.cve_detail import CVEDetail
    from ..models.cvssbt_score import CVSSBTScore
    from ..models.cwe_detail import CWEDetail
    from ..models.d3fend_detail import D3FENDDetail
    from ..models.detection_detail import DetectionDetail
    from ..models.distro_advisory import DistroAdvisory
    from ..models.emb3d_threat import EMB3DThreat
    from ..models.epss_score import EPSSScore
    from ..models.epss_velocity import EPSSVelocity
    from ..models.error_detail import ErrorDetail
    from ..models.euvd_entry import EUVDEntry
    from ..models.exploit_detail import ExploitDetail
    from ..models.group_detail import GroupDetail
    from ..models.ics_weakness import ICSWeakness
    from ..models.iec62443_requirement import IEC62443Requirement
    from ..models.inferred_chain_candidate import InferredChainCandidate
    from ..models.jvn_advisory import JVNAdvisory
    from ..models.kev_entry import KEVEntry
    from ..models.knowledgebase_result import KnowledgebaseResult
    from ..models.lev_estimate import LEVEstimate
    from ..models.match_criteria_detail import MatchCriteriaDetail
    from ..models.metasploit_module import MetasploitModule
    from ..models.misp_attribute import MISPAttribute
    from ..models.mitigation_detail import MitigationDetail
    from ..models.nist_control_mapping import NistControlMapping
    from ..models.nuclei_template import NucleiTemplate
    from ..models.osv_advisory import OSVAdvisory
    from ..models.ot_context import OTContext
    from ..models.ot_vendor_advisory import OTVendorAdvisory
    from ..models.po_c_entry import PoCEntry
    from ..models.po_c_source_entry import PoCSourceEntry
    from ..models.revision_entry import RevisionEntry
    from ..models.sigma_rule import SigmaRule
    from ..models.similar_cve_mini import SimilarCVEMini
    from ..models.software_detail import SoftwareDetail
    from ..models.ssvc_decision import SSVCDecision
    from ..models.technique_detail import TechniqueDetail
    from ..models.threat_prediction import ThreatPrediction
    from ..models.timeline_entry import TimelineEntry
    from ..models.vendor_advisory import VendorAdvisory
    from ..models.vince_advisory import VINCEAdvisory
    from ..models.vulnrichment import Vulnrichment
    from ..models.weakness_rank import WeaknessRank


T = TypeVar("T", bound="CataloguedCVEResponse")


@_attrs_define
class CataloguedCVEResponse:
    """A CVE whose shared context rows are referenced from its enclosing response catalogue.

    Attributes:
        affected_chipsets (list[AffectedChipset] | Unset): Qualcomm-family chipset/SoC rows for this CVE, derived from
            the same Vulmatch `software` read `affected_products` uses (vendor ∈ qualcomm/qca/snapdragon; a `_firmware`
            product suffix is stripped). Opt-in via include=['affected_chipsets']; loads that read for itself and does not
            publish `affected_products`.
        affected_products (list[AffectedProduct] | Unset): Confirmed vulnerable software with vendor, product, version,
            and CPE string
        android_bulletin (AndroidBulletin | None | Unset): The stored Android Security Bulletin record this CVE names
            (`ASB-A-*`). Included by default; null when no ASB record matches (an answer, not an error) or when the stored
            read failed (reported in `errors[]`, step `fetch_android_bulletin`).
        attack_patterns (list[CAPECDetail] | Unset): CAPEC patterns; summary omits prose and examples.
            include=['capec_full'] restores them.
        campaigns (list[CampaignDetail] | Unset): Threat campaigns that used the linked techniques
        catalog_refs (CataloguedCVEResponseCatalogRefs | Unset): Layer name to ordered catalogue keys; resolve against
            the enclosing cve_context_catalog
        cellular_annotations (list[CellularAnnotation] | Unset): Rows of the 5G CVE-annotated dataset (Zenodo 17450053,
            CC-BY-4.0) for this CVE, carrying the dataset's own `native_5g` / `lte` / `auxiliary` tags. Opt-in via
            include=['cellular']; a CVE the dataset does not cover returns [] (an answer, not an error).
        cellular_core_entries (list[CellularCoreEntry] | Unset): The RANsacked research page's row for this CVE: the
            cellular-core implementation it affects (Open5GS, Magma, OpenAirInterface, NextEPC, SD-Core, Athonet, srsRAN)
            with its LTE/5G qualifier, from the curated 73-CVE table (the page's 18 non-existent CVE ids are excluded). Opt-
            in via include=['cellular_core']; a CVE the table does not cover returns [].
        certfr_advisories (list[CertFRAdvisory] | Unset): CERT-FR advisories naming this CVE, newest first with id as
            tie-breaker. The default returns at most 10 rows and keeps only the requested CVE id. Use
            include=['certfr_advisories_full'] for all rows and CVE ids. An unreadable corpus adds a fetch_certfr error.
        certfr_advisories_total (int | Unset): Number of matching CERT-FR advisories before the cap. Default: 0.
        certfr_advisories_truncated (bool | Unset): True when the CERT-FR summary row cap cut results. Default: False.
        cisa_campaigns (list[CISACampaignAdvisory] | Unset): CISA joint cybersecurity advisories (AA-series) whose STIX
            bundle references this CVE — advisory id, title, publication date, URL, sectors, locations, threat actors,
            ATT&CK techniques and observable count. Opt-in via include=['cisa_campaigns']; read from the seeded public-
            domain corpus in-process. A missing corpus is []; a corrupt one is [] plus an `errors[]` entry (step
            `fetch_cisa_campaigns`).
        confidence (Confidence | None | Unset): Enrichment completeness indicator: data_quality bucket
            (`none`/`low`/`moderate`/`high`), per-source response counts, and corroboration adjustments. The `none` bucket
            is the canonical signal that the enrichment lookup found nothing — distinguish it from `low`. See the
            `Confidence` model for field-level semantics.
        csaf_advisories (list[CSAFAdvisory] | Unset): CSAF advisories naming this CVE, newest first with tracking id as
            tie-breaker. The default returns at most 10 rows, keeps only the requested CVE id, and empties remediations and
            product_statuses. Use include=['csaf_advisories_full'] for all fetched rows and fields. An unreadable corpus
            adds a fetch_csaf_advisories error.
        csaf_advisories_total (int | Unset): Number of matching CSAF advisories before the summary cap. Default: 0.
        csaf_advisories_truncated (bool | Unset): True when the CSAF summary row cap cut results. Default: False.
        cve (CVEDetail | None | Unset): Core vulnerability details and CVSS scoring
        cvss_bt (CVSSBTScore | None | Unset): The cvss-bt row for this CVE — Base+Threat composite, severity and the
            VulnCheck-KEV / ExploitDB / Metasploit / Nuclei flags. Opt-in via include=['cvss_bt']; read from the seeded
            corpus (`data/cvss-bt/cvss-bt.csv`). A CVE the corpus does not carry is null; a missing corpus is null with no
            error; a corrupt corpus is null plus an `errors[]` entry (step `fetch_cvss_bt`). Never feeds
            `weaponization_score` or `has_public_exploit`.
        defend (list[D3FENDDetail] | Unset): D3FEND defensive techniques and countermeasures for the linked ATT&CK
            techniques. The default form omits each row's `description`, `aliases`, STIX `pattern` and `stix_id`; request
            include=['defend_full'] for them. The STIX licence marking (`object_marking_refs`) is kept in both forms.
        detections (list[DetectionDetail] | Unset): Detection data sources and components for the linked techniques
        discovered_cve_id (None | str | Unset): CVE ID from discovery, even when its core record could not be resolved
        distro_advisories (list[DistroAdvisory] | Unset): Linux distribution advisories for this CVE from SUSE CSAF-VEX,
            Ubuntu OpenVEX and Alpine secdb (Debian is not included). Only when 'distro_advisories' is in include. One row
            per source release and package, capped at 200 rows per source; an unreadable source keeps one
            `status='unavailable'` row and an `errors[]` entry. `distro_advisories_totals` and `distro_advisories_truncated`
            say what the cap cut.
        distro_advisories_totals (CataloguedCVEResponseDistroAdvisoriesTotals | Unset): Rows each distro source produced
            before the 200-row cap, keyed by source (`suse_csaf_vex`, `ubuntu_openvex`, `alpine_secdb`). An unreadable
            source is 0. Compare with the listed rows to see how many were cut; each `source_url` names the complete
            document.
        distro_advisories_truncated (bool | Unset): True when any source produced more rows than the cap lists — see
            `distro_advisories_totals`. Default: False.
        emb3d_threats (list[EMB3DThreat] | Unset): MITRE EMB3D embedded/hardware threats whose CWE ids overlap this
            CVE's weakness ids, with the countermeasures EMB3D joins to each. Opt-in via include=['emb3d']; derived from the
            CVE record's own `cwe_ids`, so `cwe` need not be requested.
        epss (EPSSScore | None | Unset): Exploit probability score
        epss_velocity (EPSSVelocity | None | Unset): EPSS score trend over the last 7 and 30 days with direction,
            acceleration, and optional inflection flag. Populated when `include=['timeline']` produced data. `null`
            otherwise.
        errors (list[ErrorDetail] | Unset): Partial failure details - check this array for incomplete enrichment
        euvd (EUVDEntry | None | Unset): The stored ENISA EUVD entry aliasing this CVE. Opt-in via include=['euvd']; an
            unmatched CVE is null, an unavailable copy adds `stored_copy_unavailable`, and an older valid copy adds
            `stale_copy`.
        exploits (list[ExploitDetail] | Unset): Authoritative exploit objects linked to this CVE (ExploitDB public
            exploit evidence). Returned when include=['exploits']. Real exploit evidence (type + references), not a
            heuristic guess.
        groups (list[GroupDetail] | Unset): Threat actor groups known to use the linked techniques
        ics_weakness (list[ICSWeakness] | Unset): The CVE's weaknesses that belong to MITRE's CWE-1358 ICS view. Opt-in
            via include=['weakness_ranks'] (the same token as `weakness_ranks`); a zero-cost in-process catalog read.
        identifier_resolved (bool | None | Unset): Whether the CVE id resolved to a record. `false` means the id was not
            found, so every layer below is empty for that reason rather than because the record exists and has no data — the
            two were previously indistinguishable. `null` when resolution was not evaluated.
        iec_62443_requirements (list[IEC62443Requirement] | Unset): The ISA/IEC 62443 requirements the CVE's weaknesses
            are mapped to (CWE-1424), one row per (CWE, part, requirement). Opt-in via include=['weakness_ranks']; a zero-
            cost in-process catalog read.
        inferred_chain_candidates (list[InferredChainCandidate] | None | Unset): AI-proposed technique candidates.
            Returned only when `include` contains `inferred_chain` and `techniques[]` is empty. Each entry is a low-
            confidence, non-authoritative analyst hint intended for human review.
        jvn_advisories (list[JVNAdvisory] | Unset): JVNDB (Japan Vulnerability Notes) advisories that reference this
            CVE, with the advisory id, title, first `sec:cpe` vendor/product, published timestamp and URL — link and
            metadata only. Opt-in via include=['jvn']; read from the seeded corpus. A missing corpus is []; a corrupt one is
            [] plus an `errors[]` entry (step `fetch_jvn`).
        kev (KEVEntry | None | Unset): Known Exploited Vulnerabilities catalog status
        knowledgebase (list[KnowledgebaseResult] | Unset): Related intelligence from the knowledge base
        lev (LEVEstimate | None | Unset): NIST CSWP 41 Likely Exploited Vulnerabilities (LEV2): a lower bound on the
            probability this CVE has already been exploited, from the daily EPSS history on record. Unlike EPSS it looks
            back, not forward; `window_days` says how much history it covers. Null without EPSS.
        likely_tactics (list[str] | None | Unset): Likely ATT&CK tactic classes, such as `initial-access` or `lateral-
            movement`, inferred from the affected product vendor. Populated only when `techniques[]` is empty and a vendor
            profile is available. These are analyst hints, not technique IDs or authoritative attribution.
        match_criteria (list[MatchCriteriaDetail] | Unset): The NVD criteria behind the distinct `match_criteria_id`s on
            `affected_products`, each with its matchstring, version bounds, covered software and the CVEs it hits. Returned
            when `include=['criteria']` (which loads the affected-product rows it reads for itself); the list is
            deduplicated by criterion id, so one entry answers for every row that carries it.
        metasploit_modules (list[MetasploitModule] | Unset): Metasploit Framework modules that name this CVE — read from
            the framework's published module metadata, one entry per module, best rank first. Only when 'metasploit' is in
            include. Deliberately separate from `exploits` (ExploitDB) and from every scoring field: these come from a
            source the offline path cannot reach, so folding them in would move `has_public_exploit` / `weaponization_score`
            on a network dependency.
        misp (list[MISPAttribute] | Unset): Matching indicators from our curated MISP, built from public threat feeds
            (list: https://crimsoncrawler.com/docs/guides/data-sources/#our-curated-misp)
        mitigations (list[MitigationDetail] | Unset): Defensive mitigations for the linked techniques
        navigator (CataloguedCVEResponseNavigatorType0 | None | Unset): ATT&CK Navigator layer JSON, consumable by the
            MITRE Navigator tool (https://mitre-attack.github.io/attack-navigator/) as-is — drop the value into the 'Open
            Existing Layer → Upload from Local' import. Returned only when `include=['navigator']` is requested. `null` when
            the layer could not be built. Useful for visualizing the CVE's technique footprint.
        nist_controls (list[NistControlMapping] | Unset): NIST SP 800-53 rev 5 controls that mitigate the techniques on
            this response, via MITRE CTID. Pass-through static lookup; only populates when 'nist_controls' is in the request
            include set.
        nuclei_templates (list[NucleiTemplate] | Unset): ProjectDiscovery Nuclei templates whose own id/classification
            names this CVE, with only their published header fields (never request/flow material). Only when 'nuclei' is in
            include.
        osv_advisories (list[OSVAdvisory] | Unset): Stored permissive OSV advisories cross-referenced to this CVE id,
            with per-ecosystem fixed versions. Included by default via `osv`; `osv_restricted` adds restricted or unknown
            sources. Package/version discovery uses the stored OSV index.
        osv_advisories_total (int | None | Unset): Exact number of distinct indexed OSV advisory candidates, or null
            when unavailable.
        osv_advisories_truncated (bool | Unset): True when the response budget or an unreadable advisory omitted indexed
            candidates. Default: False.
        osv_next_offset (int | None | Unset): Position to request next (`osv_offset`) when OSV candidates remain beyond
            this page; omitted when the walk is complete or no continuation is available. Follow it even when it is 0 (the
            other sections consumed the page budget). `osv_advisories_truncated` stays true while candidates remain.
        osv_snapshot_id (None | str | Unset): Snapshot to send as `osv_snapshot_id` with `osv_next_offset`; omitted with
            it.
        ot_context (None | OTContext | Unset): OT/RF asset context derived deterministically from the data this response
            already reads: sectors (ICS Advisory Project CSV, CSAF notes, curated vendor map), OT protocols, fix
            availability (CSAF product status), KEV OT vendor classification, RF technology and access vector, and the CVE's
            ISA/IEC 62443 requirements. Opt-in via include=['ot_context']; no LLM and no new upstream source.
        ot_vendor_advisories (list[OTVendorAdvisory] | Unset): Direct OT/embedded vendor advisories naming this CVE —
            Rockwell Automation and MediaTek (`ot_vendor_advisories[]`), with CVE ids, CVSS scores, products and MediaTek
            chipset codes. Link and metadata only. Opt-in via include=['ot_vendor_advisories']; a zero-cost in-process read
            of the seeded corpus.
        poc (list[PoCEntry] | Unset): Proof-of-concept exploits from GitHub, capped to the 15 highest-starred
            repositories in a stable order. The default form omits each row's `description`; request include=['poc_full']
            for every row with its description.
        poc_source (list[PoCSourceEntry] | Unset): AI-assisted analysis of selected PoC repositories: trigger, affected
            path, preconditions, and mitigation. At most three entries are returned; raw source code is never returned.
        poc_total (int | Unset): How many PoC repositories matched, before the summary cap (0 when not published)
            Default: 0.
        poc_truncated (bool | Unset): True when `poc` is the relevance-ordered cap; request include=['poc_full'] for
            every row Default: False.
        predictions (list[ThreatPrediction] | Unset): Threat predictions - probability each technique will be employed
        revision_history (list[RevisionEntry] | Unset): The CVE record's revision history from
            `/cve/objects/{id}/versions/`, newest first, with `latest` marking the current revision. `versions` (the KB-
            version list used on the ATT&CK family surfaces) is empty here — a CVE record has revisions, not MITRE KB
            versions. Opt-in via include=['versions'].
        sigma_rules (list[SigmaRule] | Unset): SigmaHQ detection rules whose tags name this CVE. Opt-in via
            include=['sigma']; read from the seeded Sigma corpus index. Sigma rules are licensed DRL-1.1 and are attributed
            via `source_url`, never redistributed.
        similar_cves (list[SimilarCVEMini] | Unset): Up to 15 CVEs with overlapping weakness/technique fingerprint,
            ranked by a weighted Jaccard similarity that may include CPE vendor:product overlap and CVSS vector Hamming
            similarity when available. Returned only when `include=['similar_cves']` is requested. Each entry carries a per-
            signal `signal_breakdown` for transparency.
        software (list[SoftwareDetail] | Unset): Malware and tools that employ the linked techniques
        ssvc (None | SSVCDecision | Unset): SSVC vulnerability-prioritization decision for this CVE. Populated when
            'ssvc' is in the request include set. Method (CERT/CC Deployer or CISA Coordinator) and stakeholder context
            (exposure, human_impact, etc.) come from the optional `stakeholder` request field; defaults apply when omitted.
            Inputs (`exploitation`, `automatable`, `technical_impact`) are derived from structured CVE evidence: KEV, EPSS,
            PoC count, and the CVSS vector.
        summary (None | str | Unset): AI-generated 3-5 sentence executive summary of the vulnerability context, woven
            from the structured signals in this response (CVSS, EPSS, KEV deadline, weaponization, top techniques, PoC
            presence). Returned only when `include=['summary']` is requested. `null` when AI summarization is unavailable or
            the layer was not requested. Check `errors[]` for a generation failure.
        techniques (list[TechniqueDetail] | Unset): ATT&CK techniques linked to this CVE through published
            vulnerability, CWE, and CAPEC relationships. CVEs sharing a broad CWE can have overlapping techniques; check
            `techniques_provenance` when CVE-specific precision matters.
        techniques_provenance (CataloguedCVEResponseTechniquesProvenanceType0 | None | Unset): Precision class of
            `techniques[]`. `cwe_closure`: reached through a specific CWE's CAPEC closure, shared by every CVE with that
            weakness. `cwe_class`: reached through a generic or Pillar-level CWE's closure, shared across unrelated CVEs.
            `heuristic`: indirect evidence (MISP, keyword, or malware fallback). `cve_specific`: the prior label, kept only
            for a CVE with no CWE on record. `null` when `techniques` was not requested or none resolved. `cwe_class` and
            `cwe_closure` each earn 0.6x the techniques weight and drop the chain-tier lift; `heuristic` earns 0.3x.
        timeline (list[TimelineEntry] | Unset): EPSS score history for trend visualization. One entry per available
            scoring date. Returned only when `include=['timeline']` is requested. Pair with `epss_velocity` for derivative
            analysis.
        unresolved_criteria_ids (list[str] | Unset): `match_criteria_id`s from `affected_products` that `match_criteria`
            does NOT answer for — the criterion read 404s (a stale or withdrawn NVD criterion) or the per-response
            resolution cap dropped it. Empty means every distinct id on the response resolved, so an empty `match_criteria`
            with this empty too is a genuine 'no criteria on these rows'.
        vendor_advisories (list[VendorAdvisory] | Unset): Vendor advisory metadata for this CVE from Microsoft (MSRC
            CVRF), Red Hat Security Data and Cisco PSIRT openVuln — one row per source that answered, in that order. Only
            when 'vendor_advisories' is in include; a failing source keeps its own row rather than suppressing the others.
        vince_advisories (list[VINCEAdvisory] | Unset): CERT/CC Vulnerability Notes referencing this CVE. Opt-in via
            include=['vince']; up to 20 newest notes are returned. Partial and unavailable copies are reported in errors.
        vince_notes_total (int | Unset): Matching CERT/CC notes before the 20-note limit Default: 0.
        vince_notes_truncated (bool | Unset): Whether more than 20 CERT/CC notes matched Default: False.
        vulnrichment (None | Unset | Vulnrichment): Stored Vulnrichment data for this CVE: extra CWE ids, KEV membership
            and an ADP provider's SSVC content (`adp_ssvc`, verbatim — never written into `ssvc`). Opt-in via
            include=['vulnrichment']; a CVE absent from the copy is null, while an unavailable copy returns a wrapper with
            `status='unavailable'` and an `errors[]` entry.
        weakness_ranks (list[WeaknessRank] | Unset): Ranked-list positions for this CVE's weakness ids — CWE Top 25 and
            the OWASP Top 10 / API / LLM editions, one row per (list, rank), matched by CWE id. Opt-in via
            include=['weakness_ranks']; the `weaknesses` layer itself stays governed by its own `cwe` token.
        weaknesses (list[CWEDetail] | Unset): Root cause weakness classifications (CWE)
        weaponization_score (float | None | Unset): Composite 0-100 risk score that combines EPSS (exploit probability),
            KEV listing (active exploitation), public PoC presence/recency, and CVSS severity. Higher = more weaponized.
            `null` when none of the input signals are available. Use as a prioritization input alongside CVSS and EPSS;
            values >=70 warrant mention in summaries, >=85 lead the narrative.
    """

    affected_chipsets: list[AffectedChipset] | Unset = UNSET
    affected_products: list[AffectedProduct] | Unset = UNSET
    android_bulletin: AndroidBulletin | None | Unset = UNSET
    attack_patterns: list[CAPECDetail] | Unset = UNSET
    campaigns: list[CampaignDetail] | Unset = UNSET
    catalog_refs: CataloguedCVEResponseCatalogRefs | Unset = UNSET
    cellular_annotations: list[CellularAnnotation] | Unset = UNSET
    cellular_core_entries: list[CellularCoreEntry] | Unset = UNSET
    certfr_advisories: list[CertFRAdvisory] | Unset = UNSET
    certfr_advisories_total: int | Unset = 0
    certfr_advisories_truncated: bool | Unset = False
    cisa_campaigns: list[CISACampaignAdvisory] | Unset = UNSET
    confidence: Confidence | None | Unset = UNSET
    csaf_advisories: list[CSAFAdvisory] | Unset = UNSET
    csaf_advisories_total: int | Unset = 0
    csaf_advisories_truncated: bool | Unset = False
    cve: CVEDetail | None | Unset = UNSET
    cvss_bt: CVSSBTScore | None | Unset = UNSET
    defend: list[D3FENDDetail] | Unset = UNSET
    detections: list[DetectionDetail] | Unset = UNSET
    discovered_cve_id: None | str | Unset = UNSET
    distro_advisories: list[DistroAdvisory] | Unset = UNSET
    distro_advisories_totals: CataloguedCVEResponseDistroAdvisoriesTotals | Unset = UNSET
    distro_advisories_truncated: bool | Unset = False
    emb3d_threats: list[EMB3DThreat] | Unset = UNSET
    epss: EPSSScore | None | Unset = UNSET
    epss_velocity: EPSSVelocity | None | Unset = UNSET
    errors: list[ErrorDetail] | Unset = UNSET
    euvd: EUVDEntry | None | Unset = UNSET
    exploits: list[ExploitDetail] | Unset = UNSET
    groups: list[GroupDetail] | Unset = UNSET
    ics_weakness: list[ICSWeakness] | Unset = UNSET
    identifier_resolved: bool | None | Unset = UNSET
    iec_62443_requirements: list[IEC62443Requirement] | Unset = UNSET
    inferred_chain_candidates: list[InferredChainCandidate] | None | Unset = UNSET
    jvn_advisories: list[JVNAdvisory] | Unset = UNSET
    kev: KEVEntry | None | Unset = UNSET
    knowledgebase: list[KnowledgebaseResult] | Unset = UNSET
    lev: LEVEstimate | None | Unset = UNSET
    likely_tactics: list[str] | None | Unset = UNSET
    match_criteria: list[MatchCriteriaDetail] | Unset = UNSET
    metasploit_modules: list[MetasploitModule] | Unset = UNSET
    misp: list[MISPAttribute] | Unset = UNSET
    mitigations: list[MitigationDetail] | Unset = UNSET
    navigator: CataloguedCVEResponseNavigatorType0 | None | Unset = UNSET
    nist_controls: list[NistControlMapping] | Unset = UNSET
    nuclei_templates: list[NucleiTemplate] | Unset = UNSET
    osv_advisories: list[OSVAdvisory] | Unset = UNSET
    osv_advisories_total: int | None | Unset = UNSET
    osv_advisories_truncated: bool | Unset = False
    osv_next_offset: int | None | Unset = UNSET
    osv_snapshot_id: None | str | Unset = UNSET
    ot_context: None | OTContext | Unset = UNSET
    ot_vendor_advisories: list[OTVendorAdvisory] | Unset = UNSET
    poc: list[PoCEntry] | Unset = UNSET
    poc_source: list[PoCSourceEntry] | Unset = UNSET
    poc_total: int | Unset = 0
    poc_truncated: bool | Unset = False
    predictions: list[ThreatPrediction] | Unset = UNSET
    revision_history: list[RevisionEntry] | Unset = UNSET
    sigma_rules: list[SigmaRule] | Unset = UNSET
    similar_cves: list[SimilarCVEMini] | Unset = UNSET
    software: list[SoftwareDetail] | Unset = UNSET
    ssvc: None | SSVCDecision | Unset = UNSET
    summary: None | str | Unset = UNSET
    techniques: list[TechniqueDetail] | Unset = UNSET
    techniques_provenance: CataloguedCVEResponseTechniquesProvenanceType0 | None | Unset = UNSET
    timeline: list[TimelineEntry] | Unset = UNSET
    unresolved_criteria_ids: list[str] | Unset = UNSET
    vendor_advisories: list[VendorAdvisory] | Unset = UNSET
    vince_advisories: list[VINCEAdvisory] | Unset = UNSET
    vince_notes_total: int | Unset = 0
    vince_notes_truncated: bool | Unset = False
    vulnrichment: None | Unset | Vulnrichment = UNSET
    weakness_ranks: list[WeaknessRank] | Unset = UNSET
    weaknesses: list[CWEDetail] | Unset = UNSET
    weaponization_score: float | None | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        from ..models.affected_chipset import AffectedChipset  # noqa: PLC0415
        from ..models.affected_product import AffectedProduct  # noqa: PLC0415
        from ..models.android_bulletin import AndroidBulletin  # noqa: PLC0415
        from ..models.campaign_detail import CampaignDetail  # noqa: PLC0415
        from ..models.capec_detail import CAPECDetail  # noqa: PLC0415
        from ..models.catalogued_cve_response_catalog_refs import CataloguedCVEResponseCatalogRefs  # noqa: PLC0415
        from ..models.catalogued_cve_response_distro_advisories_totals import (
            CataloguedCVEResponseDistroAdvisoriesTotals,  # noqa: PLC0415
        )
        from ..models.catalogued_cve_response_navigator_type_0 import (
            CataloguedCVEResponseNavigatorType0,  # noqa: PLC0415
        )
        from ..models.cellular_annotation import CellularAnnotation  # noqa: PLC0415
        from ..models.cellular_core_entry import CellularCoreEntry  # noqa: PLC0415
        from ..models.cert_fr_advisory import CertFRAdvisory  # noqa: PLC0415
        from ..models.cisa_campaign_advisory import CISACampaignAdvisory  # noqa: PLC0415
        from ..models.confidence import Confidence  # noqa: PLC0415
        from ..models.csaf_advisory import CSAFAdvisory  # noqa: PLC0415
        from ..models.cve_detail import CVEDetail  # noqa: PLC0415
        from ..models.cvssbt_score import CVSSBTScore  # noqa: PLC0415
        from ..models.cwe_detail import CWEDetail  # noqa: PLC0415
        from ..models.d3fend_detail import D3FENDDetail  # noqa: PLC0415
        from ..models.detection_detail import DetectionDetail  # noqa: PLC0415
        from ..models.distro_advisory import DistroAdvisory  # noqa: PLC0415
        from ..models.emb3d_threat import EMB3DThreat  # noqa: PLC0415
        from ..models.epss_score import EPSSScore  # noqa: PLC0415
        from ..models.epss_velocity import EPSSVelocity  # noqa: PLC0415
        from ..models.error_detail import ErrorDetail  # noqa: PLC0415
        from ..models.euvd_entry import EUVDEntry  # noqa: PLC0415
        from ..models.exploit_detail import ExploitDetail  # noqa: PLC0415
        from ..models.group_detail import GroupDetail  # noqa: PLC0415
        from ..models.ics_weakness import ICSWeakness  # noqa: PLC0415
        from ..models.iec62443_requirement import IEC62443Requirement  # noqa: PLC0415
        from ..models.inferred_chain_candidate import InferredChainCandidate  # noqa: PLC0415
        from ..models.jvn_advisory import JVNAdvisory  # noqa: PLC0415
        from ..models.kev_entry import KEVEntry  # noqa: PLC0415
        from ..models.knowledgebase_result import KnowledgebaseResult  # noqa: PLC0415
        from ..models.lev_estimate import LEVEstimate  # noqa: PLC0415
        from ..models.match_criteria_detail import MatchCriteriaDetail  # noqa: PLC0415
        from ..models.metasploit_module import MetasploitModule  # noqa: PLC0415
        from ..models.misp_attribute import MISPAttribute  # noqa: PLC0415
        from ..models.mitigation_detail import MitigationDetail  # noqa: PLC0415
        from ..models.nist_control_mapping import NistControlMapping  # noqa: PLC0415
        from ..models.nuclei_template import NucleiTemplate  # noqa: PLC0415
        from ..models.osv_advisory import OSVAdvisory  # noqa: PLC0415
        from ..models.ot_context import OTContext  # noqa: PLC0415
        from ..models.ot_vendor_advisory import OTVendorAdvisory  # noqa: PLC0415
        from ..models.po_c_entry import PoCEntry  # noqa: PLC0415
        from ..models.po_c_source_entry import PoCSourceEntry  # noqa: PLC0415
        from ..models.revision_entry import RevisionEntry  # noqa: PLC0415
        from ..models.sigma_rule import SigmaRule  # noqa: PLC0415
        from ..models.similar_cve_mini import SimilarCVEMini  # noqa: PLC0415
        from ..models.software_detail import SoftwareDetail  # noqa: PLC0415
        from ..models.ssvc_decision import SSVCDecision  # noqa: PLC0415
        from ..models.technique_detail import TechniqueDetail  # noqa: PLC0415
        from ..models.threat_prediction import ThreatPrediction  # noqa: PLC0415
        from ..models.timeline_entry import TimelineEntry  # noqa: PLC0415
        from ..models.vendor_advisory import VendorAdvisory  # noqa: PLC0415
        from ..models.vince_advisory import VINCEAdvisory  # noqa: PLC0415
        from ..models.vulnrichment import Vulnrichment  # noqa: PLC0415
        from ..models.weakness_rank import WeaknessRank  # noqa: PLC0415

        affected_chipsets: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.affected_chipsets, Unset):
            affected_chipsets = []
            for affected_chipsets_item_data in self.affected_chipsets:
                affected_chipsets_item = affected_chipsets_item_data.to_dict()
                affected_chipsets.append(affected_chipsets_item)

        affected_products: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.affected_products, Unset):
            affected_products = []
            for affected_products_item_data in self.affected_products:
                affected_products_item = affected_products_item_data.to_dict()
                affected_products.append(affected_products_item)

        android_bulletin: dict[str, Any] | None | Unset
        if isinstance(self.android_bulletin, Unset):
            android_bulletin = UNSET
        elif isinstance(self.android_bulletin, AndroidBulletin):
            android_bulletin = self.android_bulletin.to_dict()
        else:
            android_bulletin = self.android_bulletin

        attack_patterns: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.attack_patterns, Unset):
            attack_patterns = []
            for attack_patterns_item_data in self.attack_patterns:
                attack_patterns_item = attack_patterns_item_data.to_dict()
                attack_patterns.append(attack_patterns_item)

        campaigns: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.campaigns, Unset):
            campaigns = []
            for campaigns_item_data in self.campaigns:
                campaigns_item = campaigns_item_data.to_dict()
                campaigns.append(campaigns_item)

        catalog_refs: dict[str, Any] | Unset = UNSET
        if not isinstance(self.catalog_refs, Unset):
            catalog_refs = self.catalog_refs.to_dict()

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

        certfr_advisories_total = self.certfr_advisories_total

        certfr_advisories_truncated = self.certfr_advisories_truncated

        cisa_campaigns: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.cisa_campaigns, Unset):
            cisa_campaigns = []
            for cisa_campaigns_item_data in self.cisa_campaigns:
                cisa_campaigns_item = cisa_campaigns_item_data.to_dict()
                cisa_campaigns.append(cisa_campaigns_item)

        confidence: dict[str, Any] | None | Unset
        if isinstance(self.confidence, Unset):
            confidence = UNSET
        elif isinstance(self.confidence, Confidence):
            confidence = self.confidence.to_dict()
        else:
            confidence = self.confidence

        csaf_advisories: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.csaf_advisories, Unset):
            csaf_advisories = []
            for csaf_advisories_item_data in self.csaf_advisories:
                csaf_advisories_item = csaf_advisories_item_data.to_dict()
                csaf_advisories.append(csaf_advisories_item)

        csaf_advisories_total = self.csaf_advisories_total

        csaf_advisories_truncated = self.csaf_advisories_truncated

        cve: dict[str, Any] | None | Unset
        if isinstance(self.cve, Unset):
            cve = UNSET
        elif isinstance(self.cve, CVEDetail):
            cve = self.cve.to_dict()
        else:
            cve = self.cve

        cvss_bt: dict[str, Any] | None | Unset
        if isinstance(self.cvss_bt, Unset):
            cvss_bt = UNSET
        elif isinstance(self.cvss_bt, CVSSBTScore):
            cvss_bt = self.cvss_bt.to_dict()
        else:
            cvss_bt = self.cvss_bt

        defend: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.defend, Unset):
            defend = []
            for defend_item_data in self.defend:
                defend_item = defend_item_data.to_dict()
                defend.append(defend_item)

        detections: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.detections, Unset):
            detections = []
            for detections_item_data in self.detections:
                detections_item = detections_item_data.to_dict()
                detections.append(detections_item)

        discovered_cve_id: None | str | Unset
        if isinstance(self.discovered_cve_id, Unset):
            discovered_cve_id = UNSET
        else:
            discovered_cve_id = self.discovered_cve_id

        distro_advisories: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.distro_advisories, Unset):
            distro_advisories = []
            for distro_advisories_item_data in self.distro_advisories:
                distro_advisories_item = distro_advisories_item_data.to_dict()
                distro_advisories.append(distro_advisories_item)

        distro_advisories_totals: dict[str, Any] | Unset = UNSET
        if not isinstance(self.distro_advisories_totals, Unset):
            distro_advisories_totals = self.distro_advisories_totals.to_dict()

        distro_advisories_truncated = self.distro_advisories_truncated

        emb3d_threats: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.emb3d_threats, Unset):
            emb3d_threats = []
            for emb3d_threats_item_data in self.emb3d_threats:
                emb3d_threats_item = emb3d_threats_item_data.to_dict()
                emb3d_threats.append(emb3d_threats_item)

        epss: dict[str, Any] | None | Unset
        if isinstance(self.epss, Unset):
            epss = UNSET
        elif isinstance(self.epss, EPSSScore):
            epss = self.epss.to_dict()
        else:
            epss = self.epss

        epss_velocity: dict[str, Any] | None | Unset
        if isinstance(self.epss_velocity, Unset):
            epss_velocity = UNSET
        elif isinstance(self.epss_velocity, EPSSVelocity):
            epss_velocity = self.epss_velocity.to_dict()
        else:
            epss_velocity = self.epss_velocity

        errors: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.errors, Unset):
            errors = []
            for errors_item_data in self.errors:
                errors_item = errors_item_data.to_dict()
                errors.append(errors_item)

        euvd: dict[str, Any] | None | Unset
        if isinstance(self.euvd, Unset):
            euvd = UNSET
        elif isinstance(self.euvd, EUVDEntry):
            euvd = self.euvd.to_dict()
        else:
            euvd = self.euvd

        exploits: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.exploits, Unset):
            exploits = []
            for exploits_item_data in self.exploits:
                exploits_item = exploits_item_data.to_dict()
                exploits.append(exploits_item)

        groups: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.groups, Unset):
            groups = []
            for groups_item_data in self.groups:
                groups_item = groups_item_data.to_dict()
                groups.append(groups_item)

        ics_weakness: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.ics_weakness, Unset):
            ics_weakness = []
            for ics_weakness_item_data in self.ics_weakness:
                ics_weakness_item = ics_weakness_item_data.to_dict()
                ics_weakness.append(ics_weakness_item)

        identifier_resolved: bool | None | Unset
        if isinstance(self.identifier_resolved, Unset):
            identifier_resolved = UNSET
        else:
            identifier_resolved = self.identifier_resolved

        iec_62443_requirements: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.iec_62443_requirements, Unset):
            iec_62443_requirements = []
            for iec_62443_requirements_item_data in self.iec_62443_requirements:
                iec_62443_requirements_item = iec_62443_requirements_item_data.to_dict()
                iec_62443_requirements.append(iec_62443_requirements_item)

        inferred_chain_candidates: list[dict[str, Any]] | None | Unset
        if isinstance(self.inferred_chain_candidates, Unset):
            inferred_chain_candidates = UNSET
        elif isinstance(self.inferred_chain_candidates, list):
            inferred_chain_candidates = []
            for inferred_chain_candidates_type_0_item_data in self.inferred_chain_candidates:
                inferred_chain_candidates_type_0_item = inferred_chain_candidates_type_0_item_data.to_dict()
                inferred_chain_candidates.append(inferred_chain_candidates_type_0_item)

        else:
            inferred_chain_candidates = self.inferred_chain_candidates

        jvn_advisories: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.jvn_advisories, Unset):
            jvn_advisories = []
            for jvn_advisories_item_data in self.jvn_advisories:
                jvn_advisories_item = jvn_advisories_item_data.to_dict()
                jvn_advisories.append(jvn_advisories_item)

        kev: dict[str, Any] | None | Unset
        if isinstance(self.kev, Unset):
            kev = UNSET
        elif isinstance(self.kev, KEVEntry):
            kev = self.kev.to_dict()
        else:
            kev = self.kev

        knowledgebase: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.knowledgebase, Unset):
            knowledgebase = []
            for knowledgebase_item_data in self.knowledgebase:
                knowledgebase_item = knowledgebase_item_data.to_dict()
                knowledgebase.append(knowledgebase_item)

        lev: dict[str, Any] | None | Unset
        if isinstance(self.lev, Unset):
            lev = UNSET
        elif isinstance(self.lev, LEVEstimate):
            lev = self.lev.to_dict()
        else:
            lev = self.lev

        likely_tactics: list[str] | None | Unset
        if isinstance(self.likely_tactics, Unset):
            likely_tactics = UNSET
        elif isinstance(self.likely_tactics, list):
            likely_tactics = self.likely_tactics

        else:
            likely_tactics = self.likely_tactics

        match_criteria: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.match_criteria, Unset):
            match_criteria = []
            for match_criteria_item_data in self.match_criteria:
                match_criteria_item = match_criteria_item_data.to_dict()
                match_criteria.append(match_criteria_item)

        metasploit_modules: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.metasploit_modules, Unset):
            metasploit_modules = []
            for metasploit_modules_item_data in self.metasploit_modules:
                metasploit_modules_item = metasploit_modules_item_data.to_dict()
                metasploit_modules.append(metasploit_modules_item)

        misp: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.misp, Unset):
            misp = []
            for misp_item_data in self.misp:
                misp_item = misp_item_data.to_dict()
                misp.append(misp_item)

        mitigations: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.mitigations, Unset):
            mitigations = []
            for mitigations_item_data in self.mitigations:
                mitigations_item = mitigations_item_data.to_dict()
                mitigations.append(mitigations_item)

        navigator: dict[str, Any] | None | Unset
        if isinstance(self.navigator, Unset):
            navigator = UNSET
        elif isinstance(self.navigator, CataloguedCVEResponseNavigatorType0):
            navigator = self.navigator.to_dict()
        else:
            navigator = self.navigator

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

        osv_advisories: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.osv_advisories, Unset):
            osv_advisories = []
            for osv_advisories_item_data in self.osv_advisories:
                osv_advisories_item = osv_advisories_item_data.to_dict()
                osv_advisories.append(osv_advisories_item)

        osv_advisories_total: int | None | Unset
        if isinstance(self.osv_advisories_total, Unset):
            osv_advisories_total = UNSET
        else:
            osv_advisories_total = self.osv_advisories_total

        osv_advisories_truncated = self.osv_advisories_truncated

        osv_next_offset: int | None | Unset
        if isinstance(self.osv_next_offset, Unset):
            osv_next_offset = UNSET
        else:
            osv_next_offset = self.osv_next_offset

        osv_snapshot_id: None | str | Unset
        if isinstance(self.osv_snapshot_id, Unset):
            osv_snapshot_id = UNSET
        else:
            osv_snapshot_id = self.osv_snapshot_id

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

        poc: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.poc, Unset):
            poc = []
            for poc_item_data in self.poc:
                poc_item = poc_item_data.to_dict()
                poc.append(poc_item)

        poc_source: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.poc_source, Unset):
            poc_source = []
            for poc_source_item_data in self.poc_source:
                poc_source_item = poc_source_item_data.to_dict()
                poc_source.append(poc_source_item)

        poc_total = self.poc_total

        poc_truncated = self.poc_truncated

        predictions: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.predictions, Unset):
            predictions = []
            for predictions_item_data in self.predictions:
                predictions_item = predictions_item_data.to_dict()
                predictions.append(predictions_item)

        revision_history: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.revision_history, Unset):
            revision_history = []
            for revision_history_item_data in self.revision_history:
                revision_history_item = revision_history_item_data.to_dict()
                revision_history.append(revision_history_item)

        sigma_rules: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.sigma_rules, Unset):
            sigma_rules = []
            for sigma_rules_item_data in self.sigma_rules:
                sigma_rules_item = sigma_rules_item_data.to_dict()
                sigma_rules.append(sigma_rules_item)

        similar_cves: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.similar_cves, Unset):
            similar_cves = []
            for similar_cves_item_data in self.similar_cves:
                similar_cves_item = similar_cves_item_data.to_dict()
                similar_cves.append(similar_cves_item)

        software: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.software, Unset):
            software = []
            for software_item_data in self.software:
                software_item = software_item_data.to_dict()
                software.append(software_item)

        ssvc: dict[str, Any] | None | Unset
        if isinstance(self.ssvc, Unset):
            ssvc = UNSET
        elif isinstance(self.ssvc, SSVCDecision):
            ssvc = self.ssvc.to_dict()
        else:
            ssvc = self.ssvc

        summary: None | str | Unset
        if isinstance(self.summary, Unset):
            summary = UNSET
        else:
            summary = self.summary

        techniques: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.techniques, Unset):
            techniques = []
            for techniques_item_data in self.techniques:
                techniques_item = techniques_item_data.to_dict()
                techniques.append(techniques_item)

        techniques_provenance: None | str | Unset
        if isinstance(self.techniques_provenance, Unset):
            techniques_provenance = UNSET
        elif isinstance(self.techniques_provenance, CataloguedCVEResponseTechniquesProvenanceType0):
            techniques_provenance = self.techniques_provenance.value
        else:
            techniques_provenance = self.techniques_provenance

        timeline: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.timeline, Unset):
            timeline = []
            for timeline_item_data in self.timeline:
                timeline_item = timeline_item_data.to_dict()
                timeline.append(timeline_item)

        unresolved_criteria_ids: list[str] | Unset = UNSET
        if not isinstance(self.unresolved_criteria_ids, Unset):
            unresolved_criteria_ids = self.unresolved_criteria_ids

        vendor_advisories: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.vendor_advisories, Unset):
            vendor_advisories = []
            for vendor_advisories_item_data in self.vendor_advisories:
                vendor_advisories_item = vendor_advisories_item_data.to_dict()
                vendor_advisories.append(vendor_advisories_item)

        vince_advisories: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.vince_advisories, Unset):
            vince_advisories = []
            for vince_advisories_item_data in self.vince_advisories:
                vince_advisories_item = vince_advisories_item_data.to_dict()
                vince_advisories.append(vince_advisories_item)

        vince_notes_total = self.vince_notes_total

        vince_notes_truncated = self.vince_notes_truncated

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

        weaknesses: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.weaknesses, Unset):
            weaknesses = []
            for weaknesses_item_data in self.weaknesses:
                weaknesses_item = weaknesses_item_data.to_dict()
                weaknesses.append(weaknesses_item)

        weaponization_score: float | None | Unset
        if isinstance(self.weaponization_score, Unset):
            weaponization_score = UNSET
        else:
            weaponization_score = self.weaponization_score

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if affected_chipsets is not UNSET:
            field_dict["affected_chipsets"] = affected_chipsets
        if affected_products is not UNSET:
            field_dict["affected_products"] = affected_products
        if android_bulletin is not UNSET:
            field_dict["android_bulletin"] = android_bulletin
        if attack_patterns is not UNSET:
            field_dict["attack_patterns"] = attack_patterns
        if campaigns is not UNSET:
            field_dict["campaigns"] = campaigns
        if catalog_refs is not UNSET:
            field_dict["catalog_refs"] = catalog_refs
        if cellular_annotations is not UNSET:
            field_dict["cellular_annotations"] = cellular_annotations
        if cellular_core_entries is not UNSET:
            field_dict["cellular_core_entries"] = cellular_core_entries
        if certfr_advisories is not UNSET:
            field_dict["certfr_advisories"] = certfr_advisories
        if certfr_advisories_total is not UNSET:
            field_dict["certfr_advisories_total"] = certfr_advisories_total
        if certfr_advisories_truncated is not UNSET:
            field_dict["certfr_advisories_truncated"] = certfr_advisories_truncated
        if cisa_campaigns is not UNSET:
            field_dict["cisa_campaigns"] = cisa_campaigns
        if confidence is not UNSET:
            field_dict["confidence"] = confidence
        if csaf_advisories is not UNSET:
            field_dict["csaf_advisories"] = csaf_advisories
        if csaf_advisories_total is not UNSET:
            field_dict["csaf_advisories_total"] = csaf_advisories_total
        if csaf_advisories_truncated is not UNSET:
            field_dict["csaf_advisories_truncated"] = csaf_advisories_truncated
        if cve is not UNSET:
            field_dict["cve"] = cve
        if cvss_bt is not UNSET:
            field_dict["cvss_bt"] = cvss_bt
        if defend is not UNSET:
            field_dict["defend"] = defend
        if detections is not UNSET:
            field_dict["detections"] = detections
        if discovered_cve_id is not UNSET:
            field_dict["discovered_cve_id"] = discovered_cve_id
        if distro_advisories is not UNSET:
            field_dict["distro_advisories"] = distro_advisories
        if distro_advisories_totals is not UNSET:
            field_dict["distro_advisories_totals"] = distro_advisories_totals
        if distro_advisories_truncated is not UNSET:
            field_dict["distro_advisories_truncated"] = distro_advisories_truncated
        if emb3d_threats is not UNSET:
            field_dict["emb3d_threats"] = emb3d_threats
        if epss is not UNSET:
            field_dict["epss"] = epss
        if epss_velocity is not UNSET:
            field_dict["epss_velocity"] = epss_velocity
        if errors is not UNSET:
            field_dict["errors"] = errors
        if euvd is not UNSET:
            field_dict["euvd"] = euvd
        if exploits is not UNSET:
            field_dict["exploits"] = exploits
        if groups is not UNSET:
            field_dict["groups"] = groups
        if ics_weakness is not UNSET:
            field_dict["ics_weakness"] = ics_weakness
        if identifier_resolved is not UNSET:
            field_dict["identifier_resolved"] = identifier_resolved
        if iec_62443_requirements is not UNSET:
            field_dict["iec_62443_requirements"] = iec_62443_requirements
        if inferred_chain_candidates is not UNSET:
            field_dict["inferred_chain_candidates"] = inferred_chain_candidates
        if jvn_advisories is not UNSET:
            field_dict["jvn_advisories"] = jvn_advisories
        if kev is not UNSET:
            field_dict["kev"] = kev
        if knowledgebase is not UNSET:
            field_dict["knowledgebase"] = knowledgebase
        if lev is not UNSET:
            field_dict["lev"] = lev
        if likely_tactics is not UNSET:
            field_dict["likely_tactics"] = likely_tactics
        if match_criteria is not UNSET:
            field_dict["match_criteria"] = match_criteria
        if metasploit_modules is not UNSET:
            field_dict["metasploit_modules"] = metasploit_modules
        if misp is not UNSET:
            field_dict["misp"] = misp
        if mitigations is not UNSET:
            field_dict["mitigations"] = mitigations
        if navigator is not UNSET:
            field_dict["navigator"] = navigator
        if nist_controls is not UNSET:
            field_dict["nist_controls"] = nist_controls
        if nuclei_templates is not UNSET:
            field_dict["nuclei_templates"] = nuclei_templates
        if osv_advisories is not UNSET:
            field_dict["osv_advisories"] = osv_advisories
        if osv_advisories_total is not UNSET:
            field_dict["osv_advisories_total"] = osv_advisories_total
        if osv_advisories_truncated is not UNSET:
            field_dict["osv_advisories_truncated"] = osv_advisories_truncated
        if osv_next_offset is not UNSET:
            field_dict["osv_next_offset"] = osv_next_offset
        if osv_snapshot_id is not UNSET:
            field_dict["osv_snapshot_id"] = osv_snapshot_id
        if ot_context is not UNSET:
            field_dict["ot_context"] = ot_context
        if ot_vendor_advisories is not UNSET:
            field_dict["ot_vendor_advisories"] = ot_vendor_advisories
        if poc is not UNSET:
            field_dict["poc"] = poc
        if poc_source is not UNSET:
            field_dict["poc_source"] = poc_source
        if poc_total is not UNSET:
            field_dict["poc_total"] = poc_total
        if poc_truncated is not UNSET:
            field_dict["poc_truncated"] = poc_truncated
        if predictions is not UNSET:
            field_dict["predictions"] = predictions
        if revision_history is not UNSET:
            field_dict["revision_history"] = revision_history
        if sigma_rules is not UNSET:
            field_dict["sigma_rules"] = sigma_rules
        if similar_cves is not UNSET:
            field_dict["similar_cves"] = similar_cves
        if software is not UNSET:
            field_dict["software"] = software
        if ssvc is not UNSET:
            field_dict["ssvc"] = ssvc
        if summary is not UNSET:
            field_dict["summary"] = summary
        if techniques is not UNSET:
            field_dict["techniques"] = techniques
        if techniques_provenance is not UNSET:
            field_dict["techniques_provenance"] = techniques_provenance
        if timeline is not UNSET:
            field_dict["timeline"] = timeline
        if unresolved_criteria_ids is not UNSET:
            field_dict["unresolved_criteria_ids"] = unresolved_criteria_ids
        if vendor_advisories is not UNSET:
            field_dict["vendor_advisories"] = vendor_advisories
        if vince_advisories is not UNSET:
            field_dict["vince_advisories"] = vince_advisories
        if vince_notes_total is not UNSET:
            field_dict["vince_notes_total"] = vince_notes_total
        if vince_notes_truncated is not UNSET:
            field_dict["vince_notes_truncated"] = vince_notes_truncated
        if vulnrichment is not UNSET:
            field_dict["vulnrichment"] = vulnrichment
        if weakness_ranks is not UNSET:
            field_dict["weakness_ranks"] = weakness_ranks
        if weaknesses is not UNSET:
            field_dict["weaknesses"] = weaknesses
        if weaponization_score is not UNSET:
            field_dict["weaponization_score"] = weaponization_score

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.affected_chipset import AffectedChipset  # noqa: PLC0415
        from ..models.affected_product import AffectedProduct  # noqa: PLC0415
        from ..models.android_bulletin import AndroidBulletin  # noqa: PLC0415
        from ..models.campaign_detail import CampaignDetail  # noqa: PLC0415
        from ..models.capec_detail import CAPECDetail  # noqa: PLC0415
        from ..models.catalogued_cve_response_catalog_refs import CataloguedCVEResponseCatalogRefs  # noqa: PLC0415
        from ..models.catalogued_cve_response_distro_advisories_totals import (
            CataloguedCVEResponseDistroAdvisoriesTotals,  # noqa: PLC0415
        )
        from ..models.catalogued_cve_response_navigator_type_0 import (
            CataloguedCVEResponseNavigatorType0,  # noqa: PLC0415
        )
        from ..models.cellular_annotation import CellularAnnotation  # noqa: PLC0415
        from ..models.cellular_core_entry import CellularCoreEntry  # noqa: PLC0415
        from ..models.cert_fr_advisory import CertFRAdvisory  # noqa: PLC0415
        from ..models.cisa_campaign_advisory import CISACampaignAdvisory  # noqa: PLC0415
        from ..models.confidence import Confidence  # noqa: PLC0415
        from ..models.csaf_advisory import CSAFAdvisory  # noqa: PLC0415
        from ..models.cve_detail import CVEDetail  # noqa: PLC0415
        from ..models.cvssbt_score import CVSSBTScore  # noqa: PLC0415
        from ..models.cwe_detail import CWEDetail  # noqa: PLC0415
        from ..models.d3fend_detail import D3FENDDetail  # noqa: PLC0415
        from ..models.detection_detail import DetectionDetail  # noqa: PLC0415
        from ..models.distro_advisory import DistroAdvisory  # noqa: PLC0415
        from ..models.emb3d_threat import EMB3DThreat  # noqa: PLC0415
        from ..models.epss_score import EPSSScore  # noqa: PLC0415
        from ..models.epss_velocity import EPSSVelocity  # noqa: PLC0415
        from ..models.error_detail import ErrorDetail  # noqa: PLC0415
        from ..models.euvd_entry import EUVDEntry  # noqa: PLC0415
        from ..models.exploit_detail import ExploitDetail  # noqa: PLC0415
        from ..models.group_detail import GroupDetail  # noqa: PLC0415
        from ..models.ics_weakness import ICSWeakness  # noqa: PLC0415
        from ..models.iec62443_requirement import IEC62443Requirement  # noqa: PLC0415
        from ..models.inferred_chain_candidate import InferredChainCandidate  # noqa: PLC0415
        from ..models.jvn_advisory import JVNAdvisory  # noqa: PLC0415
        from ..models.kev_entry import KEVEntry  # noqa: PLC0415
        from ..models.knowledgebase_result import KnowledgebaseResult  # noqa: PLC0415
        from ..models.lev_estimate import LEVEstimate  # noqa: PLC0415
        from ..models.match_criteria_detail import MatchCriteriaDetail  # noqa: PLC0415
        from ..models.metasploit_module import MetasploitModule  # noqa: PLC0415
        from ..models.misp_attribute import MISPAttribute  # noqa: PLC0415
        from ..models.mitigation_detail import MitigationDetail  # noqa: PLC0415
        from ..models.nist_control_mapping import NistControlMapping  # noqa: PLC0415
        from ..models.nuclei_template import NucleiTemplate  # noqa: PLC0415
        from ..models.osv_advisory import OSVAdvisory  # noqa: PLC0415
        from ..models.ot_context import OTContext  # noqa: PLC0415
        from ..models.ot_vendor_advisory import OTVendorAdvisory  # noqa: PLC0415
        from ..models.po_c_entry import PoCEntry  # noqa: PLC0415
        from ..models.po_c_source_entry import PoCSourceEntry  # noqa: PLC0415
        from ..models.revision_entry import RevisionEntry  # noqa: PLC0415
        from ..models.sigma_rule import SigmaRule  # noqa: PLC0415
        from ..models.similar_cve_mini import SimilarCVEMini  # noqa: PLC0415
        from ..models.software_detail import SoftwareDetail  # noqa: PLC0415
        from ..models.ssvc_decision import SSVCDecision  # noqa: PLC0415
        from ..models.technique_detail import TechniqueDetail  # noqa: PLC0415
        from ..models.threat_prediction import ThreatPrediction  # noqa: PLC0415
        from ..models.timeline_entry import TimelineEntry  # noqa: PLC0415
        from ..models.vendor_advisory import VendorAdvisory  # noqa: PLC0415
        from ..models.vince_advisory import VINCEAdvisory  # noqa: PLC0415
        from ..models.vulnrichment import Vulnrichment  # noqa: PLC0415
        from ..models.weakness_rank import WeaknessRank  # noqa: PLC0415

        d = dict(src_dict)
        _affected_chipsets = d.pop("affected_chipsets", UNSET)
        affected_chipsets: list[AffectedChipset] | Unset = UNSET
        if _affected_chipsets is not UNSET:
            affected_chipsets = []
            for affected_chipsets_item_data in _affected_chipsets:
                affected_chipsets_item = AffectedChipset.from_dict(affected_chipsets_item_data)

                affected_chipsets.append(affected_chipsets_item)

        _affected_products = d.pop("affected_products", UNSET)
        affected_products: list[AffectedProduct] | Unset = UNSET
        if _affected_products is not UNSET:
            affected_products = []
            for affected_products_item_data in _affected_products:
                affected_products_item = AffectedProduct.from_dict(affected_products_item_data)

                affected_products.append(affected_products_item)

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

        _attack_patterns = d.pop("attack_patterns", UNSET)
        attack_patterns: list[CAPECDetail] | Unset = UNSET
        if _attack_patterns is not UNSET:
            attack_patterns = []
            for attack_patterns_item_data in _attack_patterns:
                attack_patterns_item = CAPECDetail.from_dict(attack_patterns_item_data)

                attack_patterns.append(attack_patterns_item)

        _campaigns = d.pop("campaigns", UNSET)
        campaigns: list[CampaignDetail] | Unset = UNSET
        if _campaigns is not UNSET:
            campaigns = []
            for campaigns_item_data in _campaigns:
                campaigns_item = CampaignDetail.from_dict(campaigns_item_data)

                campaigns.append(campaigns_item)

        _catalog_refs = d.pop("catalog_refs", UNSET)
        catalog_refs: CataloguedCVEResponseCatalogRefs | Unset
        if isinstance(_catalog_refs, Unset):
            catalog_refs = UNSET
        else:
            catalog_refs = CataloguedCVEResponseCatalogRefs.from_dict(_catalog_refs)

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

        certfr_advisories_total = d.pop("certfr_advisories_total", UNSET)

        certfr_advisories_truncated = d.pop("certfr_advisories_truncated", UNSET)

        _cisa_campaigns = d.pop("cisa_campaigns", UNSET)
        cisa_campaigns: list[CISACampaignAdvisory] | Unset = UNSET
        if _cisa_campaigns is not UNSET:
            cisa_campaigns = []
            for cisa_campaigns_item_data in _cisa_campaigns:
                cisa_campaigns_item = CISACampaignAdvisory.from_dict(cisa_campaigns_item_data)

                cisa_campaigns.append(cisa_campaigns_item)

        def _parse_confidence(data: object) -> Confidence | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, dict):
                    raise TypeError()
                confidence_type_0 = Confidence.from_dict(data)

                return confidence_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(Confidence | None | Unset, data)

        confidence = _parse_confidence(d.pop("confidence", UNSET))

        _csaf_advisories = d.pop("csaf_advisories", UNSET)
        csaf_advisories: list[CSAFAdvisory] | Unset = UNSET
        if _csaf_advisories is not UNSET:
            csaf_advisories = []
            for csaf_advisories_item_data in _csaf_advisories:
                csaf_advisories_item = CSAFAdvisory.from_dict(csaf_advisories_item_data)

                csaf_advisories.append(csaf_advisories_item)

        csaf_advisories_total = d.pop("csaf_advisories_total", UNSET)

        csaf_advisories_truncated = d.pop("csaf_advisories_truncated", UNSET)

        def _parse_cve(data: object) -> CVEDetail | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, dict):
                    raise TypeError()
                cve_type_0 = CVEDetail.from_dict(data)

                return cve_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(CVEDetail | None | Unset, data)

        cve = _parse_cve(d.pop("cve", UNSET))

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

        _defend = d.pop("defend", UNSET)
        defend: list[D3FENDDetail] | Unset = UNSET
        if _defend is not UNSET:
            defend = []
            for defend_item_data in _defend:
                defend_item = D3FENDDetail.from_dict(defend_item_data)

                defend.append(defend_item)

        _detections = d.pop("detections", UNSET)
        detections: list[DetectionDetail] | Unset = UNSET
        if _detections is not UNSET:
            detections = []
            for detections_item_data in _detections:
                detections_item = DetectionDetail.from_dict(detections_item_data)

                detections.append(detections_item)

        def _parse_discovered_cve_id(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        discovered_cve_id = _parse_discovered_cve_id(d.pop("discovered_cve_id", UNSET))

        _distro_advisories = d.pop("distro_advisories", UNSET)
        distro_advisories: list[DistroAdvisory] | Unset = UNSET
        if _distro_advisories is not UNSET:
            distro_advisories = []
            for distro_advisories_item_data in _distro_advisories:
                distro_advisories_item = DistroAdvisory.from_dict(distro_advisories_item_data)

                distro_advisories.append(distro_advisories_item)

        _distro_advisories_totals = d.pop("distro_advisories_totals", UNSET)
        distro_advisories_totals: CataloguedCVEResponseDistroAdvisoriesTotals | Unset
        if isinstance(_distro_advisories_totals, Unset):
            distro_advisories_totals = UNSET
        else:
            distro_advisories_totals = CataloguedCVEResponseDistroAdvisoriesTotals.from_dict(_distro_advisories_totals)

        distro_advisories_truncated = d.pop("distro_advisories_truncated", UNSET)

        _emb3d_threats = d.pop("emb3d_threats", UNSET)
        emb3d_threats: list[EMB3DThreat] | Unset = UNSET
        if _emb3d_threats is not UNSET:
            emb3d_threats = []
            for emb3d_threats_item_data in _emb3d_threats:
                emb3d_threats_item = EMB3DThreat.from_dict(emb3d_threats_item_data)

                emb3d_threats.append(emb3d_threats_item)

        def _parse_epss(data: object) -> EPSSScore | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, dict):
                    raise TypeError()
                epss_type_0 = EPSSScore.from_dict(data)

                return epss_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(EPSSScore | None | Unset, data)

        epss = _parse_epss(d.pop("epss", UNSET))

        def _parse_epss_velocity(data: object) -> EPSSVelocity | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, dict):
                    raise TypeError()
                epss_velocity_type_0 = EPSSVelocity.from_dict(data)

                return epss_velocity_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(EPSSVelocity | None | Unset, data)

        epss_velocity = _parse_epss_velocity(d.pop("epss_velocity", UNSET))

        _errors = d.pop("errors", UNSET)
        errors: list[ErrorDetail] | Unset = UNSET
        if _errors is not UNSET:
            errors = []
            for errors_item_data in _errors:
                errors_item = ErrorDetail.from_dict(errors_item_data)

                errors.append(errors_item)

        def _parse_euvd(data: object) -> EUVDEntry | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, dict):
                    raise TypeError()
                euvd_type_0 = EUVDEntry.from_dict(data)

                return euvd_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(EUVDEntry | None | Unset, data)

        euvd = _parse_euvd(d.pop("euvd", UNSET))

        _exploits = d.pop("exploits", UNSET)
        exploits: list[ExploitDetail] | Unset = UNSET
        if _exploits is not UNSET:
            exploits = []
            for exploits_item_data in _exploits:
                exploits_item = ExploitDetail.from_dict(exploits_item_data)

                exploits.append(exploits_item)

        _groups = d.pop("groups", UNSET)
        groups: list[GroupDetail] | Unset = UNSET
        if _groups is not UNSET:
            groups = []
            for groups_item_data in _groups:
                groups_item = GroupDetail.from_dict(groups_item_data)

                groups.append(groups_item)

        _ics_weakness = d.pop("ics_weakness", UNSET)
        ics_weakness: list[ICSWeakness] | Unset = UNSET
        if _ics_weakness is not UNSET:
            ics_weakness = []
            for ics_weakness_item_data in _ics_weakness:
                ics_weakness_item = ICSWeakness.from_dict(ics_weakness_item_data)

                ics_weakness.append(ics_weakness_item)

        def _parse_identifier_resolved(data: object) -> bool | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(bool | None | Unset, data)

        identifier_resolved = _parse_identifier_resolved(d.pop("identifier_resolved", UNSET))

        _iec_62443_requirements = d.pop("iec_62443_requirements", UNSET)
        iec_62443_requirements: list[IEC62443Requirement] | Unset = UNSET
        if _iec_62443_requirements is not UNSET:
            iec_62443_requirements = []
            for iec_62443_requirements_item_data in _iec_62443_requirements:
                iec_62443_requirements_item = IEC62443Requirement.from_dict(iec_62443_requirements_item_data)

                iec_62443_requirements.append(iec_62443_requirements_item)

        def _parse_inferred_chain_candidates(data: object) -> list[InferredChainCandidate] | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, list):
                    raise TypeError()
                inferred_chain_candidates_type_0 = []
                _inferred_chain_candidates_type_0 = data
                for inferred_chain_candidates_type_0_item_data in _inferred_chain_candidates_type_0:
                    inferred_chain_candidates_type_0_item = InferredChainCandidate.from_dict(
                        inferred_chain_candidates_type_0_item_data
                    )

                    inferred_chain_candidates_type_0.append(inferred_chain_candidates_type_0_item)

                return inferred_chain_candidates_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(list[InferredChainCandidate] | None | Unset, data)

        inferred_chain_candidates = _parse_inferred_chain_candidates(d.pop("inferred_chain_candidates", UNSET))

        _jvn_advisories = d.pop("jvn_advisories", UNSET)
        jvn_advisories: list[JVNAdvisory] | Unset = UNSET
        if _jvn_advisories is not UNSET:
            jvn_advisories = []
            for jvn_advisories_item_data in _jvn_advisories:
                jvn_advisories_item = JVNAdvisory.from_dict(jvn_advisories_item_data)

                jvn_advisories.append(jvn_advisories_item)

        def _parse_kev(data: object) -> KEVEntry | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, dict):
                    raise TypeError()
                kev_type_0 = KEVEntry.from_dict(data)

                return kev_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(KEVEntry | None | Unset, data)

        kev = _parse_kev(d.pop("kev", UNSET))

        _knowledgebase = d.pop("knowledgebase", UNSET)
        knowledgebase: list[KnowledgebaseResult] | Unset = UNSET
        if _knowledgebase is not UNSET:
            knowledgebase = []
            for knowledgebase_item_data in _knowledgebase:
                knowledgebase_item = KnowledgebaseResult.from_dict(knowledgebase_item_data)

                knowledgebase.append(knowledgebase_item)

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

        _match_criteria = d.pop("match_criteria", UNSET)
        match_criteria: list[MatchCriteriaDetail] | Unset = UNSET
        if _match_criteria is not UNSET:
            match_criteria = []
            for match_criteria_item_data in _match_criteria:
                match_criteria_item = MatchCriteriaDetail.from_dict(match_criteria_item_data)

                match_criteria.append(match_criteria_item)

        _metasploit_modules = d.pop("metasploit_modules", UNSET)
        metasploit_modules: list[MetasploitModule] | Unset = UNSET
        if _metasploit_modules is not UNSET:
            metasploit_modules = []
            for metasploit_modules_item_data in _metasploit_modules:
                metasploit_modules_item = MetasploitModule.from_dict(metasploit_modules_item_data)

                metasploit_modules.append(metasploit_modules_item)

        _misp = d.pop("misp", UNSET)
        misp: list[MISPAttribute] | Unset = UNSET
        if _misp is not UNSET:
            misp = []
            for misp_item_data in _misp:
                misp_item = MISPAttribute.from_dict(misp_item_data)

                misp.append(misp_item)

        _mitigations = d.pop("mitigations", UNSET)
        mitigations: list[MitigationDetail] | Unset = UNSET
        if _mitigations is not UNSET:
            mitigations = []
            for mitigations_item_data in _mitigations:
                mitigations_item = MitigationDetail.from_dict(mitigations_item_data)

                mitigations.append(mitigations_item)

        def _parse_navigator(data: object) -> CataloguedCVEResponseNavigatorType0 | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, dict):
                    raise TypeError()
                navigator_type_0 = CataloguedCVEResponseNavigatorType0.from_dict(data)

                return navigator_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(CataloguedCVEResponseNavigatorType0 | None | Unset, data)

        navigator = _parse_navigator(d.pop("navigator", UNSET))

        _nist_controls = d.pop("nist_controls", UNSET)
        nist_controls: list[NistControlMapping] | Unset = UNSET
        if _nist_controls is not UNSET:
            nist_controls = []
            for nist_controls_item_data in _nist_controls:
                nist_controls_item = NistControlMapping.from_dict(nist_controls_item_data)

                nist_controls.append(nist_controls_item)

        _nuclei_templates = d.pop("nuclei_templates", UNSET)
        nuclei_templates: list[NucleiTemplate] | Unset = UNSET
        if _nuclei_templates is not UNSET:
            nuclei_templates = []
            for nuclei_templates_item_data in _nuclei_templates:
                nuclei_templates_item = NucleiTemplate.from_dict(nuclei_templates_item_data)

                nuclei_templates.append(nuclei_templates_item)

        _osv_advisories = d.pop("osv_advisories", UNSET)
        osv_advisories: list[OSVAdvisory] | Unset = UNSET
        if _osv_advisories is not UNSET:
            osv_advisories = []
            for osv_advisories_item_data in _osv_advisories:
                osv_advisories_item = OSVAdvisory.from_dict(osv_advisories_item_data)

                osv_advisories.append(osv_advisories_item)

        def _parse_osv_advisories_total(data: object) -> int | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(int | None | Unset, data)

        osv_advisories_total = _parse_osv_advisories_total(d.pop("osv_advisories_total", UNSET))

        osv_advisories_truncated = d.pop("osv_advisories_truncated", UNSET)

        def _parse_osv_next_offset(data: object) -> int | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(int | None | Unset, data)

        osv_next_offset = _parse_osv_next_offset(d.pop("osv_next_offset", UNSET))

        def _parse_osv_snapshot_id(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        osv_snapshot_id = _parse_osv_snapshot_id(d.pop("osv_snapshot_id", UNSET))

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

        _poc = d.pop("poc", UNSET)
        poc: list[PoCEntry] | Unset = UNSET
        if _poc is not UNSET:
            poc = []
            for poc_item_data in _poc:
                poc_item = PoCEntry.from_dict(poc_item_data)

                poc.append(poc_item)

        _poc_source = d.pop("poc_source", UNSET)
        poc_source: list[PoCSourceEntry] | Unset = UNSET
        if _poc_source is not UNSET:
            poc_source = []
            for poc_source_item_data in _poc_source:
                poc_source_item = PoCSourceEntry.from_dict(poc_source_item_data)

                poc_source.append(poc_source_item)

        poc_total = d.pop("poc_total", UNSET)

        poc_truncated = d.pop("poc_truncated", UNSET)

        _predictions = d.pop("predictions", UNSET)
        predictions: list[ThreatPrediction] | Unset = UNSET
        if _predictions is not UNSET:
            predictions = []
            for predictions_item_data in _predictions:
                predictions_item = ThreatPrediction.from_dict(predictions_item_data)

                predictions.append(predictions_item)

        _revision_history = d.pop("revision_history", UNSET)
        revision_history: list[RevisionEntry] | Unset = UNSET
        if _revision_history is not UNSET:
            revision_history = []
            for revision_history_item_data in _revision_history:
                revision_history_item = RevisionEntry.from_dict(revision_history_item_data)

                revision_history.append(revision_history_item)

        _sigma_rules = d.pop("sigma_rules", UNSET)
        sigma_rules: list[SigmaRule] | Unset = UNSET
        if _sigma_rules is not UNSET:
            sigma_rules = []
            for sigma_rules_item_data in _sigma_rules:
                sigma_rules_item = SigmaRule.from_dict(sigma_rules_item_data)

                sigma_rules.append(sigma_rules_item)

        _similar_cves = d.pop("similar_cves", UNSET)
        similar_cves: list[SimilarCVEMini] | Unset = UNSET
        if _similar_cves is not UNSET:
            similar_cves = []
            for similar_cves_item_data in _similar_cves:
                similar_cves_item = SimilarCVEMini.from_dict(similar_cves_item_data)

                similar_cves.append(similar_cves_item)

        _software = d.pop("software", UNSET)
        software: list[SoftwareDetail] | Unset = UNSET
        if _software is not UNSET:
            software = []
            for software_item_data in _software:
                software_item = SoftwareDetail.from_dict(software_item_data)

                software.append(software_item)

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

        def _parse_summary(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        summary = _parse_summary(d.pop("summary", UNSET))

        _techniques = d.pop("techniques", UNSET)
        techniques: list[TechniqueDetail] | Unset = UNSET
        if _techniques is not UNSET:
            techniques = []
            for techniques_item_data in _techniques:
                techniques_item = TechniqueDetail.from_dict(techniques_item_data)

                techniques.append(techniques_item)

        def _parse_techniques_provenance(data: object) -> CataloguedCVEResponseTechniquesProvenanceType0 | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, str):
                    raise TypeError()
                techniques_provenance_type_0 = CataloguedCVEResponseTechniquesProvenanceType0(data)

                return techniques_provenance_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(CataloguedCVEResponseTechniquesProvenanceType0 | None | Unset, data)

        techniques_provenance = _parse_techniques_provenance(d.pop("techniques_provenance", UNSET))

        _timeline = d.pop("timeline", UNSET)
        timeline: list[TimelineEntry] | Unset = UNSET
        if _timeline is not UNSET:
            timeline = []
            for timeline_item_data in _timeline:
                timeline_item = TimelineEntry.from_dict(timeline_item_data)

                timeline.append(timeline_item)

        unresolved_criteria_ids = cast(list[str], d.pop("unresolved_criteria_ids", UNSET))

        _vendor_advisories = d.pop("vendor_advisories", UNSET)
        vendor_advisories: list[VendorAdvisory] | Unset = UNSET
        if _vendor_advisories is not UNSET:
            vendor_advisories = []
            for vendor_advisories_item_data in _vendor_advisories:
                vendor_advisories_item = VendorAdvisory.from_dict(vendor_advisories_item_data)

                vendor_advisories.append(vendor_advisories_item)

        _vince_advisories = d.pop("vince_advisories", UNSET)
        vince_advisories: list[VINCEAdvisory] | Unset = UNSET
        if _vince_advisories is not UNSET:
            vince_advisories = []
            for vince_advisories_item_data in _vince_advisories:
                vince_advisories_item = VINCEAdvisory.from_dict(vince_advisories_item_data)

                vince_advisories.append(vince_advisories_item)

        vince_notes_total = d.pop("vince_notes_total", UNSET)

        vince_notes_truncated = d.pop("vince_notes_truncated", UNSET)

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

        _weaknesses = d.pop("weaknesses", UNSET)
        weaknesses: list[CWEDetail] | Unset = UNSET
        if _weaknesses is not UNSET:
            weaknesses = []
            for weaknesses_item_data in _weaknesses:
                weaknesses_item = CWEDetail.from_dict(weaknesses_item_data)

                weaknesses.append(weaknesses_item)

        def _parse_weaponization_score(data: object) -> float | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(float | None | Unset, data)

        weaponization_score = _parse_weaponization_score(d.pop("weaponization_score", UNSET))

        catalogued_cve_response = cls(
            affected_chipsets=affected_chipsets,
            affected_products=affected_products,
            android_bulletin=android_bulletin,
            attack_patterns=attack_patterns,
            campaigns=campaigns,
            catalog_refs=catalog_refs,
            cellular_annotations=cellular_annotations,
            cellular_core_entries=cellular_core_entries,
            certfr_advisories=certfr_advisories,
            certfr_advisories_total=certfr_advisories_total,
            certfr_advisories_truncated=certfr_advisories_truncated,
            cisa_campaigns=cisa_campaigns,
            confidence=confidence,
            csaf_advisories=csaf_advisories,
            csaf_advisories_total=csaf_advisories_total,
            csaf_advisories_truncated=csaf_advisories_truncated,
            cve=cve,
            cvss_bt=cvss_bt,
            defend=defend,
            detections=detections,
            discovered_cve_id=discovered_cve_id,
            distro_advisories=distro_advisories,
            distro_advisories_totals=distro_advisories_totals,
            distro_advisories_truncated=distro_advisories_truncated,
            emb3d_threats=emb3d_threats,
            epss=epss,
            epss_velocity=epss_velocity,
            errors=errors,
            euvd=euvd,
            exploits=exploits,
            groups=groups,
            ics_weakness=ics_weakness,
            identifier_resolved=identifier_resolved,
            iec_62443_requirements=iec_62443_requirements,
            inferred_chain_candidates=inferred_chain_candidates,
            jvn_advisories=jvn_advisories,
            kev=kev,
            knowledgebase=knowledgebase,
            lev=lev,
            likely_tactics=likely_tactics,
            match_criteria=match_criteria,
            metasploit_modules=metasploit_modules,
            misp=misp,
            mitigations=mitigations,
            navigator=navigator,
            nist_controls=nist_controls,
            nuclei_templates=nuclei_templates,
            osv_advisories=osv_advisories,
            osv_advisories_total=osv_advisories_total,
            osv_advisories_truncated=osv_advisories_truncated,
            osv_next_offset=osv_next_offset,
            osv_snapshot_id=osv_snapshot_id,
            ot_context=ot_context,
            ot_vendor_advisories=ot_vendor_advisories,
            poc=poc,
            poc_source=poc_source,
            poc_total=poc_total,
            poc_truncated=poc_truncated,
            predictions=predictions,
            revision_history=revision_history,
            sigma_rules=sigma_rules,
            similar_cves=similar_cves,
            software=software,
            ssvc=ssvc,
            summary=summary,
            techniques=techniques,
            techniques_provenance=techniques_provenance,
            timeline=timeline,
            unresolved_criteria_ids=unresolved_criteria_ids,
            vendor_advisories=vendor_advisories,
            vince_advisories=vince_advisories,
            vince_notes_total=vince_notes_total,
            vince_notes_truncated=vince_notes_truncated,
            vulnrichment=vulnrichment,
            weakness_ranks=weakness_ranks,
            weaknesses=weaknesses,
            weaponization_score=weaponization_score,
        )

        catalogued_cve_response.additional_properties = d
        return catalogued_cve_response

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

from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, BinaryIO, Generator, Literal, TextIO, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..models.batch_cve_item_techniques_scope import BatchCVEItemTechniquesScope
from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.artifact_enrichment_stakeholder import ArtifactEnrichmentStakeholder


T = TypeVar("T", bound="BatchCVEItem")


@_attrs_define
class BatchCVEItem:
    """Batch item: enrich a CVE.

    Attributes:
        cve_id (str): CVE identifier (e.g. CVE-2026-26929)
        include (list[str] | Unset): Response layers to include. Replaces the default list. Allowed values:
            affected_products, campaigns, capec, cisa_kev, criteria, cwe, defend, details, detections, epss, exploits,
            groups, inferred_chain, kev, knowledgebase, log_sources, metasploit, misp, mitigations, navigator,
            nist_controls, nuclei, osv, osv_restricted, poc, poc_source, similar_cves, software, ssvc, summary, techniques,
            tie, timeline, vendor_advisories, distro_advisories, versions, affected_chipsets, android_bulletin, cellular,
            cellular_core, cvss_bt, emb3d, sigma, vulnrichment, euvd, vince, csaf_advisories, certfr_advisories, jvn,
            ot_vendor_advisories, weakness_ranks. `capec_full`, `csaf_advisories_full`, and `certfr_advisories_full` restore
            full CVE rows; the advisory summaries retain at most 10 newest rows and omit large fields. `versions` attaches
            the object's KB revision history (`revision_history`). `cisa_kev` is included by default and reads the stored
            CISA catalog for this CVE, filling the `kev` columns the mirror cannot carry (`vendor_project`, `product`,
            `forensic_triage`) or left empty (`notes`), marking the entry `supplemented_from='cisa-official'`; a CVE the
            mirror does not carry gets a `kev` entry built from CISA's own record, so it does not need `kev` in the same
            request. `metasploit` and `nuclei` use stored catalogs. Along with `vendor_advisories`, they have separate
            response blocks (`metasploit_modules`, `nuclei_templates`, `vendor_advisories`); none feeds the offline
            authoritative path or the weaponization score. These layers are optional on this endpoint; artifact and
            inventory enrichment can add `metasploit` and `nuclei` automatically. `distro_advisories` adds stored SUSE CSAF-
            VEX, Ubuntu OpenVEX and Alpine secdb rows for this CVE, one per release (fixed / not_affected / needs_triage /
            open), each with its licence and attribution. Debian is not included. It does not feed the offline path.
            `distro_advisories_totals` (rows per source before the 200-row cap) and `distro_advisories_truncated` say what
            the cap cut. `criteria` resolves distinct `match_criteria_id` on the affected-product rows into the NVD
            criterion it names — its matchstring, version-range bounds, covered software and the CVEs it hits, plus its
            revision timestamps — so the join key that endpoint publishes resolves in the other direction; it loads those
            rows for itself, so it does not need `affected_products` in the same request (and does not publish that layer).
            `details` does not gate this endpoint's own `cve` object — it is returned whether or not the token is requested
            (the token still counts toward the include set `confidence` reports). The technique-derived layers (`groups`,
            `software`, `campaigns`, `mitigations`, `detections`, `defend`, `navigator`, `nist_controls`, `tie`) resolve the
            technique set they read, so they answer without `techniques` in the same request — and they never publish it:
            `techniques[]` still requires its own token. `timeline` reads the same EPSS series as `epss` and does not
            publish the `epss` object either. `cellular_core` returns the RANsacked research page's row for this CVE — the
            affected cellular-core implementation with its LTE/5G qualifier, from the curated 73-CVE table
            (`cellular_core_entries[]`); it is deliberately separate from `cellular`, which is the Zenodo 5G dataset with
            its own tags. `certfr_advisories` returns the CERT-FR (ANSSI) avis and alertes that reference this CVE, with the
            reference id, title, last revision date, canonical page URL, the advisory's own `scada` flag, affected
            vendors/products and its published risk descriptions (`certfr_advisories[]`); link and metadata only. `jvn`
            returns the JVNDB advisories that reference this CVE, as link and metadata rows (`jvn_advisories[]`); the
            advisory body is never redistributed. `ot_vendor_advisories` returns the direct OT/embedded vendor advisories
            that name this CVE — Rockwell Automation and MediaTek, with CVE ids, CVSS scores and MediaTek chipset codes
            (`ot_vendor_advisories[]`); a seeded in-process corpus, link and metadata only. `cisa_campaigns` returns the
            CISA joint cybersecurity advisories (AA-series) whose STIX bundle references this CVE, as bounded metadata plus
            context (`cisa_campaigns[]`: advisory id, title, published date, URL, sectors, locations, threat actors, ATT&CK
            techniques and the bundle's observable count); the advisory body is never redistributed. `defend` reaches its
            countermeasures through the technique's ATT&CK mitigations — the corpus links D3FEND to mitigations, never
            directly to a technique — and reports `error: "no_mapping"` only where that join finds none. `ot_context`
            attaches the OT/RF block: `sectors[]` (the ICS Advisory Project CSV, CSAF notes, then a curated vendor map, each
            row naming its source), `protocols[]` and `rf_technology[]` from CPE/product/CSAF/Nuclei text,
            `fix_availability` from CSAF product status, `kev_ot` from the KEV vendor, `access_vector_rf` from the CVSS
            access vector, and the CVE's ISA/IEC 62443 requirements. It is a deterministic zero-LLM derivation; it reads the
            cached Vulmatch `cve_bundle_software` rows and the CSAF table when requested alone, and adds no new external
            source. It also extends `weakness_ranks` with `ics_weakness[]` (CWE-1358) and `iec_62443_requirements[]`
            (CWE-1424), which the `weakness_ranks` token itself also returns.
        osv_offset (int | Unset): Position in the ordered OSV advisory candidates to continue from. Use only the
            `osv_next_offset` returned by the preceding OSV page, together with its `osv_snapshot_id`; page 0 omits both.
            Requires `osv` or `osv_restricted` in `include`. Default: 0.
        osv_snapshot_id (None | str | Unset): Snapshot returned with `osv_next_offset` when the response budget omitted
            OSV advisories. Resend the original request unchanged apart from `osv_offset` and this field; the reply is an
            OSV-only page. A changed stored-OSV generation or an expired snapshot returns 409 `snapshot_expired`; an
            unreadable snapshot store or stored copy returns 503 `snapshot_unavailable`.
        stakeholder (ArtifactEnrichmentStakeholder | None | Unset): Optional SSVC stakeholder context for
            `include=['ssvc']`. When omitted the ArtifactEnrichmentStakeholder defaults apply (CERT/CC Deployer tree,
            `exposure=open`, `human_impact=medium` — the worst-reasonable case for an unknown environment). Ignored when
            `ssvc` is not in `include`.
        techniques_scope (BatchCVEItemTechniquesScope | Unset): Precision filter for the resolved `techniques`. Trades
            recall against CVE-specificity:
            - `all` (default): every linked technique, including those derived from broad/Pillar CWEs (e.g. CWE-20 'Improper
            Input Validation'). Maximum recall, but unrelated CVEs sharing a generic CWE converge on the same coarse set —
            check `techniques_provenance` to tell which.
            - `specific`: drop techniques attributable only to a generic CWE's CAPEC closure, keeping those tied to the
            CVE's specific weaknesses. Higher precision; may be empty when the CVE has no specific ATT&CK mapping (the
            honest answer for such CVEs).
            Ignored when `techniques` is not in `include`. Default: BatchCVEItemTechniquesScope.ALL.
        type_ (Literal['cve'] | Unset): Selects CVE enrichment for this batch item Default: 'cve'.
    """

    cve_id: str
    include: list[str] | Unset = UNSET
    osv_offset: int | Unset = 0
    osv_snapshot_id: None | str | Unset = UNSET
    stakeholder: ArtifactEnrichmentStakeholder | None | Unset = UNSET
    techniques_scope: BatchCVEItemTechniquesScope | Unset = BatchCVEItemTechniquesScope.ALL
    type_: Literal["cve"] | Unset = "cve"
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        from ..models.artifact_enrichment_stakeholder import ArtifactEnrichmentStakeholder  # noqa: PLC0415

        cve_id = self.cve_id

        include: list[str] | Unset = UNSET
        if not isinstance(self.include, Unset):
            include = self.include

        osv_offset = self.osv_offset

        osv_snapshot_id: None | str | Unset
        if isinstance(self.osv_snapshot_id, Unset):
            osv_snapshot_id = UNSET
        else:
            osv_snapshot_id = self.osv_snapshot_id

        stakeholder: dict[str, Any] | None | Unset
        if isinstance(self.stakeholder, Unset):
            stakeholder = UNSET
        elif isinstance(self.stakeholder, ArtifactEnrichmentStakeholder):
            stakeholder = self.stakeholder.to_dict()
        else:
            stakeholder = self.stakeholder

        techniques_scope: str | Unset = UNSET
        if not isinstance(self.techniques_scope, Unset):
            techniques_scope = self.techniques_scope.value

        type_ = self.type_

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "cve_id": cve_id,
            }
        )
        if include is not UNSET:
            field_dict["include"] = include
        if osv_offset is not UNSET:
            field_dict["osv_offset"] = osv_offset
        if osv_snapshot_id is not UNSET:
            field_dict["osv_snapshot_id"] = osv_snapshot_id
        if stakeholder is not UNSET:
            field_dict["stakeholder"] = stakeholder
        if techniques_scope is not UNSET:
            field_dict["techniques_scope"] = techniques_scope
        if type_ is not UNSET:
            field_dict["type"] = type_

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.artifact_enrichment_stakeholder import ArtifactEnrichmentStakeholder  # noqa: PLC0415

        d = dict(src_dict)
        cve_id = d.pop("cve_id")

        include = cast(list[str], d.pop("include", UNSET))

        osv_offset = d.pop("osv_offset", UNSET)

        def _parse_osv_snapshot_id(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        osv_snapshot_id = _parse_osv_snapshot_id(d.pop("osv_snapshot_id", UNSET))

        def _parse_stakeholder(data: object) -> ArtifactEnrichmentStakeholder | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, dict):
                    raise TypeError()
                stakeholder_type_0 = ArtifactEnrichmentStakeholder.from_dict(data)

                return stakeholder_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(ArtifactEnrichmentStakeholder | None | Unset, data)

        stakeholder = _parse_stakeholder(d.pop("stakeholder", UNSET))

        _techniques_scope = d.pop("techniques_scope", UNSET)
        techniques_scope: BatchCVEItemTechniquesScope | Unset
        if isinstance(_techniques_scope, Unset):
            techniques_scope = UNSET
        else:
            techniques_scope = BatchCVEItemTechniquesScope(_techniques_scope)

        type_ = cast(Literal["cve"] | Unset, d.pop("type", UNSET))
        if type_ != "cve" and not isinstance(type_, Unset):
            raise ValueError(f"type must match const 'cve', got '{type_}'")

        batch_cve_item = cls(
            cve_id=cve_id,
            include=include,
            osv_offset=osv_offset,
            osv_snapshot_id=osv_snapshot_id,
            stakeholder=stakeholder,
            techniques_scope=techniques_scope,
            type_=type_,
        )

        batch_cve_item.additional_properties = d
        return batch_cve_item

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

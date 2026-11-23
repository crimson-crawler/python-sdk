from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, BinaryIO, Generator, TextIO, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.asset_class import AssetClass
    from ..models.atomic_red_team_test import AtomicRedTeamTest
    from ..models.campaign_detail import CampaignDetail
    from ..models.cisa_campaign_advisory import CISACampaignAdvisory
    from ..models.cve_mini_detail import CVEMiniDetail
    from ..models.d3fend_detail import D3FENDDetail
    from ..models.detection_detail import DetectionDetail
    from ..models.enrich_technique_response_navigator_type_0 import EnrichTechniqueResponseNavigatorType0
    from ..models.error_detail import ErrorDetail
    from ..models.fight_technique import FightTechnique
    from ..models.framework_mapping import FrameworkMapping
    from ..models.group_detail import GroupDetail
    from ..models.gtfo_bins_binary import GTFOBinsBinary
    from ..models.hijack_libs_entry import HijackLibsEntry
    from ..models.knowledgebase_result import KnowledgebaseResult
    from ..models.lol_driver import LOLDriver
    from ..models.lolbas_binary import LOLBASBinary
    from ..models.misp_event import MISPEvent
    from ..models.mitigation_detail import MitigationDetail
    from ..models.nist_control_mapping import NistControlMapping
    from ..models.sigma_rule import SigmaRule
    from ..models.software_detail import SoftwareDetail
    from ..models.technique_detail import TechniqueDetail
    from ..models.threat_prediction import ThreatPrediction


T = TypeVar("T", bound="EnrichTechniqueResponse")


@_attrs_define
class EnrichTechniqueResponse:
    """ATT&CK technique enrichment with threat predictions and related intelligence.

    Attributes:
        asset (AssetClass | None | Unset): ICS only, and only for an `asset_id` request: the requested asset class. Null
            on every other selector — the asset is never substituted for a technique.
        asset_classes (list[AssetClass] | Unset): The ICS asset classes the returned techniques target (PLC, HMI, RTU,
            Safety Controller, …), deduplicated by asset id and read from the ICS technique rows' own `targets` edges. Opt-
            in via include=['asset_classes'] on an `ics` framework request; enterprise/mobile rows carry no assets, so the
            list is empty there. For an `asset_id` request the requested asset is returned in `asset`; the rows in
            `techniques` are its targets and do not carry assets of their own.
        atomic_tests (list[AtomicRedTeamTest] | Unset): Atomic Red Team tests exercising this technique (a parent also
            matches its sub-techniques), first 50 per technique; see `atomic_tests_total`. Name, GUID, supported platforms,
            executor kind, elevation flag and the upstream YAML link only — no command bodies. Opt-in via
            include=['atomic_red_team']; a committed MIT-licensed projection read in-process.
        atomic_tests_total (int | Unset): Atomic Red Team tests matching this technique before the per-technique cap
            Default: 0.
        campaigns (list[CampaignDetail] | Unset): Threat campaigns that used the linked techniques
        cisa_campaigns (list[CISACampaignAdvisory] | Unset): CISA joint cybersecurity advisories (AA-series) whose STIX
            bundle names this ATT&CK technique, deduplicated by advisory id (a parent technique also matches advisories
            naming one of its sub-techniques). Opt-in via include=['cisa_campaigns']; a zero-cost in-process corpus read.
        cves (list[CVEMiniDetail] | Unset): CVEs linked to these techniques
        defend (list[D3FENDDetail] | Unset): D3FEND defensive techniques and countermeasures for the linked ATT&CK
            techniques. The default form omits each row's `description`, `aliases`, STIX `pattern` and `stix_id`; request
            include=['defend_full'] for them. The STIX licence marking (`object_marking_refs`) is kept in both forms.
        detections (list[DetectionDetail] | Unset): Detection data sources and components for the linked techniques
        errors (list[ErrorDetail] | Unset): Partial failure details
        fight_techniques (list[FightTechnique] | Unset): MITRE FiGHT 5G techniques whose own `FGT####` id maps onto this
            ATT&CK id (strip FGT, prefix T, keep the dotted suffix — never a name match). Opt-in via include=['fight'];
            FiGHT-specific sub-techniques with no ATT&CK parent answer [].
        framework_mappings (list[FrameworkMapping] | Unset): CTID multi-framework control/capability mappings for the
            requested technique ids — one row per framework capability, each carrying the framework's own version and the
            ATT&CK version that family was built against (the nine committed families use different ATT&CK versions, so rows
            are never merged across versions). Opt-in via include=['framework_mappings']; an unmapped sub-technique answers
            with its parent's rows.
        groups (list[GroupDetail] | Unset): Threat actor groups known to use the linked techniques
        gtfobins_binaries (list[GTFOBinsBinary] | Unset): GTFOBins tools whose function/context categories map onto this
            ATT&CK technique (a parent also matches tools mapped to one of its sub-techniques), first 50 per technique; see
            `gtfobins_binaries_total`. Names, categories and the project page only — no snippets or descriptions. Opt-in via
            include=['lotl'].
        gtfobins_binaries_total (int | Unset): GTFOBins tools matching this technique before the per-technique cap
            Default: 0.
        hijacklibs_entries (list[HijackLibsEntry] | Unset): HijackLibs DLL hijacks whose vulnerable-executable type maps
            onto this ATT&CK technique (T1574.001 search order/phantom/environment-variable types, T1574.002 sideloading),
            first 50 per technique; see `hijacklibs_entries_total`. Names, paths, vendor and types only — opt-in via
            include=['lotl'].
        hijacklibs_entries_total (int | Unset): HijackLibs entries matching this technique before the per-technique cap
            Default: 0.
        identifier_resolved (bool | None | Unset): Whether the object this request looked up directly resolved to a
            record. `false` means it was not found, so every layer below is empty for that reason rather than because the
            record exists and has no data — the two were previously indistinguishable. `null` when the request used
            `search`, where an empty result is a legitimate no-match, or when the lookup was never attempted (a
            `details`-less technique-id request). For `technique_id`/`technique_ids` requests `true` means at least one id
            resolved, NOT that all did, and the marker is reported only when the technique objects were loaded. For an
            `asset_id` request it reports whether the ASSET resolved — decided on every request, `details` or not, since the
            asset class is this response's own object for that selector — so a resolved asset whose `techniques` list
            happens to be empty is `true`, while `false` means the asset was not published: either the id is not in the
            corpus, or the read of that asset failed, and `errors[]` (step `fetch_ics_asset`) is what distinguishes the two.
        knowledgebase (list[KnowledgebaseResult] | Unset): Related intelligence from the knowledge base
        lol_drivers (list[LOLDriver] | Unset): LOLDrivers entries exercising this technique (first 50 per technique; see
            `lol_drivers_total`). Opt-in via include=['lotl']; read from the seeded LOLDrivers index in-process.
        lol_drivers_total (int | Unset): LOLDrivers rows matching this technique before the per-technique cap Default:
            0.
        lolbas_binaries (list[LOLBASBinary] | Unset): LOLBAS binaries whose commands declare this ATT&CK technique (a
            parent also matches binaries tagged one of its sub-techniques). Names, technique ids and the project page only —
            no commands or descriptions. Opt-in via include=['lolbas']; GTFOBins and HijackLibs arrive on the `lotl` token.
        misp (list[MISPEvent] | Unset): Threat events referencing these techniques
        mitigations (list[MitigationDetail] | Unset): Defensive mitigations for the linked techniques
        navigator (EnrichTechniqueResponseNavigatorType0 | None | Unset): ATT&CK Navigator layer JSON for visualization
            in MITRE's Navigator tool
        nist_controls (list[NistControlMapping] | Unset): NIST SP 800-53 rev 5 controls that mitigate the techniques on
            this response, via MITRE CTID. Pass-through static lookup; only populates when 'nist_controls' is in the request
            include set.
        predictions (list[ThreatPrediction] | Unset): Threat predictions for each technique
        sigma_rules (list[SigmaRule] | Unset): SigmaHQ detection rules whose ATT&CK tags name this technique (a parent
            technique also matches its sub-technique rules). Opt-in via include=['sigma']; DRL-1.1, attributed via
            `source_url`.
        software (list[SoftwareDetail] | Unset): Malware and tools that employ the linked techniques
        summary (None | str | Unset): AI-generated summary of the technique and its mitigations
        techniques (list[TechniqueDetail] | Unset): Technique details including tactics, platforms, and mitigations. For
            an `asset_id` request these are the asset's own targets (the ICS techniques whose `targets` edge points at it).
        threat_level (None | str | Unset): Computed threat classification: critical, high, medium, or low
    """

    asset: AssetClass | None | Unset = UNSET
    asset_classes: list[AssetClass] | Unset = UNSET
    atomic_tests: list[AtomicRedTeamTest] | Unset = UNSET
    atomic_tests_total: int | Unset = 0
    campaigns: list[CampaignDetail] | Unset = UNSET
    cisa_campaigns: list[CISACampaignAdvisory] | Unset = UNSET
    cves: list[CVEMiniDetail] | Unset = UNSET
    defend: list[D3FENDDetail] | Unset = UNSET
    detections: list[DetectionDetail] | Unset = UNSET
    errors: list[ErrorDetail] | Unset = UNSET
    fight_techniques: list[FightTechnique] | Unset = UNSET
    framework_mappings: list[FrameworkMapping] | Unset = UNSET
    groups: list[GroupDetail] | Unset = UNSET
    gtfobins_binaries: list[GTFOBinsBinary] | Unset = UNSET
    gtfobins_binaries_total: int | Unset = 0
    hijacklibs_entries: list[HijackLibsEntry] | Unset = UNSET
    hijacklibs_entries_total: int | Unset = 0
    identifier_resolved: bool | None | Unset = UNSET
    knowledgebase: list[KnowledgebaseResult] | Unset = UNSET
    lol_drivers: list[LOLDriver] | Unset = UNSET
    lol_drivers_total: int | Unset = 0
    lolbas_binaries: list[LOLBASBinary] | Unset = UNSET
    misp: list[MISPEvent] | Unset = UNSET
    mitigations: list[MitigationDetail] | Unset = UNSET
    navigator: EnrichTechniqueResponseNavigatorType0 | None | Unset = UNSET
    nist_controls: list[NistControlMapping] | Unset = UNSET
    predictions: list[ThreatPrediction] | Unset = UNSET
    sigma_rules: list[SigmaRule] | Unset = UNSET
    software: list[SoftwareDetail] | Unset = UNSET
    summary: None | str | Unset = UNSET
    techniques: list[TechniqueDetail] | Unset = UNSET
    threat_level: None | str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        from ..models.asset_class import AssetClass  # noqa: PLC0415
        from ..models.atomic_red_team_test import AtomicRedTeamTest  # noqa: PLC0415
        from ..models.campaign_detail import CampaignDetail  # noqa: PLC0415
        from ..models.cisa_campaign_advisory import CISACampaignAdvisory  # noqa: PLC0415
        from ..models.cve_mini_detail import CVEMiniDetail  # noqa: PLC0415
        from ..models.d3fend_detail import D3FENDDetail  # noqa: PLC0415
        from ..models.detection_detail import DetectionDetail  # noqa: PLC0415
        from ..models.enrich_technique_response_navigator_type_0 import (
            EnrichTechniqueResponseNavigatorType0,  # noqa: PLC0415
        )
        from ..models.error_detail import ErrorDetail  # noqa: PLC0415
        from ..models.fight_technique import FightTechnique  # noqa: PLC0415
        from ..models.framework_mapping import FrameworkMapping  # noqa: PLC0415
        from ..models.group_detail import GroupDetail  # noqa: PLC0415
        from ..models.gtfo_bins_binary import GTFOBinsBinary  # noqa: PLC0415
        from ..models.hijack_libs_entry import HijackLibsEntry  # noqa: PLC0415
        from ..models.knowledgebase_result import KnowledgebaseResult  # noqa: PLC0415
        from ..models.lol_driver import LOLDriver  # noqa: PLC0415
        from ..models.lolbas_binary import LOLBASBinary  # noqa: PLC0415
        from ..models.misp_event import MISPEvent  # noqa: PLC0415
        from ..models.mitigation_detail import MitigationDetail  # noqa: PLC0415
        from ..models.nist_control_mapping import NistControlMapping  # noqa: PLC0415
        from ..models.sigma_rule import SigmaRule  # noqa: PLC0415
        from ..models.software_detail import SoftwareDetail  # noqa: PLC0415
        from ..models.technique_detail import TechniqueDetail  # noqa: PLC0415
        from ..models.threat_prediction import ThreatPrediction  # noqa: PLC0415

        asset: dict[str, Any] | None | Unset
        if isinstance(self.asset, Unset):
            asset = UNSET
        elif isinstance(self.asset, AssetClass):
            asset = self.asset.to_dict()
        else:
            asset = self.asset

        asset_classes: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.asset_classes, Unset):
            asset_classes = []
            for asset_classes_item_data in self.asset_classes:
                asset_classes_item = asset_classes_item_data.to_dict()
                asset_classes.append(asset_classes_item)

        atomic_tests: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.atomic_tests, Unset):
            atomic_tests = []
            for atomic_tests_item_data in self.atomic_tests:
                atomic_tests_item = atomic_tests_item_data.to_dict()
                atomic_tests.append(atomic_tests_item)

        atomic_tests_total = self.atomic_tests_total

        campaigns: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.campaigns, Unset):
            campaigns = []
            for campaigns_item_data in self.campaigns:
                campaigns_item = campaigns_item_data.to_dict()
                campaigns.append(campaigns_item)

        cisa_campaigns: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.cisa_campaigns, Unset):
            cisa_campaigns = []
            for cisa_campaigns_item_data in self.cisa_campaigns:
                cisa_campaigns_item = cisa_campaigns_item_data.to_dict()
                cisa_campaigns.append(cisa_campaigns_item)

        cves: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.cves, Unset):
            cves = []
            for cves_item_data in self.cves:
                cves_item = cves_item_data.to_dict()
                cves.append(cves_item)

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

        errors: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.errors, Unset):
            errors = []
            for errors_item_data in self.errors:
                errors_item = errors_item_data.to_dict()
                errors.append(errors_item)

        fight_techniques: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.fight_techniques, Unset):
            fight_techniques = []
            for fight_techniques_item_data in self.fight_techniques:
                fight_techniques_item = fight_techniques_item_data.to_dict()
                fight_techniques.append(fight_techniques_item)

        framework_mappings: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.framework_mappings, Unset):
            framework_mappings = []
            for framework_mappings_item_data in self.framework_mappings:
                framework_mappings_item = framework_mappings_item_data.to_dict()
                framework_mappings.append(framework_mappings_item)

        groups: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.groups, Unset):
            groups = []
            for groups_item_data in self.groups:
                groups_item = groups_item_data.to_dict()
                groups.append(groups_item)

        gtfobins_binaries: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.gtfobins_binaries, Unset):
            gtfobins_binaries = []
            for gtfobins_binaries_item_data in self.gtfobins_binaries:
                gtfobins_binaries_item = gtfobins_binaries_item_data.to_dict()
                gtfobins_binaries.append(gtfobins_binaries_item)

        gtfobins_binaries_total = self.gtfobins_binaries_total

        hijacklibs_entries: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.hijacklibs_entries, Unset):
            hijacklibs_entries = []
            for hijacklibs_entries_item_data in self.hijacklibs_entries:
                hijacklibs_entries_item = hijacklibs_entries_item_data.to_dict()
                hijacklibs_entries.append(hijacklibs_entries_item)

        hijacklibs_entries_total = self.hijacklibs_entries_total

        identifier_resolved: bool | None | Unset
        if isinstance(self.identifier_resolved, Unset):
            identifier_resolved = UNSET
        else:
            identifier_resolved = self.identifier_resolved

        knowledgebase: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.knowledgebase, Unset):
            knowledgebase = []
            for knowledgebase_item_data in self.knowledgebase:
                knowledgebase_item = knowledgebase_item_data.to_dict()
                knowledgebase.append(knowledgebase_item)

        lol_drivers: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.lol_drivers, Unset):
            lol_drivers = []
            for lol_drivers_item_data in self.lol_drivers:
                lol_drivers_item = lol_drivers_item_data.to_dict()
                lol_drivers.append(lol_drivers_item)

        lol_drivers_total = self.lol_drivers_total

        lolbas_binaries: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.lolbas_binaries, Unset):
            lolbas_binaries = []
            for lolbas_binaries_item_data in self.lolbas_binaries:
                lolbas_binaries_item = lolbas_binaries_item_data.to_dict()
                lolbas_binaries.append(lolbas_binaries_item)

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
        elif isinstance(self.navigator, EnrichTechniqueResponseNavigatorType0):
            navigator = self.navigator.to_dict()
        else:
            navigator = self.navigator

        nist_controls: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.nist_controls, Unset):
            nist_controls = []
            for nist_controls_item_data in self.nist_controls:
                nist_controls_item = nist_controls_item_data.to_dict()
                nist_controls.append(nist_controls_item)

        predictions: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.predictions, Unset):
            predictions = []
            for predictions_item_data in self.predictions:
                predictions_item = predictions_item_data.to_dict()
                predictions.append(predictions_item)

        sigma_rules: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.sigma_rules, Unset):
            sigma_rules = []
            for sigma_rules_item_data in self.sigma_rules:
                sigma_rules_item = sigma_rules_item_data.to_dict()
                sigma_rules.append(sigma_rules_item)

        software: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.software, Unset):
            software = []
            for software_item_data in self.software:
                software_item = software_item_data.to_dict()
                software.append(software_item)

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

        threat_level: None | str | Unset
        if isinstance(self.threat_level, Unset):
            threat_level = UNSET
        else:
            threat_level = self.threat_level

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if asset is not UNSET:
            field_dict["asset"] = asset
        if asset_classes is not UNSET:
            field_dict["asset_classes"] = asset_classes
        if atomic_tests is not UNSET:
            field_dict["atomic_tests"] = atomic_tests
        if atomic_tests_total is not UNSET:
            field_dict["atomic_tests_total"] = atomic_tests_total
        if campaigns is not UNSET:
            field_dict["campaigns"] = campaigns
        if cisa_campaigns is not UNSET:
            field_dict["cisa_campaigns"] = cisa_campaigns
        if cves is not UNSET:
            field_dict["cves"] = cves
        if defend is not UNSET:
            field_dict["defend"] = defend
        if detections is not UNSET:
            field_dict["detections"] = detections
        if errors is not UNSET:
            field_dict["errors"] = errors
        if fight_techniques is not UNSET:
            field_dict["fight_techniques"] = fight_techniques
        if framework_mappings is not UNSET:
            field_dict["framework_mappings"] = framework_mappings
        if groups is not UNSET:
            field_dict["groups"] = groups
        if gtfobins_binaries is not UNSET:
            field_dict["gtfobins_binaries"] = gtfobins_binaries
        if gtfobins_binaries_total is not UNSET:
            field_dict["gtfobins_binaries_total"] = gtfobins_binaries_total
        if hijacklibs_entries is not UNSET:
            field_dict["hijacklibs_entries"] = hijacklibs_entries
        if hijacklibs_entries_total is not UNSET:
            field_dict["hijacklibs_entries_total"] = hijacklibs_entries_total
        if identifier_resolved is not UNSET:
            field_dict["identifier_resolved"] = identifier_resolved
        if knowledgebase is not UNSET:
            field_dict["knowledgebase"] = knowledgebase
        if lol_drivers is not UNSET:
            field_dict["lol_drivers"] = lol_drivers
        if lol_drivers_total is not UNSET:
            field_dict["lol_drivers_total"] = lol_drivers_total
        if lolbas_binaries is not UNSET:
            field_dict["lolbas_binaries"] = lolbas_binaries
        if misp is not UNSET:
            field_dict["misp"] = misp
        if mitigations is not UNSET:
            field_dict["mitigations"] = mitigations
        if navigator is not UNSET:
            field_dict["navigator"] = navigator
        if nist_controls is not UNSET:
            field_dict["nist_controls"] = nist_controls
        if predictions is not UNSET:
            field_dict["predictions"] = predictions
        if sigma_rules is not UNSET:
            field_dict["sigma_rules"] = sigma_rules
        if software is not UNSET:
            field_dict["software"] = software
        if summary is not UNSET:
            field_dict["summary"] = summary
        if techniques is not UNSET:
            field_dict["techniques"] = techniques
        if threat_level is not UNSET:
            field_dict["threat_level"] = threat_level

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.asset_class import AssetClass  # noqa: PLC0415
        from ..models.atomic_red_team_test import AtomicRedTeamTest  # noqa: PLC0415
        from ..models.campaign_detail import CampaignDetail  # noqa: PLC0415
        from ..models.cisa_campaign_advisory import CISACampaignAdvisory  # noqa: PLC0415
        from ..models.cve_mini_detail import CVEMiniDetail  # noqa: PLC0415
        from ..models.d3fend_detail import D3FENDDetail  # noqa: PLC0415
        from ..models.detection_detail import DetectionDetail  # noqa: PLC0415
        from ..models.enrich_technique_response_navigator_type_0 import (
            EnrichTechniqueResponseNavigatorType0,  # noqa: PLC0415
        )
        from ..models.error_detail import ErrorDetail  # noqa: PLC0415
        from ..models.fight_technique import FightTechnique  # noqa: PLC0415
        from ..models.framework_mapping import FrameworkMapping  # noqa: PLC0415
        from ..models.group_detail import GroupDetail  # noqa: PLC0415
        from ..models.gtfo_bins_binary import GTFOBinsBinary  # noqa: PLC0415
        from ..models.hijack_libs_entry import HijackLibsEntry  # noqa: PLC0415
        from ..models.knowledgebase_result import KnowledgebaseResult  # noqa: PLC0415
        from ..models.lol_driver import LOLDriver  # noqa: PLC0415
        from ..models.lolbas_binary import LOLBASBinary  # noqa: PLC0415
        from ..models.misp_event import MISPEvent  # noqa: PLC0415
        from ..models.mitigation_detail import MitigationDetail  # noqa: PLC0415
        from ..models.nist_control_mapping import NistControlMapping  # noqa: PLC0415
        from ..models.sigma_rule import SigmaRule  # noqa: PLC0415
        from ..models.software_detail import SoftwareDetail  # noqa: PLC0415
        from ..models.technique_detail import TechniqueDetail  # noqa: PLC0415
        from ..models.threat_prediction import ThreatPrediction  # noqa: PLC0415

        d = dict(src_dict)

        def _parse_asset(data: object) -> AssetClass | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, dict):
                    raise TypeError()
                asset_type_0 = AssetClass.from_dict(data)

                return asset_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(AssetClass | None | Unset, data)

        asset = _parse_asset(d.pop("asset", UNSET))

        _asset_classes = d.pop("asset_classes", UNSET)
        asset_classes: list[AssetClass] | Unset = UNSET
        if _asset_classes is not UNSET:
            asset_classes = []
            for asset_classes_item_data in _asset_classes:
                asset_classes_item = AssetClass.from_dict(asset_classes_item_data)

                asset_classes.append(asset_classes_item)

        _atomic_tests = d.pop("atomic_tests", UNSET)
        atomic_tests: list[AtomicRedTeamTest] | Unset = UNSET
        if _atomic_tests is not UNSET:
            atomic_tests = []
            for atomic_tests_item_data in _atomic_tests:
                atomic_tests_item = AtomicRedTeamTest.from_dict(atomic_tests_item_data)

                atomic_tests.append(atomic_tests_item)

        atomic_tests_total = d.pop("atomic_tests_total", UNSET)

        _campaigns = d.pop("campaigns", UNSET)
        campaigns: list[CampaignDetail] | Unset = UNSET
        if _campaigns is not UNSET:
            campaigns = []
            for campaigns_item_data in _campaigns:
                campaigns_item = CampaignDetail.from_dict(campaigns_item_data)

                campaigns.append(campaigns_item)

        _cisa_campaigns = d.pop("cisa_campaigns", UNSET)
        cisa_campaigns: list[CISACampaignAdvisory] | Unset = UNSET
        if _cisa_campaigns is not UNSET:
            cisa_campaigns = []
            for cisa_campaigns_item_data in _cisa_campaigns:
                cisa_campaigns_item = CISACampaignAdvisory.from_dict(cisa_campaigns_item_data)

                cisa_campaigns.append(cisa_campaigns_item)

        _cves = d.pop("cves", UNSET)
        cves: list[CVEMiniDetail] | Unset = UNSET
        if _cves is not UNSET:
            cves = []
            for cves_item_data in _cves:
                cves_item = CVEMiniDetail.from_dict(cves_item_data)

                cves.append(cves_item)

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

        _errors = d.pop("errors", UNSET)
        errors: list[ErrorDetail] | Unset = UNSET
        if _errors is not UNSET:
            errors = []
            for errors_item_data in _errors:
                errors_item = ErrorDetail.from_dict(errors_item_data)

                errors.append(errors_item)

        _fight_techniques = d.pop("fight_techniques", UNSET)
        fight_techniques: list[FightTechnique] | Unset = UNSET
        if _fight_techniques is not UNSET:
            fight_techniques = []
            for fight_techniques_item_data in _fight_techniques:
                fight_techniques_item = FightTechnique.from_dict(fight_techniques_item_data)

                fight_techniques.append(fight_techniques_item)

        _framework_mappings = d.pop("framework_mappings", UNSET)
        framework_mappings: list[FrameworkMapping] | Unset = UNSET
        if _framework_mappings is not UNSET:
            framework_mappings = []
            for framework_mappings_item_data in _framework_mappings:
                framework_mappings_item = FrameworkMapping.from_dict(framework_mappings_item_data)

                framework_mappings.append(framework_mappings_item)

        _groups = d.pop("groups", UNSET)
        groups: list[GroupDetail] | Unset = UNSET
        if _groups is not UNSET:
            groups = []
            for groups_item_data in _groups:
                groups_item = GroupDetail.from_dict(groups_item_data)

                groups.append(groups_item)

        _gtfobins_binaries = d.pop("gtfobins_binaries", UNSET)
        gtfobins_binaries: list[GTFOBinsBinary] | Unset = UNSET
        if _gtfobins_binaries is not UNSET:
            gtfobins_binaries = []
            for gtfobins_binaries_item_data in _gtfobins_binaries:
                gtfobins_binaries_item = GTFOBinsBinary.from_dict(gtfobins_binaries_item_data)

                gtfobins_binaries.append(gtfobins_binaries_item)

        gtfobins_binaries_total = d.pop("gtfobins_binaries_total", UNSET)

        _hijacklibs_entries = d.pop("hijacklibs_entries", UNSET)
        hijacklibs_entries: list[HijackLibsEntry] | Unset = UNSET
        if _hijacklibs_entries is not UNSET:
            hijacklibs_entries = []
            for hijacklibs_entries_item_data in _hijacklibs_entries:
                hijacklibs_entries_item = HijackLibsEntry.from_dict(hijacklibs_entries_item_data)

                hijacklibs_entries.append(hijacklibs_entries_item)

        hijacklibs_entries_total = d.pop("hijacklibs_entries_total", UNSET)

        def _parse_identifier_resolved(data: object) -> bool | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(bool | None | Unset, data)

        identifier_resolved = _parse_identifier_resolved(d.pop("identifier_resolved", UNSET))

        _knowledgebase = d.pop("knowledgebase", UNSET)
        knowledgebase: list[KnowledgebaseResult] | Unset = UNSET
        if _knowledgebase is not UNSET:
            knowledgebase = []
            for knowledgebase_item_data in _knowledgebase:
                knowledgebase_item = KnowledgebaseResult.from_dict(knowledgebase_item_data)

                knowledgebase.append(knowledgebase_item)

        _lol_drivers = d.pop("lol_drivers", UNSET)
        lol_drivers: list[LOLDriver] | Unset = UNSET
        if _lol_drivers is not UNSET:
            lol_drivers = []
            for lol_drivers_item_data in _lol_drivers:
                lol_drivers_item = LOLDriver.from_dict(lol_drivers_item_data)

                lol_drivers.append(lol_drivers_item)

        lol_drivers_total = d.pop("lol_drivers_total", UNSET)

        _lolbas_binaries = d.pop("lolbas_binaries", UNSET)
        lolbas_binaries: list[LOLBASBinary] | Unset = UNSET
        if _lolbas_binaries is not UNSET:
            lolbas_binaries = []
            for lolbas_binaries_item_data in _lolbas_binaries:
                lolbas_binaries_item = LOLBASBinary.from_dict(lolbas_binaries_item_data)

                lolbas_binaries.append(lolbas_binaries_item)

        _misp = d.pop("misp", UNSET)
        misp: list[MISPEvent] | Unset = UNSET
        if _misp is not UNSET:
            misp = []
            for misp_item_data in _misp:
                misp_item = MISPEvent.from_dict(misp_item_data)

                misp.append(misp_item)

        _mitigations = d.pop("mitigations", UNSET)
        mitigations: list[MitigationDetail] | Unset = UNSET
        if _mitigations is not UNSET:
            mitigations = []
            for mitigations_item_data in _mitigations:
                mitigations_item = MitigationDetail.from_dict(mitigations_item_data)

                mitigations.append(mitigations_item)

        def _parse_navigator(data: object) -> EnrichTechniqueResponseNavigatorType0 | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, dict):
                    raise TypeError()
                navigator_type_0 = EnrichTechniqueResponseNavigatorType0.from_dict(data)

                return navigator_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(EnrichTechniqueResponseNavigatorType0 | None | Unset, data)

        navigator = _parse_navigator(d.pop("navigator", UNSET))

        _nist_controls = d.pop("nist_controls", UNSET)
        nist_controls: list[NistControlMapping] | Unset = UNSET
        if _nist_controls is not UNSET:
            nist_controls = []
            for nist_controls_item_data in _nist_controls:
                nist_controls_item = NistControlMapping.from_dict(nist_controls_item_data)

                nist_controls.append(nist_controls_item)

        _predictions = d.pop("predictions", UNSET)
        predictions: list[ThreatPrediction] | Unset = UNSET
        if _predictions is not UNSET:
            predictions = []
            for predictions_item_data in _predictions:
                predictions_item = ThreatPrediction.from_dict(predictions_item_data)

                predictions.append(predictions_item)

        _sigma_rules = d.pop("sigma_rules", UNSET)
        sigma_rules: list[SigmaRule] | Unset = UNSET
        if _sigma_rules is not UNSET:
            sigma_rules = []
            for sigma_rules_item_data in _sigma_rules:
                sigma_rules_item = SigmaRule.from_dict(sigma_rules_item_data)

                sigma_rules.append(sigma_rules_item)

        _software = d.pop("software", UNSET)
        software: list[SoftwareDetail] | Unset = UNSET
        if _software is not UNSET:
            software = []
            for software_item_data in _software:
                software_item = SoftwareDetail.from_dict(software_item_data)

                software.append(software_item)

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

        def _parse_threat_level(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        threat_level = _parse_threat_level(d.pop("threat_level", UNSET))

        enrich_technique_response = cls(
            asset=asset,
            asset_classes=asset_classes,
            atomic_tests=atomic_tests,
            atomic_tests_total=atomic_tests_total,
            campaigns=campaigns,
            cisa_campaigns=cisa_campaigns,
            cves=cves,
            defend=defend,
            detections=detections,
            errors=errors,
            fight_techniques=fight_techniques,
            framework_mappings=framework_mappings,
            groups=groups,
            gtfobins_binaries=gtfobins_binaries,
            gtfobins_binaries_total=gtfobins_binaries_total,
            hijacklibs_entries=hijacklibs_entries,
            hijacklibs_entries_total=hijacklibs_entries_total,
            identifier_resolved=identifier_resolved,
            knowledgebase=knowledgebase,
            lol_drivers=lol_drivers,
            lol_drivers_total=lol_drivers_total,
            lolbas_binaries=lolbas_binaries,
            misp=misp,
            mitigations=mitigations,
            navigator=navigator,
            nist_controls=nist_controls,
            predictions=predictions,
            sigma_rules=sigma_rules,
            software=software,
            summary=summary,
            techniques=techniques,
            threat_level=threat_level,
        )

        enrich_technique_response.additional_properties = d
        return enrich_technique_response

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

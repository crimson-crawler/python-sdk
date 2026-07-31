"""Contains all the data models used in inputs/outputs"""

from .activity_summary import ActivitySummary
from .admiralty_grade import AdmiraltyGrade
from .admiralty_grade_credibility import AdmiraltyGradeCredibility
from .admiralty_grade_reliability import AdmiraltyGradeReliability
from .affected_product import AffectedProduct
from .artifact_enrichment_doc_request import ArtifactEnrichmentDocRequest
from .artifact_enrichment_doc_request_formats_item import ArtifactEnrichmentDocRequestFormatsItem
from .artifact_enrichment_file_input import ArtifactEnrichmentFileInput
from .artifact_enrichment_job_response import ArtifactEnrichmentJobResponse
from .artifact_enrichment_job_response_status import ArtifactEnrichmentJobResponseStatus
from .artifact_enrichment_meta import ArtifactEnrichmentMeta
from .artifact_enrichment_meta_extractor_versions import ArtifactEnrichmentMetaExtractorVersions
from .artifact_enrichment_meta_overall_confidence_type_0 import ArtifactEnrichmentMetaOverallConfidenceType0
from .artifact_enrichment_meta_ref_count_by_type import ArtifactEnrichmentMetaRefCountByType
from .artifact_enrichment_reference import ArtifactEnrichmentReference
from .artifact_enrichment_reference_action_type_0 import ArtifactEnrichmentReferenceActionType0
from .artifact_enrichment_reference_confidence_type_0 import ArtifactEnrichmentReferenceConfidenceType0
from .artifact_enrichment_reference_enrichment_type_0 import ArtifactEnrichmentReferenceEnrichmentType0
from .artifact_enrichment_reference_exploit_maturity_type_0 import ArtifactEnrichmentReferenceExploitMaturityType0
from .artifact_enrichment_reference_likelihood_type_0 import ArtifactEnrichmentReferenceLikelihoodType0
from .artifact_enrichment_reference_score_breakdown import ArtifactEnrichmentReferenceScoreBreakdown
from .artifact_enrichment_reference_techniques_provenance_type_0 import (
    ArtifactEnrichmentReferenceTechniquesProvenanceType0,
)
from .artifact_enrichment_reference_type import ArtifactEnrichmentReferenceType
from .artifact_enrichment_report import ArtifactEnrichmentReport
from .artifact_enrichment_report_exports import ArtifactEnrichmentReportExports
from .artifact_enrichment_report_rollups_type_0 import ArtifactEnrichmentReportRollupsType0
from .artifact_enrichment_stakeholder import ArtifactEnrichmentStakeholder
from .artifact_enrichment_stakeholder_exposure import ArtifactEnrichmentStakeholderExposure
from .artifact_enrichment_stakeholder_human_impact import ArtifactEnrichmentStakeholderHumanImpact
from .artifact_enrichment_stakeholder_method import ArtifactEnrichmentStakeholderMethod
from .artifact_enrichment_stakeholder_mission_prevalence import ArtifactEnrichmentStakeholderMissionPrevalence
from .artifact_enrichment_stakeholder_public_wellbeing_impact import ArtifactEnrichmentStakeholderPublicWellbeingImpact
from .assess_group_exposure_request import AssessGroupExposureRequest
from .assess_group_exposure_request_framework import AssessGroupExposureRequestFramework
from .assess_group_exposure_response import AssessGroupExposureResponse
from .assess_group_exposure_response_navigator_type_0 import AssessGroupExposureResponseNavigatorType0
from .assess_ioc_portfolio_request import AssessIOCPortfolioRequest
from .assess_ioc_portfolio_request_indicators_item import AssessIOCPortfolioRequestIndicatorsItem
from .assess_ioc_portfolio_response import AssessIOCPortfolioResponse
from .assess_ioc_portfolio_response_warninglist_hits_item import AssessIOCPortfolioResponseWarninglistHitsItem
from .assess_technique_coverage_request import AssessTechniqueCoverageRequest
from .assess_technique_coverage_request_framework import AssessTechniqueCoverageRequestFramework
from .assess_technique_coverage_response import AssessTechniqueCoverageResponse
from .assess_technique_coverage_response_navigator_type_0 import AssessTechniqueCoverageResponseNavigatorType0
from .assess_vulnerability_exposure_request import AssessVulnerabilityExposureRequest
from .assess_vulnerability_exposure_response import AssessVulnerabilityExposureResponse
from .assess_vulnerability_exposure_response_navigator_type_0 import AssessVulnerabilityExposureResponseNavigatorType0
from .assess_vulnerability_exposure_response_ssvc_decisions_item import (
    AssessVulnerabilityExposureResponseSsvcDecisionsItem,
)
from .assess_vulnerability_exposure_response_weaponization_scores_item import (
    AssessVulnerabilityExposureResponseWeaponizationScoresItem,
)
from .attack_path import AttackPath
from .attack_path_step import AttackPathStep
from .batch_atlas_item import BatchATLASItem
from .batch_campaign_item import BatchCampaignItem
from .batch_campaign_item_framework import BatchCampaignItemFramework
from .batch_capec_item import BatchCAPECItem
from .batch_cve_item import BatchCVEItem
from .batch_cve_item_techniques_scope import BatchCVEItemTechniquesScope
from .batch_cwe_item import BatchCWEItem
from .batch_d3fend_item import BatchD3FENDItem
from .batch_disarm_item import BatchDISARMItem
from .batch_group_item import BatchGroupItem
from .batch_group_item_framework import BatchGroupItemFramework
from .batch_ioc_item import BatchIOCItem
from .batch_item_result import BatchItemResult
from .batch_item_result_data_type_0 import BatchItemResultDataType0
from .batch_item_result_status import BatchItemResultStatus
from .batch_location_item import BatchLocationItem
from .batch_package_item import BatchPackageItem
from .batch_po_c_source_item import BatchPoCSourceItem
from .batch_product_item import BatchProductItem
from .batch_sector_item import BatchSectorItem
from .batch_software_item import BatchSoftwareItem
from .batch_software_item_framework import BatchSoftwareItemFramework
from .batch_technique_item import BatchTechniqueItem
from .batch_technique_item_framework import BatchTechniqueItemFramework
from .campaign_detail import CampaignDetail
from .capec_detail import CAPECDetail
from .chained_cve_pair import ChainedCVEPair
from .citation import Citation
from .confidence import Confidence
from .countermeasure_detail import CountermeasureDetail
from .coverage_gap import CoverageGap
from .coverage_gap_kind import CoverageGapKind
from .coverage_score import CoverageScore
from .cpe_product import CPEProduct
from .cve_detail import CVEDetail
from .cve_mini_detail import CVEMiniDetail
from .cve_reference import CVEReference
from .cwe_detail import CWEDetail
from .cwe_detail_related_weaknesses_item import CWEDetailRelatedWeaknessesItem
from .d3fend_detail import D3FENDDetail
from .defense_coverage import DefenseCoverage
from .defense_triad import DefenseTriad
from .defense_triad_origin import DefenseTriadOrigin
from .detection_detail import DetectionDetail
from .detection_opportunity import DetectionOpportunity
from .enrich_atlas_request import EnrichATLASRequest
from .enrich_atlas_response import EnrichATLASResponse
from .enrich_atlas_response_navigator_type_0 import EnrichATLASResponseNavigatorType0
from .enrich_batch_request import EnrichBatchRequest
from .enrich_batch_response import EnrichBatchResponse
from .enrich_campaign_request import EnrichCampaignRequest
from .enrich_campaign_request_framework import EnrichCampaignRequestFramework
from .enrich_campaign_response import EnrichCampaignResponse
from .enrich_campaign_response_navigator_type_0 import EnrichCampaignResponseNavigatorType0
from .enrich_capec_request import EnrichCAPECRequest
from .enrich_capec_response import EnrichCAPECResponse
from .enrich_capec_response_navigator_type_0 import EnrichCAPECResponseNavigatorType0
from .enrich_cve_request import EnrichCVERequest
from .enrich_cve_request_techniques_scope import EnrichCVERequestTechniquesScope
from .enrich_cve_response import EnrichCVEResponse
from .enrich_cve_response_navigator_type_0 import EnrichCVEResponseNavigatorType0
from .enrich_cve_response_techniques_provenance_type_0 import EnrichCVEResponseTechniquesProvenanceType0
from .enrich_cwe_request import EnrichCWERequest
from .enrich_cwe_response import EnrichCWEResponse
from .enrich_cwe_response_navigator_type_0 import EnrichCWEResponseNavigatorType0
from .enrich_d3fend_request import EnrichD3FENDRequest
from .enrich_d3fend_response import EnrichD3FENDResponse
from .enrich_disarm_request import EnrichDISARMRequest
from .enrich_disarm_response import EnrichDISARMResponse
from .enrich_disarm_response_navigator_type_0 import EnrichDISARMResponseNavigatorType0
from .enrich_group_request import EnrichGroupRequest
from .enrich_group_request_framework import EnrichGroupRequestFramework
from .enrich_group_response import EnrichGroupResponse
from .enrich_group_response_navigator_type_0 import EnrichGroupResponseNavigatorType0
from .enrich_ioc_request import EnrichIOCRequest
from .enrich_ioc_response import EnrichIOCResponse
from .enrich_ioc_response_navigator_type_0 import EnrichIOCResponseNavigatorType0
from .enrich_location_request import EnrichLocationRequest
from .enrich_location_response import EnrichLocationResponse
from .enrich_location_response_navigator_type_0 import EnrichLocationResponseNavigatorType0
from .enrich_package_request import EnrichPackageRequest
from .enrich_package_response import EnrichPackageResponse
from .enrich_product_request import EnrichProductRequest
from .enrich_product_response import EnrichProductResponse
from .enrich_product_response_cve_fix_versions import EnrichProductResponseCveFixVersions
from .enrich_sector_request import EnrichSectorRequest
from .enrich_sector_response import EnrichSectorResponse
from .enrich_sector_response_navigator_type_0 import EnrichSectorResponseNavigatorType0
from .enrich_software_request import EnrichSoftwareRequest
from .enrich_software_request_framework import EnrichSoftwareRequestFramework
from .enrich_software_response import EnrichSoftwareResponse
from .enrich_software_response_navigator_type_0 import EnrichSoftwareResponseNavigatorType0
from .enrich_technique_request import EnrichTechniqueRequest
from .enrich_technique_request_framework import EnrichTechniqueRequestFramework
from .enrich_technique_response import EnrichTechniqueResponse
from .enrich_technique_response_navigator_type_0 import EnrichTechniqueResponseNavigatorType0
from .enrichment_job_event import EnrichmentJobEvent
from .enrichment_job_event_level import EnrichmentJobEventLevel
from .enrichment_job_event_meta_type_0 import EnrichmentJobEventMetaType0
from .enrichment_job_stage import EnrichmentJobStage
from .enrichment_job_stage_status import EnrichmentJobStageStatus
from .enrichment_job_substage import EnrichmentJobSubstage
from .enrichment_job_substage_status import EnrichmentJobSubstageStatus
from .enrichment_submit_response import EnrichmentSubmitResponse
from .epss_score import EPSSScore
from .epss_velocity import EPSSVelocity
from .error_detail import ErrorDetail
from .exploit_chain_phase import ExploitChainPhase
from .exploit_detail import ExploitDetail
from .exploitation_frequency import ExploitationFrequency
from .exploitation_frequency_severity_distribution import ExploitationFrequencySeverityDistribution
from .fetch_po_c_source_request import FetchPoCSourceRequest
from .fetch_po_c_source_response import FetchPoCSourceResponse
from .galaxy_cluster_detail import GalaxyClusterDetail
from .galaxy_cluster_detail_meta import GalaxyClusterDetailMeta
from .galaxy_cluster_relation import GalaxyClusterRelation
from .galaxy_data import GalaxyData
from .group_detail import GroupDetail
from .inferred_chain_candidate import InferredChainCandidate
from .inventory_advisory import InventoryAdvisory
from .inventory_asset import InventoryAsset
from .inventory_asset_finding import InventoryAssetFinding
from .inventory_cve import InventoryCVE
from .inventory_enrichment_job_response import InventoryEnrichmentJobResponse
from .inventory_enrichment_job_response_status import InventoryEnrichmentJobResponseStatus
from .inventory_enrichment_request import InventoryEnrichmentRequest
from .inventory_enrichment_result import InventoryEnrichmentResult
from .inventory_enrichment_result_attachment_enrichment_type_0 import InventoryEnrichmentResultAttachmentEnrichmentType0
from .inventory_mitigation import InventoryMitigation
from .inventory_rollup import InventoryRollup
from .inventory_rollup_criticality_counts import InventoryRollupCriticalityCounts
from .inventory_technique import InventoryTechnique
from .kev_entry import KEVEntry
from .key_judgment import KeyJudgment
from .key_judgment_confidence_type_0 import KeyJudgmentConfidenceType0
from .key_judgment_likelihood_type_0 import KeyJudgmentLikelihoodType0
from .knowledgebase_result import KnowledgebaseResult
from .knowledgebase_result_metadata_type_0 import KnowledgebaseResultMetadataType0
from .location_detail import LocationDetail
from .location_detail_groups_item_type_2 import LocationDetailGroupsItemType2
from .misp_attribute import MISPAttribute
from .misp_event import MISPEvent
from .misp_event_galaxies_item import MISPEventGalaxiesItem
from .misp_feed_hit import MISPFeedHit
from .misp_related_attribute import MISPRelatedAttribute
from .misp_sighting import MISPSighting
from .misp_warninglist_hit import MISPWarninglistHit
from .mitigation_detail import MitigationDetail
from .nist_control_mapping import NistControlMapping
from .osv_advisory import OSVAdvisory
from .osv_affected_range import OSVAffectedRange
from .overlap_analysis import OverlapAnalysis
from .overlap_analysis_tactic_coverage_per_group import OverlapAnalysisTacticCoveragePerGroup
from .overlap_analysis_unique_per_group import OverlapAnalysisUniquePerGroup
from .po_c_entry import PoCEntry
from .po_c_source_entry import PoCSourceEntry
from .po_c_source_summary import PoCSourceSummary
from .prioritized_action import PrioritizedAction
from .prioritized_action_effort_type_0 import PrioritizedActionEffortType0
from .priority_gap import PriorityGap
from .remediation_entry import RemediationEntry
from .risk_profile import RiskProfile
from .risk_summary import RiskSummary
from .risk_summary_top_cwes_item import RiskSummaryTopCwesItem
from .risk_summary_top_techniques_item import RiskSummaryTopTechniquesItem
from .search_cti_request import SearchCTIRequest
from .search_cti_request_types_type_0_item import SearchCTIRequestTypesType0Item
from .search_cti_response import SearchCTIResponse
from .search_cti_response_results_item import SearchCTIResponseResultsItem
from .search_cve_request import SearchCVERequest
from .search_cve_request_sort_type_0 import SearchCVERequestSortType0
from .search_cve_request_vuln_status_type_0 import SearchCVERequestVulnStatusType0
from .search_cve_response import SearchCVEResponse
from .search_d3fend_request import SearchD3FENDRequest
from .search_d3fend_request_d3_fend_form_type_0 import SearchD3FENDRequestD3FendFormType0
from .search_d3fend_response import SearchD3FENDResponse
from .search_kev_request import SearchKEVRequest
from .search_kev_request_ransomware_status_type_0 import SearchKEVRequestRansomwareStatusType0
from .search_kev_response import SearchKEVResponse
from .search_knowledgebase_request import SearchKnowledgebaseRequest
from .search_knowledgebase_request_collections_item import SearchKnowledgebaseRequestCollectionsItem
from .search_knowledgebase_response import SearchKnowledgebaseResponse
from .search_misp_request import SearchMISPRequest
from .search_misp_response import SearchMISPResponse
from .search_po_c_request import SearchPoCRequest
from .search_po_c_response import SearchPoCResponse
from .search_vendor_request import SearchVendorRequest
from .search_vendor_response import SearchVendorResponse
from .sector_context import SectorContext
from .sector_detail import SectorDetail
from .sector_detail_groups_item_type_2 import SectorDetailGroupsItemType2
from .software_detail import SoftwareDetail
from .source_confidence_statement import SourceConfidenceStatement
from .source_confidence_statement_grade_distribution import SourceConfidenceStatementGradeDistribution
from .source_confidence_statement_overall_confidence import SourceConfidenceStatementOverallConfidence
from .source_contribution import SourceContribution
from .source_corroboration import SourceCorroboration
from .source_corroboration_grade_distribution import SourceCorroborationGradeDistribution
from .source_corroboration_overall_confidence import SourceCorroborationOverallConfidence
from .ssvc_decision import SSVCDecision
from .ssvc_decision_automatable import SSVCDecisionAutomatable
from .ssvc_decision_decision import SSVCDecisionDecision
from .ssvc_decision_exploitation import SSVCDecisionExploitation
from .ssvc_decision_exposure_type_0 import SSVCDecisionExposureType0
from .ssvc_decision_human_impact_type_0 import SSVCDecisionHumanImpactType0
from .ssvc_decision_method import SSVCDecisionMethod
from .ssvc_decision_mission_prevalence_type_0 import SSVCDecisionMissionPrevalenceType0
from .ssvc_decision_public_wellbeing_impact_type_0 import SSVCDecisionPublicWellbeingImpactType0
from .ssvc_decision_technical_impact import SSVCDecisionTechnicalImpact
from .ssvc_decision_tree_source import SSVCDecisionTreeSource
from .technique_detail import TechniqueDetail
from .technique_detail_kill_chain_phases_item import TechniqueDetailKillChainPhasesItem
from .threat_assessment import ThreatAssessment
from .threat_prediction import ThreatPrediction
from .timeline_entry import TimelineEntry
from .timeline_event import TimelineEvent
from .timeline_event_kind import TimelineEventKind
from .warninglist_result import WarninglistResult
from .web_result import WebResult

__all__ = (
    "ActivitySummary",
    "AdmiraltyGrade",
    "AdmiraltyGradeCredibility",
    "AdmiraltyGradeReliability",
    "AffectedProduct",
    "ArtifactEnrichmentDocRequest",
    "ArtifactEnrichmentDocRequestFormatsItem",
    "ArtifactEnrichmentFileInput",
    "ArtifactEnrichmentJobResponse",
    "ArtifactEnrichmentJobResponseStatus",
    "ArtifactEnrichmentMeta",
    "ArtifactEnrichmentMetaExtractorVersions",
    "ArtifactEnrichmentMetaOverallConfidenceType0",
    "ArtifactEnrichmentMetaRefCountByType",
    "ArtifactEnrichmentReference",
    "ArtifactEnrichmentReferenceActionType0",
    "ArtifactEnrichmentReferenceConfidenceType0",
    "ArtifactEnrichmentReferenceEnrichmentType0",
    "ArtifactEnrichmentReferenceExploitMaturityType0",
    "ArtifactEnrichmentReferenceLikelihoodType0",
    "ArtifactEnrichmentReferenceScoreBreakdown",
    "ArtifactEnrichmentReferenceTechniquesProvenanceType0",
    "ArtifactEnrichmentReferenceType",
    "ArtifactEnrichmentReport",
    "ArtifactEnrichmentReportExports",
    "ArtifactEnrichmentReportRollupsType0",
    "ArtifactEnrichmentStakeholder",
    "ArtifactEnrichmentStakeholderExposure",
    "ArtifactEnrichmentStakeholderHumanImpact",
    "ArtifactEnrichmentStakeholderMethod",
    "ArtifactEnrichmentStakeholderMissionPrevalence",
    "ArtifactEnrichmentStakeholderPublicWellbeingImpact",
    "AssessGroupExposureRequest",
    "AssessGroupExposureRequestFramework",
    "AssessGroupExposureResponse",
    "AssessGroupExposureResponseNavigatorType0",
    "AssessIOCPortfolioRequest",
    "AssessIOCPortfolioRequestIndicatorsItem",
    "AssessIOCPortfolioResponse",
    "AssessIOCPortfolioResponseWarninglistHitsItem",
    "AssessTechniqueCoverageRequest",
    "AssessTechniqueCoverageRequestFramework",
    "AssessTechniqueCoverageResponse",
    "AssessTechniqueCoverageResponseNavigatorType0",
    "AssessVulnerabilityExposureRequest",
    "AssessVulnerabilityExposureResponse",
    "AssessVulnerabilityExposureResponseNavigatorType0",
    "AssessVulnerabilityExposureResponseSsvcDecisionsItem",
    "AssessVulnerabilityExposureResponseWeaponizationScoresItem",
    "AttackPath",
    "AttackPathStep",
    "BatchATLASItem",
    "BatchCampaignItem",
    "BatchCampaignItemFramework",
    "BatchCAPECItem",
    "BatchCVEItem",
    "BatchCVEItemTechniquesScope",
    "BatchCWEItem",
    "BatchD3FENDItem",
    "BatchDISARMItem",
    "BatchGroupItem",
    "BatchGroupItemFramework",
    "BatchIOCItem",
    "BatchItemResult",
    "BatchItemResultDataType0",
    "BatchItemResultStatus",
    "BatchLocationItem",
    "BatchPackageItem",
    "BatchPoCSourceItem",
    "BatchProductItem",
    "BatchSectorItem",
    "BatchSoftwareItem",
    "BatchSoftwareItemFramework",
    "BatchTechniqueItem",
    "BatchTechniqueItemFramework",
    "CampaignDetail",
    "CAPECDetail",
    "ChainedCVEPair",
    "Citation",
    "Confidence",
    "CountermeasureDetail",
    "CoverageGap",
    "CoverageGapKind",
    "CoverageScore",
    "CPEProduct",
    "CVEDetail",
    "CVEMiniDetail",
    "CVEReference",
    "CWEDetail",
    "CWEDetailRelatedWeaknessesItem",
    "D3FENDDetail",
    "DefenseCoverage",
    "DefenseTriad",
    "DefenseTriadOrigin",
    "DetectionDetail",
    "DetectionOpportunity",
    "EnrichATLASRequest",
    "EnrichATLASResponse",
    "EnrichATLASResponseNavigatorType0",
    "EnrichBatchRequest",
    "EnrichBatchResponse",
    "EnrichCampaignRequest",
    "EnrichCampaignRequestFramework",
    "EnrichCampaignResponse",
    "EnrichCampaignResponseNavigatorType0",
    "EnrichCAPECRequest",
    "EnrichCAPECResponse",
    "EnrichCAPECResponseNavigatorType0",
    "EnrichCVERequest",
    "EnrichCVERequestTechniquesScope",
    "EnrichCVEResponse",
    "EnrichCVEResponseNavigatorType0",
    "EnrichCVEResponseTechniquesProvenanceType0",
    "EnrichCWERequest",
    "EnrichCWEResponse",
    "EnrichCWEResponseNavigatorType0",
    "EnrichD3FENDRequest",
    "EnrichD3FENDResponse",
    "EnrichDISARMRequest",
    "EnrichDISARMResponse",
    "EnrichDISARMResponseNavigatorType0",
    "EnrichGroupRequest",
    "EnrichGroupRequestFramework",
    "EnrichGroupResponse",
    "EnrichGroupResponseNavigatorType0",
    "EnrichIOCRequest",
    "EnrichIOCResponse",
    "EnrichIOCResponseNavigatorType0",
    "EnrichLocationRequest",
    "EnrichLocationResponse",
    "EnrichLocationResponseNavigatorType0",
    "EnrichmentJobEvent",
    "EnrichmentJobEventLevel",
    "EnrichmentJobEventMetaType0",
    "EnrichmentJobStage",
    "EnrichmentJobStageStatus",
    "EnrichmentJobSubstage",
    "EnrichmentJobSubstageStatus",
    "EnrichmentSubmitResponse",
    "EnrichPackageRequest",
    "EnrichPackageResponse",
    "EnrichProductRequest",
    "EnrichProductResponse",
    "EnrichProductResponseCveFixVersions",
    "EnrichSectorRequest",
    "EnrichSectorResponse",
    "EnrichSectorResponseNavigatorType0",
    "EnrichSoftwareRequest",
    "EnrichSoftwareRequestFramework",
    "EnrichSoftwareResponse",
    "EnrichSoftwareResponseNavigatorType0",
    "EnrichTechniqueRequest",
    "EnrichTechniqueRequestFramework",
    "EnrichTechniqueResponse",
    "EnrichTechniqueResponseNavigatorType0",
    "EPSSScore",
    "EPSSVelocity",
    "ErrorDetail",
    "ExploitationFrequency",
    "ExploitationFrequencySeverityDistribution",
    "ExploitChainPhase",
    "ExploitDetail",
    "FetchPoCSourceRequest",
    "FetchPoCSourceResponse",
    "GalaxyClusterDetail",
    "GalaxyClusterDetailMeta",
    "GalaxyClusterRelation",
    "GalaxyData",
    "GroupDetail",
    "InferredChainCandidate",
    "InventoryAdvisory",
    "InventoryAsset",
    "InventoryAssetFinding",
    "InventoryCVE",
    "InventoryEnrichmentJobResponse",
    "InventoryEnrichmentJobResponseStatus",
    "InventoryEnrichmentRequest",
    "InventoryEnrichmentResult",
    "InventoryEnrichmentResultAttachmentEnrichmentType0",
    "InventoryMitigation",
    "InventoryRollup",
    "InventoryRollupCriticalityCounts",
    "InventoryTechnique",
    "KEVEntry",
    "KeyJudgment",
    "KeyJudgmentConfidenceType0",
    "KeyJudgmentLikelihoodType0",
    "KnowledgebaseResult",
    "KnowledgebaseResultMetadataType0",
    "LocationDetail",
    "LocationDetailGroupsItemType2",
    "MISPAttribute",
    "MISPEvent",
    "MISPEventGalaxiesItem",
    "MISPFeedHit",
    "MISPRelatedAttribute",
    "MISPSighting",
    "MISPWarninglistHit",
    "MitigationDetail",
    "NistControlMapping",
    "OSVAdvisory",
    "OSVAffectedRange",
    "OverlapAnalysis",
    "OverlapAnalysisTacticCoveragePerGroup",
    "OverlapAnalysisUniquePerGroup",
    "PoCEntry",
    "PoCSourceEntry",
    "PoCSourceSummary",
    "PrioritizedAction",
    "PrioritizedActionEffortType0",
    "PriorityGap",
    "RemediationEntry",
    "RiskProfile",
    "RiskSummary",
    "RiskSummaryTopCwesItem",
    "RiskSummaryTopTechniquesItem",
    "SearchCTIRequest",
    "SearchCTIRequestTypesType0Item",
    "SearchCTIResponse",
    "SearchCTIResponseResultsItem",
    "SearchCVERequest",
    "SearchCVERequestSortType0",
    "SearchCVERequestVulnStatusType0",
    "SearchCVEResponse",
    "SearchD3FENDRequest",
    "SearchD3FENDRequestD3FendFormType0",
    "SearchD3FENDResponse",
    "SearchKEVRequest",
    "SearchKEVRequestRansomwareStatusType0",
    "SearchKEVResponse",
    "SearchKnowledgebaseRequest",
    "SearchKnowledgebaseRequestCollectionsItem",
    "SearchKnowledgebaseResponse",
    "SearchMISPRequest",
    "SearchMISPResponse",
    "SearchPoCRequest",
    "SearchPoCResponse",
    "SearchVendorRequest",
    "SearchVendorResponse",
    "SectorContext",
    "SectorDetail",
    "SectorDetailGroupsItemType2",
    "SoftwareDetail",
    "SourceConfidenceStatement",
    "SourceConfidenceStatementGradeDistribution",
    "SourceConfidenceStatementOverallConfidence",
    "SourceContribution",
    "SourceCorroboration",
    "SourceCorroborationGradeDistribution",
    "SourceCorroborationOverallConfidence",
    "SSVCDecision",
    "SSVCDecisionAutomatable",
    "SSVCDecisionDecision",
    "SSVCDecisionExploitation",
    "SSVCDecisionExposureType0",
    "SSVCDecisionHumanImpactType0",
    "SSVCDecisionMethod",
    "SSVCDecisionMissionPrevalenceType0",
    "SSVCDecisionPublicWellbeingImpactType0",
    "SSVCDecisionTechnicalImpact",
    "SSVCDecisionTreeSource",
    "TechniqueDetail",
    "TechniqueDetailKillChainPhasesItem",
    "ThreatAssessment",
    "ThreatPrediction",
    "TimelineEntry",
    "TimelineEvent",
    "TimelineEventKind",
    "WarninglistResult",
    "WebResult",
)

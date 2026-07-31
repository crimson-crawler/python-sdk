from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, BinaryIO, Generator, TextIO, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..models.ssvc_decision_automatable import SSVCDecisionAutomatable
from ..models.ssvc_decision_decision import SSVCDecisionDecision
from ..models.ssvc_decision_exploitation import SSVCDecisionExploitation
from ..models.ssvc_decision_exposure_type_0 import SSVCDecisionExposureType0
from ..models.ssvc_decision_human_impact_type_0 import SSVCDecisionHumanImpactType0
from ..models.ssvc_decision_method import SSVCDecisionMethod
from ..models.ssvc_decision_mission_prevalence_type_0 import SSVCDecisionMissionPrevalenceType0
from ..models.ssvc_decision_public_wellbeing_impact_type_0 import SSVCDecisionPublicWellbeingImpactType0
from ..models.ssvc_decision_technical_impact import SSVCDecisionTechnicalImpact
from ..models.ssvc_decision_tree_source import SSVCDecisionTreeSource
from ..types import UNSET, Unset

T = TypeVar("T", bound="SSVCDecision")


@_attrs_define
class SSVCDecision:
    """Deterministic SSVC decision from the CERT/CC Deployer tree or CISA Coordinator tree.

    `method` identifies the applied tree. The remaining fields expose its evidence-derived and
    stakeholder-supplied inputs, final decision, recommended action, and assumptions.

        Attributes:
            automatable (SSVCDecisionAutomatable): Whether attack steps can be automated (CVSS-derived)
            decision (SSVCDecisionDecision): SSVC outcome. Deployer: defer<scheduled<out_of_cycle<immediate. CISA
                Coordinator: track<track_star<attend<act.
            exploitation (SSVCDecisionExploitation): Exploitation state (data-derived)
            technical_impact (SSVCDecisionTechnicalImpact): Technical impact (CVSS C/I/A-derived)
            assumed_inputs (list[str] | Unset): Stakeholder input fields that were ASSUMED (conservative worst-reasonable
                default), not observed — an enrichment can't know a CVE's deployment exposure or human impact, so it defaults
                them (deployer: exposure=open / human_impact=medium). Lists those field names so the decision isn't read as
                environment-specific. Empty when the caller supplied an explicit stakeholder.
                Exploitation/automatable/technical_impact are always data-derived, never here.
            exposure (None | SSVCDecisionExposureType0 | Unset): Deployer-tree input: system exposure (stakeholder). Null
                when method='cisa_coordinator'.
            human_impact (None | SSVCDecisionHumanImpactType0 | Unset): Deployer-tree input: human impact (stakeholder).
                Null when method='cisa_coordinator'.
            method (SSVCDecisionMethod | Unset): Which SSVC decision tree was applied Default: SSVCDecisionMethod.DEPLOYER.
            mission_prevalence (None | SSVCDecisionMissionPrevalenceType0 | Unset): CISA Coordinator input: mission
                prevalence. Null when method='deployer'.
            public_wellbeing_impact (None | SSVCDecisionPublicWellbeingImpactType0 | Unset): CISA Coordinator input: worst-
                case public well-being impact. Null when method='deployer'.
            role (str | Unset): SSVC stakeholder role (Deployer / Coordinator) Default: 'Deployer'.
            tree_source (SSVCDecisionTreeSource | Unset): Origin of the decision table for audit transparency. 'verbatim' =
                Deployer tree hardcoded from CERT/CC spec; 'csv' = CISA tree loaded from staged canonical CSV; 'fallback' = CISA
                tree using the rule-based fallback (CSV not staged). Default: SSVCDecisionTreeSource.VERBATIM.
            version (str | Unset): SSVC decision-model version (Deployer 2.1 / CISA 2.0.3) Default: '2.1'.
    """

    automatable: SSVCDecisionAutomatable
    decision: SSVCDecisionDecision
    exploitation: SSVCDecisionExploitation
    technical_impact: SSVCDecisionTechnicalImpact
    assumed_inputs: list[str] | Unset = UNSET
    exposure: None | SSVCDecisionExposureType0 | Unset = UNSET
    human_impact: None | SSVCDecisionHumanImpactType0 | Unset = UNSET
    method: SSVCDecisionMethod | Unset = SSVCDecisionMethod.DEPLOYER
    mission_prevalence: None | SSVCDecisionMissionPrevalenceType0 | Unset = UNSET
    public_wellbeing_impact: None | SSVCDecisionPublicWellbeingImpactType0 | Unset = UNSET
    role: str | Unset = "Deployer"
    tree_source: SSVCDecisionTreeSource | Unset = SSVCDecisionTreeSource.VERBATIM
    version: str | Unset = "2.1"
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        automatable = self.automatable.value

        decision = self.decision.value

        exploitation = self.exploitation.value

        technical_impact = self.technical_impact.value

        assumed_inputs: list[str] | Unset = UNSET
        if not isinstance(self.assumed_inputs, Unset):
            assumed_inputs = self.assumed_inputs

        exposure: None | str | Unset
        if isinstance(self.exposure, Unset):
            exposure = UNSET
        elif isinstance(self.exposure, SSVCDecisionExposureType0):
            exposure = self.exposure.value
        else:
            exposure = self.exposure

        human_impact: None | str | Unset
        if isinstance(self.human_impact, Unset):
            human_impact = UNSET
        elif isinstance(self.human_impact, SSVCDecisionHumanImpactType0):
            human_impact = self.human_impact.value
        else:
            human_impact = self.human_impact

        method: str | Unset = UNSET
        if not isinstance(self.method, Unset):
            method = self.method.value

        mission_prevalence: None | str | Unset
        if isinstance(self.mission_prevalence, Unset):
            mission_prevalence = UNSET
        elif isinstance(self.mission_prevalence, SSVCDecisionMissionPrevalenceType0):
            mission_prevalence = self.mission_prevalence.value
        else:
            mission_prevalence = self.mission_prevalence

        public_wellbeing_impact: None | str | Unset
        if isinstance(self.public_wellbeing_impact, Unset):
            public_wellbeing_impact = UNSET
        elif isinstance(self.public_wellbeing_impact, SSVCDecisionPublicWellbeingImpactType0):
            public_wellbeing_impact = self.public_wellbeing_impact.value
        else:
            public_wellbeing_impact = self.public_wellbeing_impact

        role = self.role

        tree_source: str | Unset = UNSET
        if not isinstance(self.tree_source, Unset):
            tree_source = self.tree_source.value

        version = self.version

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "automatable": automatable,
                "decision": decision,
                "exploitation": exploitation,
                "technical_impact": technical_impact,
            }
        )
        if assumed_inputs is not UNSET:
            field_dict["assumed_inputs"] = assumed_inputs
        if exposure is not UNSET:
            field_dict["exposure"] = exposure
        if human_impact is not UNSET:
            field_dict["human_impact"] = human_impact
        if method is not UNSET:
            field_dict["method"] = method
        if mission_prevalence is not UNSET:
            field_dict["mission_prevalence"] = mission_prevalence
        if public_wellbeing_impact is not UNSET:
            field_dict["public_wellbeing_impact"] = public_wellbeing_impact
        if role is not UNSET:
            field_dict["role"] = role
        if tree_source is not UNSET:
            field_dict["tree_source"] = tree_source
        if version is not UNSET:
            field_dict["version"] = version

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        automatable = SSVCDecisionAutomatable(d.pop("automatable"))

        decision = SSVCDecisionDecision(d.pop("decision"))

        exploitation = SSVCDecisionExploitation(d.pop("exploitation"))

        technical_impact = SSVCDecisionTechnicalImpact(d.pop("technical_impact"))

        assumed_inputs = cast(list[str], d.pop("assumed_inputs", UNSET))

        def _parse_exposure(data: object) -> None | SSVCDecisionExposureType0 | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, str):
                    raise TypeError()
                exposure_type_0 = SSVCDecisionExposureType0(data)

                return exposure_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(None | SSVCDecisionExposureType0 | Unset, data)

        exposure = _parse_exposure(d.pop("exposure", UNSET))

        def _parse_human_impact(data: object) -> None | SSVCDecisionHumanImpactType0 | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, str):
                    raise TypeError()
                human_impact_type_0 = SSVCDecisionHumanImpactType0(data)

                return human_impact_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(None | SSVCDecisionHumanImpactType0 | Unset, data)

        human_impact = _parse_human_impact(d.pop("human_impact", UNSET))

        _method = d.pop("method", UNSET)
        method: SSVCDecisionMethod | Unset
        if isinstance(_method, Unset):
            method = UNSET
        else:
            method = SSVCDecisionMethod(_method)

        def _parse_mission_prevalence(data: object) -> None | SSVCDecisionMissionPrevalenceType0 | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, str):
                    raise TypeError()
                mission_prevalence_type_0 = SSVCDecisionMissionPrevalenceType0(data)

                return mission_prevalence_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(None | SSVCDecisionMissionPrevalenceType0 | Unset, data)

        mission_prevalence = _parse_mission_prevalence(d.pop("mission_prevalence", UNSET))

        def _parse_public_wellbeing_impact(data: object) -> None | SSVCDecisionPublicWellbeingImpactType0 | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, str):
                    raise TypeError()
                public_wellbeing_impact_type_0 = SSVCDecisionPublicWellbeingImpactType0(data)

                return public_wellbeing_impact_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(None | SSVCDecisionPublicWellbeingImpactType0 | Unset, data)

        public_wellbeing_impact = _parse_public_wellbeing_impact(d.pop("public_wellbeing_impact", UNSET))

        role = d.pop("role", UNSET)

        _tree_source = d.pop("tree_source", UNSET)
        tree_source: SSVCDecisionTreeSource | Unset
        if isinstance(_tree_source, Unset):
            tree_source = UNSET
        else:
            tree_source = SSVCDecisionTreeSource(_tree_source)

        version = d.pop("version", UNSET)

        ssvc_decision = cls(
            automatable=automatable,
            decision=decision,
            exploitation=exploitation,
            technical_impact=technical_impact,
            assumed_inputs=assumed_inputs,
            exposure=exposure,
            human_impact=human_impact,
            method=method,
            mission_prevalence=mission_prevalence,
            public_wellbeing_impact=public_wellbeing_impact,
            role=role,
            tree_source=tree_source,
            version=version,
        )

        ssvc_decision.additional_properties = d
        return ssvc_decision

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

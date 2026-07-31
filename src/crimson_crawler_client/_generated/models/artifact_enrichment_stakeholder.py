from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, BinaryIO, Generator, TextIO, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..models.artifact_enrichment_stakeholder_exposure import ArtifactEnrichmentStakeholderExposure
from ..models.artifact_enrichment_stakeholder_human_impact import ArtifactEnrichmentStakeholderHumanImpact
from ..models.artifact_enrichment_stakeholder_method import ArtifactEnrichmentStakeholderMethod
from ..models.artifact_enrichment_stakeholder_mission_prevalence import ArtifactEnrichmentStakeholderMissionPrevalence
from ..models.artifact_enrichment_stakeholder_public_wellbeing_impact import (
    ArtifactEnrichmentStakeholderPublicWellbeingImpact,
)
from ..types import UNSET, Unset

T = TypeVar("T", bound="ArtifactEnrichmentStakeholder")


@_attrs_define
class ArtifactEnrichmentStakeholder:
    """Deployment context for the SSVC decision.

    Defaults represent a conservative unknown environment: ``exposure=open`` and
    ``human_impact=medium``. ``method`` selects the CERT/CC Deployer tree (default) or the CISA
    Coordinator tree. ``human_impact`` applies to the Deployer tree; ``mission_prevalence`` and
    ``public_wellbeing_impact`` apply to the Coordinator tree.

        Attributes:
            exposure (ArtifactEnrichmentStakeholderExposure | Unset): System exposure: small (isolated), controlled
                (limited), open (internet-facing) Default: ArtifactEnrichmentStakeholderExposure.OPEN.
            human_impact (ArtifactEnrichmentStakeholderHumanImpact | Unset): Deployer tree input. Human/mission impact of
                compromise. Ignored by cisa_coordinator method. Default: ArtifactEnrichmentStakeholderHumanImpact.MEDIUM.
            method (ArtifactEnrichmentStakeholderMethod | Unset): SSVC decision tree to apply. 'deployer' = CERT/CC Deployer
                tree v2.1 (default, Defer/Scheduled/Out-of-Cycle/Immediate → PATCH/WATCH/INFO). 'cisa_coordinator' = CISA SSVC
                Coordinator tree v2.0 (Track/Track*/Attend/Act) — the tree CISA itself uses for KEV/advisory decisions. Default:
                ArtifactEnrichmentStakeholderMethod.DEPLOYER.
            mission_prevalence (ArtifactEnrichmentStakeholderMissionPrevalence | Unset): CISA Coordinator tree input. How
                prevalent is this in the mission? minimal = uncommon, support = supports mission-essential functions, essential
                = directly involved in mission-essential functions. Ignored by deployer method. Default:
                ArtifactEnrichmentStakeholderMissionPrevalence.SUPPORT.
            public_wellbeing_impact (ArtifactEnrichmentStakeholderPublicWellbeingImpact | Unset): CISA Coordinator tree
                input. Worst-case impact on public well-being. minimal = negligible, material = real harm (financial,
                psychological), irreversible = catastrophic + non-recoverable (physical/safety). Ignored by deployer method.
                Default: ArtifactEnrichmentStakeholderPublicWellbeingImpact.MATERIAL.
    """

    exposure: ArtifactEnrichmentStakeholderExposure | Unset = ArtifactEnrichmentStakeholderExposure.OPEN
    human_impact: ArtifactEnrichmentStakeholderHumanImpact | Unset = ArtifactEnrichmentStakeholderHumanImpact.MEDIUM
    method: ArtifactEnrichmentStakeholderMethod | Unset = ArtifactEnrichmentStakeholderMethod.DEPLOYER
    mission_prevalence: ArtifactEnrichmentStakeholderMissionPrevalence | Unset = (
        ArtifactEnrichmentStakeholderMissionPrevalence.SUPPORT
    )
    public_wellbeing_impact: ArtifactEnrichmentStakeholderPublicWellbeingImpact | Unset = (
        ArtifactEnrichmentStakeholderPublicWellbeingImpact.MATERIAL
    )
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        exposure: str | Unset = UNSET
        if not isinstance(self.exposure, Unset):
            exposure = self.exposure.value

        human_impact: str | Unset = UNSET
        if not isinstance(self.human_impact, Unset):
            human_impact = self.human_impact.value

        method: str | Unset = UNSET
        if not isinstance(self.method, Unset):
            method = self.method.value

        mission_prevalence: str | Unset = UNSET
        if not isinstance(self.mission_prevalence, Unset):
            mission_prevalence = self.mission_prevalence.value

        public_wellbeing_impact: str | Unset = UNSET
        if not isinstance(self.public_wellbeing_impact, Unset):
            public_wellbeing_impact = self.public_wellbeing_impact.value

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
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

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        _exposure = d.pop("exposure", UNSET)
        exposure: ArtifactEnrichmentStakeholderExposure | Unset
        if isinstance(_exposure, Unset):
            exposure = UNSET
        else:
            exposure = ArtifactEnrichmentStakeholderExposure(_exposure)

        _human_impact = d.pop("human_impact", UNSET)
        human_impact: ArtifactEnrichmentStakeholderHumanImpact | Unset
        if isinstance(_human_impact, Unset):
            human_impact = UNSET
        else:
            human_impact = ArtifactEnrichmentStakeholderHumanImpact(_human_impact)

        _method = d.pop("method", UNSET)
        method: ArtifactEnrichmentStakeholderMethod | Unset
        if isinstance(_method, Unset):
            method = UNSET
        else:
            method = ArtifactEnrichmentStakeholderMethod(_method)

        _mission_prevalence = d.pop("mission_prevalence", UNSET)
        mission_prevalence: ArtifactEnrichmentStakeholderMissionPrevalence | Unset
        if isinstance(_mission_prevalence, Unset):
            mission_prevalence = UNSET
        else:
            mission_prevalence = ArtifactEnrichmentStakeholderMissionPrevalence(_mission_prevalence)

        _public_wellbeing_impact = d.pop("public_wellbeing_impact", UNSET)
        public_wellbeing_impact: ArtifactEnrichmentStakeholderPublicWellbeingImpact | Unset
        if isinstance(_public_wellbeing_impact, Unset):
            public_wellbeing_impact = UNSET
        else:
            public_wellbeing_impact = ArtifactEnrichmentStakeholderPublicWellbeingImpact(_public_wellbeing_impact)

        artifact_enrichment_stakeholder = cls(
            exposure=exposure,
            human_impact=human_impact,
            method=method,
            mission_prevalence=mission_prevalence,
            public_wellbeing_impact=public_wellbeing_impact,
        )

        artifact_enrichment_stakeholder.additional_properties = d
        return artifact_enrichment_stakeholder

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

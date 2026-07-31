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
            affected_products, campaigns, capec, cwe, defend, details, detections, epss, exploits, groups, inferred_chain,
            kev, knowledgebase, misp, mitigations, navigator, nist_controls, osv, poc, poc_source, sector_context,
            similar_cves, software, ssvc, summary, techniques, tie, timeline, web, web_scrape.
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
    stakeholder: ArtifactEnrichmentStakeholder | None | Unset = UNSET
    techniques_scope: BatchCVEItemTechniquesScope | Unset = BatchCVEItemTechniquesScope.ALL
    type_: Literal["cve"] | Unset = "cve"
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        from ..models.artifact_enrichment_stakeholder import ArtifactEnrichmentStakeholder

        cve_id = self.cve_id

        include: list[str] | Unset = UNSET
        if not isinstance(self.include, Unset):
            include = self.include

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
        if stakeholder is not UNSET:
            field_dict["stakeholder"] = stakeholder
        if techniques_scope is not UNSET:
            field_dict["techniques_scope"] = techniques_scope
        if type_ is not UNSET:
            field_dict["type"] = type_

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.artifact_enrichment_stakeholder import ArtifactEnrichmentStakeholder

        d = dict(src_dict)
        cve_id = d.pop("cve_id")

        include = cast(list[str], d.pop("include", UNSET))

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

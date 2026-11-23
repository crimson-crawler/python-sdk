from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, BinaryIO, Generator, Literal, TextIO, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..models.batch_technique_item_framework import BatchTechniqueItemFramework
from ..types import UNSET, Unset

T = TypeVar("T", bound="BatchTechniqueItem")


@_attrs_define
class BatchTechniqueItem:
    """Batch item: enrich an ATT&CK technique.

    Attributes:
        asset_id (None | str | Unset): ICS asset class id for the inverse lookup (e.g. 'A0007'). Valid only with
            `framework='ics'`, and mutually exclusive with `technique_id`, `technique_ids`, and `search`: it answers 'which
            techniques target this asset class', returning the asset in `asset` and its targets in `techniques`.
        framework (BatchTechniqueItemFramework | Unset): ATT&CK framework: enterprise, ics, or mobile Default:
            BatchTechniqueItemFramework.ENTERPRISE.
        include (list[str] | Unset): Response layers to include. Replaces the default list. Allowed values:
            analytic_details, asset_classes, atomic_red_team, campaigns, cisa_campaigns, cves, defend, details, detections,
            fight, framework_mappings, fraud, groups, knowledgebase, log_sources, lolbas, lotl, misp, mitigations,
            navigator, nist_controls, sigma, software, summary, tie, versions. `versions` attaches the object's KB revision
            history (`revision_history`). `analytic_details` attaches each detection analytic's tunable fields and log
            sources. `fraud` attaches `f3_techniques` — the MITRE F3 fraud techniques sharing this technique's own ATT&CK
            id. `asset_classes` attaches `asset_classes[]` — the ICS asset classes this technique targets, on an `ics`
            framework request. `sigma` attaches `sigma_rules[]` — the SigmaHQ detection rules whose ATT&CK tags name this
            technique (DRL-1.1). `lotl` attaches `lol_drivers[]` (the LOLDrivers entries exercising this technique),
            `gtfobins_binaries[]` (GTFOBins tools whose functions/contexts map onto it) and `hijacklibs_entries[]`
            (HijackLibs DLL hijacks whose type maps onto it) — facts only, joined through the committed function/type →
            ATT&CK map, never by name. Each source is capped at 50 rows per technique; `lol_drivers_total`,
            `gtfobins_binaries_total` and `hijacklibs_entries_total` carry the true counts. `fight` attaches
            `fight_techniques[]` — the MITRE FiGHT 5G techniques whose own `FGT` id maps onto this ATT&CK id (id-only join,
            never name matching; FiGHT-specific sub-techniques with no ATT&CK parent answer nothing). `lolbas` attaches
            `lolbas_binaries[]` — the LOLBAS binaries whose commands declare this ATT&CK technique, as names and ids only
            (no commands or descriptions). `framework_mappings` attaches `framework_mappings[]` — the CTID
            control/capability mappings for this technique across the aws, azure, gcp, m365, csa_ccm, veris, cri_profile,
            intel-vpro and cis frameworks; each row carries its own ATT&CK version because the families were built against
            different ones. `cisa_campaigns` attaches `cisa_campaigns[]` — the CISA joint cybersecurity advisories (AA-
            series) whose STIX bundle names this technique (a parent technique also matches advisories naming one of its
            sub-techniques), with their actors, sectors, locations and observable count. `atomic_red_team` attaches
            `atomic_tests[]` — the Red Canary Atomic Red Team tests exercising this technique (a parent also matches its
            sub-techniques), first 50 per technique with `atomic_tests_total` carrying the true count; each row carries the
            test name, auto_generated_guid, supported platforms, executor name, elevation flag and the upstream YAML link,
            never a command body.
        search (None | str | Unset): Text query to search techniques by name or description
        technique_id (None | str | Unset): Single technique ID for direct lookup (e.g. T1190)
        technique_ids (list[str] | None | Unset): List of technique IDs for batch lookup (max 50)
        type_ (Literal['technique'] | Unset): Selects ATT&CK technique enrichment for this item Default: 'technique'.
    """

    asset_id: None | str | Unset = UNSET
    framework: BatchTechniqueItemFramework | Unset = BatchTechniqueItemFramework.ENTERPRISE
    include: list[str] | Unset = UNSET
    search: None | str | Unset = UNSET
    technique_id: None | str | Unset = UNSET
    technique_ids: list[str] | None | Unset = UNSET
    type_: Literal["technique"] | Unset = "technique"
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        asset_id: None | str | Unset
        if isinstance(self.asset_id, Unset):
            asset_id = UNSET
        else:
            asset_id = self.asset_id

        framework: str | Unset = UNSET
        if not isinstance(self.framework, Unset):
            framework = self.framework.value

        include: list[str] | Unset = UNSET
        if not isinstance(self.include, Unset):
            include = self.include

        search: None | str | Unset
        if isinstance(self.search, Unset):
            search = UNSET
        else:
            search = self.search

        technique_id: None | str | Unset
        if isinstance(self.technique_id, Unset):
            technique_id = UNSET
        else:
            technique_id = self.technique_id

        technique_ids: list[str] | None | Unset
        if isinstance(self.technique_ids, Unset):
            technique_ids = UNSET
        elif isinstance(self.technique_ids, list):
            technique_ids = self.technique_ids

        else:
            technique_ids = self.technique_ids

        type_ = self.type_

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if asset_id is not UNSET:
            field_dict["asset_id"] = asset_id
        if framework is not UNSET:
            field_dict["framework"] = framework
        if include is not UNSET:
            field_dict["include"] = include
        if search is not UNSET:
            field_dict["search"] = search
        if technique_id is not UNSET:
            field_dict["technique_id"] = technique_id
        if technique_ids is not UNSET:
            field_dict["technique_ids"] = technique_ids
        if type_ is not UNSET:
            field_dict["type"] = type_

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)

        def _parse_asset_id(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        asset_id = _parse_asset_id(d.pop("asset_id", UNSET))

        _framework = d.pop("framework", UNSET)
        framework: BatchTechniqueItemFramework | Unset
        if isinstance(_framework, Unset):
            framework = UNSET
        else:
            framework = BatchTechniqueItemFramework(_framework)

        include = cast(list[str], d.pop("include", UNSET))

        def _parse_search(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        search = _parse_search(d.pop("search", UNSET))

        def _parse_technique_id(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        technique_id = _parse_technique_id(d.pop("technique_id", UNSET))

        def _parse_technique_ids(data: object) -> list[str] | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, list):
                    raise TypeError()
                technique_ids_type_0 = cast(list[str], data)

                return technique_ids_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(list[str] | None | Unset, data)

        technique_ids = _parse_technique_ids(d.pop("technique_ids", UNSET))

        type_ = cast(Literal["technique"] | Unset, d.pop("type", UNSET))
        if type_ != "technique" and not isinstance(type_, Unset):
            raise ValueError(f"type must match const 'technique', got '{type_}'")

        batch_technique_item = cls(
            asset_id=asset_id,
            framework=framework,
            include=include,
            search=search,
            technique_id=technique_id,
            technique_ids=technique_ids,
            type_=type_,
        )

        batch_technique_item.additional_properties = d
        return batch_technique_item

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

from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, BinaryIO, Generator, TextIO, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.asset_class import AssetClass
    from ..models.detection_strategy import DetectionStrategy
    from ..models.f3_technique import F3Technique
    from ..models.log_source import LogSource
    from ..models.revision_entry import RevisionEntry
    from ..models.technique_detail_kill_chain_phases_item import TechniqueDetailKillChainPhasesItem


T = TypeVar("T", bound="TechniqueDetail")


@_attrs_define
class TechniqueDetail:
    """MITRE ATT&CK technique - a specific adversary behavior mapped to tactics.

    Attributes:
        technique_id (str): ATT&CK technique ID (e.g. T1190)
        assets (list[AssetClass] | Unset): ICS only: the control-system asset classes this technique targets (PLC, HMI,
            RTU, Safety Controller, …), read off the ICS bundle's own `targets` edges. Empty for enterprise/mobile
            techniques.
        contributors (list[str] | Unset): Technique contributors from x_mitre_contributors
        created (None | str | Unset): When MITRE first created this object (ISO 8601)
        data_sources (list[str] | Unset): Data sources for detecting this technique
        deprecated (bool | Unset): True if MITRE marked this technique deprecated (x_mitre_deprecated) Default: False.
        description (None | str | Unset): Detailed technique description
        detection (None | str | Unset): Detection guidance from ATT&CK
        detection_strategies (list[DetectionStrategy] | Unset): ATT&CK v18 detection strategies for this technique, each
            with its analytics. v18 moved detection content out of `detection` (which remains for compatibility) into these;
            that is where the current detection logic lives.
        domains (list[str] | Unset): ATT&CK domains (enterprise-attack, ics-attack, mobile-attack)
        f3_techniques (list[F3Technique] | Unset): MITRE F3 (fraud) techniques that carry THIS technique's own ATT&CK id
            as their identity (43 of F3's 132 objects do). Only populated on `/v1/enrich/technique` when `fraud` is in
            `include`; empty means either the token was not requested or F3 has no twin for this id — the two are
            distinguishable from the request.
        impact_type (list[str] | Unset): CIA impact axis MITRE assigns an impact technique (e.g. ['Availability'] for
            T1490). Carried by enterprise and ICS impact techniques (26 of 1,600 enterprise objects).
        is_subtechnique (bool | Unset): Whether this is a sub-technique (e.g. T1059.001) Default: False.
        kill_chain_phases (list[TechniqueDetailKillChainPhasesItem] | Unset): Ordered kill-chain phases ({phase_name,
            tactic_order}) for attack-path sequencing
        log_sources (list[LogSource] | Unset): Where this technique's data sources are recorded ({name, channel} per
            source) — the concrete log locations the `data_sources` names imply. Request via include=['log_sources']; the
            default form is capped at 20 rows in a stable order, and include=['log_sources_full'] returns every row.
        log_sources_total (int | Unset): How many log sources the technique has, before the summary cap (0 when not
            requested) Default: 0.
        log_sources_truncated (bool | Unset): True when `log_sources` is the capped summary; request `log_sources_full`
            for all rows Default: False.
        modified (None | str | Unset): When MITRE last revised this object (ISO 8601) — ATT&CK ships monthly
        name (None | str | Unset): Technique name (e.g. 'Exploit Public-Facing Application')
        object_marking_refs (list[str] | Unset): STIX marking-definition ids applied to this object (licence/terms)
        parent_technique_id (None | str | Unset): ATT&CK id of the parent technique this one specialises, e.g. 'T1059'
            for T1059.001. Read from the catalogue's own parent mapping, never split off the dotted id, so a sub-technique
            whose parent mapping is unavailable keeps `null` rather than a guess. `null` on every top-level technique.
        platforms (list[str] | Unset): Applicable platforms (e.g. ['Windows', 'Linux', 'macOS'])
        remote_support (bool | None | Unset): Whether the technique supports remote execution
        revision_history (list[RevisionEntry] | Unset): The object's revision history from `/objects/{id}/versions/` —
            one row per revision with the KB versions that carried it. Opt-in via include=['versions']; it answers 'when did
            MITRE last change this and under which KB version'.
        revoked (bool | Unset): True if MITRE has revoked this technique Default: False.
        spec_version (None | str | Unset): STIX spec revision the record was normalised under
            (x_mitre_attack_spec_version, else spec_version)
        stix_id (None | str | Unset): Unique object identifier for cross-referencing
        subtechnique_ids (list[str] | Unset): ATT&CK ids of this technique's own sub-techniques, e.g. ['T1059.001',
            'T1059.002'] for T1059. Empty for a technique the catalogue gives none.
        tactic_rank (int | None | Unset): For DISARM tactic rows: MITRE's explicit ordering rank (x_mitre_rank)
        tactic_shortname (None | str | Unset): For `x-mitre-tactic` rows: the shortname every downstream join keys on
            (attack.mitre.org paths, Navigator tactic ids). 100% of tactics in all six KBs.
        tactic_type (list[str] | Unset): Mobile-only axis separating pre-device-access vectors from post-compromise
            behaviour (x_mitre_tactic_type; 111 of 646 mobile objects).
        tactics (list[str] | Unset): ATT&CK tactics this technique belongs to (e.g. ['initial-access'])
        url (None | str | Unset): Reference URL for full technique details
        version (None | str | Unset): MITRE object version (x_mitre_version)
    """

    technique_id: str
    assets: list[AssetClass] | Unset = UNSET
    contributors: list[str] | Unset = UNSET
    created: None | str | Unset = UNSET
    data_sources: list[str] | Unset = UNSET
    deprecated: bool | Unset = False
    description: None | str | Unset = UNSET
    detection: None | str | Unset = UNSET
    detection_strategies: list[DetectionStrategy] | Unset = UNSET
    domains: list[str] | Unset = UNSET
    f3_techniques: list[F3Technique] | Unset = UNSET
    impact_type: list[str] | Unset = UNSET
    is_subtechnique: bool | Unset = False
    kill_chain_phases: list[TechniqueDetailKillChainPhasesItem] | Unset = UNSET
    log_sources: list[LogSource] | Unset = UNSET
    log_sources_total: int | Unset = 0
    log_sources_truncated: bool | Unset = False
    modified: None | str | Unset = UNSET
    name: None | str | Unset = UNSET
    object_marking_refs: list[str] | Unset = UNSET
    parent_technique_id: None | str | Unset = UNSET
    platforms: list[str] | Unset = UNSET
    remote_support: bool | None | Unset = UNSET
    revision_history: list[RevisionEntry] | Unset = UNSET
    revoked: bool | Unset = False
    spec_version: None | str | Unset = UNSET
    stix_id: None | str | Unset = UNSET
    subtechnique_ids: list[str] | Unset = UNSET
    tactic_rank: int | None | Unset = UNSET
    tactic_shortname: None | str | Unset = UNSET
    tactic_type: list[str] | Unset = UNSET
    tactics: list[str] | Unset = UNSET
    url: None | str | Unset = UNSET
    version: None | str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        from ..models.asset_class import AssetClass  # noqa: PLC0415
        from ..models.detection_strategy import DetectionStrategy  # noqa: PLC0415
        from ..models.f3_technique import F3Technique  # noqa: PLC0415
        from ..models.log_source import LogSource  # noqa: PLC0415
        from ..models.revision_entry import RevisionEntry  # noqa: PLC0415
        from ..models.technique_detail_kill_chain_phases_item import TechniqueDetailKillChainPhasesItem  # noqa: PLC0415

        technique_id = self.technique_id

        assets: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.assets, Unset):
            assets = []
            for assets_item_data in self.assets:
                assets_item = assets_item_data.to_dict()
                assets.append(assets_item)

        contributors: list[str] | Unset = UNSET
        if not isinstance(self.contributors, Unset):
            contributors = self.contributors

        created: None | str | Unset
        if isinstance(self.created, Unset):
            created = UNSET
        else:
            created = self.created

        data_sources: list[str] | Unset = UNSET
        if not isinstance(self.data_sources, Unset):
            data_sources = self.data_sources

        deprecated = self.deprecated

        description: None | str | Unset
        if isinstance(self.description, Unset):
            description = UNSET
        else:
            description = self.description

        detection: None | str | Unset
        if isinstance(self.detection, Unset):
            detection = UNSET
        else:
            detection = self.detection

        detection_strategies: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.detection_strategies, Unset):
            detection_strategies = []
            for detection_strategies_item_data in self.detection_strategies:
                detection_strategies_item = detection_strategies_item_data.to_dict()
                detection_strategies.append(detection_strategies_item)

        domains: list[str] | Unset = UNSET
        if not isinstance(self.domains, Unset):
            domains = self.domains

        f3_techniques: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.f3_techniques, Unset):
            f3_techniques = []
            for f3_techniques_item_data in self.f3_techniques:
                f3_techniques_item = f3_techniques_item_data.to_dict()
                f3_techniques.append(f3_techniques_item)

        impact_type: list[str] | Unset = UNSET
        if not isinstance(self.impact_type, Unset):
            impact_type = self.impact_type

        is_subtechnique = self.is_subtechnique

        kill_chain_phases: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.kill_chain_phases, Unset):
            kill_chain_phases = []
            for kill_chain_phases_item_data in self.kill_chain_phases:
                kill_chain_phases_item = kill_chain_phases_item_data.to_dict()
                kill_chain_phases.append(kill_chain_phases_item)

        log_sources: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.log_sources, Unset):
            log_sources = []
            for log_sources_item_data in self.log_sources:
                log_sources_item = log_sources_item_data.to_dict()
                log_sources.append(log_sources_item)

        log_sources_total = self.log_sources_total

        log_sources_truncated = self.log_sources_truncated

        modified: None | str | Unset
        if isinstance(self.modified, Unset):
            modified = UNSET
        else:
            modified = self.modified

        name: None | str | Unset
        if isinstance(self.name, Unset):
            name = UNSET
        else:
            name = self.name

        object_marking_refs: list[str] | Unset = UNSET
        if not isinstance(self.object_marking_refs, Unset):
            object_marking_refs = self.object_marking_refs

        parent_technique_id: None | str | Unset
        if isinstance(self.parent_technique_id, Unset):
            parent_technique_id = UNSET
        else:
            parent_technique_id = self.parent_technique_id

        platforms: list[str] | Unset = UNSET
        if not isinstance(self.platforms, Unset):
            platforms = self.platforms

        remote_support: bool | None | Unset
        if isinstance(self.remote_support, Unset):
            remote_support = UNSET
        else:
            remote_support = self.remote_support

        revision_history: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.revision_history, Unset):
            revision_history = []
            for revision_history_item_data in self.revision_history:
                revision_history_item = revision_history_item_data.to_dict()
                revision_history.append(revision_history_item)

        revoked = self.revoked

        spec_version: None | str | Unset
        if isinstance(self.spec_version, Unset):
            spec_version = UNSET
        else:
            spec_version = self.spec_version

        stix_id: None | str | Unset
        if isinstance(self.stix_id, Unset):
            stix_id = UNSET
        else:
            stix_id = self.stix_id

        subtechnique_ids: list[str] | Unset = UNSET
        if not isinstance(self.subtechnique_ids, Unset):
            subtechnique_ids = self.subtechnique_ids

        tactic_rank: int | None | Unset
        if isinstance(self.tactic_rank, Unset):
            tactic_rank = UNSET
        else:
            tactic_rank = self.tactic_rank

        tactic_shortname: None | str | Unset
        if isinstance(self.tactic_shortname, Unset):
            tactic_shortname = UNSET
        else:
            tactic_shortname = self.tactic_shortname

        tactic_type: list[str] | Unset = UNSET
        if not isinstance(self.tactic_type, Unset):
            tactic_type = self.tactic_type

        tactics: list[str] | Unset = UNSET
        if not isinstance(self.tactics, Unset):
            tactics = self.tactics

        url: None | str | Unset
        if isinstance(self.url, Unset):
            url = UNSET
        else:
            url = self.url

        version: None | str | Unset
        if isinstance(self.version, Unset):
            version = UNSET
        else:
            version = self.version

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "technique_id": technique_id,
            }
        )
        if assets is not UNSET:
            field_dict["assets"] = assets
        if contributors is not UNSET:
            field_dict["contributors"] = contributors
        if created is not UNSET:
            field_dict["created"] = created
        if data_sources is not UNSET:
            field_dict["data_sources"] = data_sources
        if deprecated is not UNSET:
            field_dict["deprecated"] = deprecated
        if description is not UNSET:
            field_dict["description"] = description
        if detection is not UNSET:
            field_dict["detection"] = detection
        if detection_strategies is not UNSET:
            field_dict["detection_strategies"] = detection_strategies
        if domains is not UNSET:
            field_dict["domains"] = domains
        if f3_techniques is not UNSET:
            field_dict["f3_techniques"] = f3_techniques
        if impact_type is not UNSET:
            field_dict["impact_type"] = impact_type
        if is_subtechnique is not UNSET:
            field_dict["is_subtechnique"] = is_subtechnique
        if kill_chain_phases is not UNSET:
            field_dict["kill_chain_phases"] = kill_chain_phases
        if log_sources is not UNSET:
            field_dict["log_sources"] = log_sources
        if log_sources_total is not UNSET:
            field_dict["log_sources_total"] = log_sources_total
        if log_sources_truncated is not UNSET:
            field_dict["log_sources_truncated"] = log_sources_truncated
        if modified is not UNSET:
            field_dict["modified"] = modified
        if name is not UNSET:
            field_dict["name"] = name
        if object_marking_refs is not UNSET:
            field_dict["object_marking_refs"] = object_marking_refs
        if parent_technique_id is not UNSET:
            field_dict["parent_technique_id"] = parent_technique_id
        if platforms is not UNSET:
            field_dict["platforms"] = platforms
        if remote_support is not UNSET:
            field_dict["remote_support"] = remote_support
        if revision_history is not UNSET:
            field_dict["revision_history"] = revision_history
        if revoked is not UNSET:
            field_dict["revoked"] = revoked
        if spec_version is not UNSET:
            field_dict["spec_version"] = spec_version
        if stix_id is not UNSET:
            field_dict["stix_id"] = stix_id
        if subtechnique_ids is not UNSET:
            field_dict["subtechnique_ids"] = subtechnique_ids
        if tactic_rank is not UNSET:
            field_dict["tactic_rank"] = tactic_rank
        if tactic_shortname is not UNSET:
            field_dict["tactic_shortname"] = tactic_shortname
        if tactic_type is not UNSET:
            field_dict["tactic_type"] = tactic_type
        if tactics is not UNSET:
            field_dict["tactics"] = tactics
        if url is not UNSET:
            field_dict["url"] = url
        if version is not UNSET:
            field_dict["version"] = version

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.asset_class import AssetClass  # noqa: PLC0415
        from ..models.detection_strategy import DetectionStrategy  # noqa: PLC0415
        from ..models.f3_technique import F3Technique  # noqa: PLC0415
        from ..models.log_source import LogSource  # noqa: PLC0415
        from ..models.revision_entry import RevisionEntry  # noqa: PLC0415
        from ..models.technique_detail_kill_chain_phases_item import TechniqueDetailKillChainPhasesItem  # noqa: PLC0415

        d = dict(src_dict)
        technique_id = d.pop("technique_id")

        _assets = d.pop("assets", UNSET)
        assets: list[AssetClass] | Unset = UNSET
        if _assets is not UNSET:
            assets = []
            for assets_item_data in _assets:
                assets_item = AssetClass.from_dict(assets_item_data)

                assets.append(assets_item)

        contributors = cast(list[str], d.pop("contributors", UNSET))

        def _parse_created(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        created = _parse_created(d.pop("created", UNSET))

        data_sources = cast(list[str], d.pop("data_sources", UNSET))

        deprecated = d.pop("deprecated", UNSET)

        def _parse_description(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        description = _parse_description(d.pop("description", UNSET))

        def _parse_detection(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        detection = _parse_detection(d.pop("detection", UNSET))

        _detection_strategies = d.pop("detection_strategies", UNSET)
        detection_strategies: list[DetectionStrategy] | Unset = UNSET
        if _detection_strategies is not UNSET:
            detection_strategies = []
            for detection_strategies_item_data in _detection_strategies:
                detection_strategies_item = DetectionStrategy.from_dict(detection_strategies_item_data)

                detection_strategies.append(detection_strategies_item)

        domains = cast(list[str], d.pop("domains", UNSET))

        _f3_techniques = d.pop("f3_techniques", UNSET)
        f3_techniques: list[F3Technique] | Unset = UNSET
        if _f3_techniques is not UNSET:
            f3_techniques = []
            for f3_techniques_item_data in _f3_techniques:
                f3_techniques_item = F3Technique.from_dict(f3_techniques_item_data)

                f3_techniques.append(f3_techniques_item)

        impact_type = cast(list[str], d.pop("impact_type", UNSET))

        is_subtechnique = d.pop("is_subtechnique", UNSET)

        _kill_chain_phases = d.pop("kill_chain_phases", UNSET)
        kill_chain_phases: list[TechniqueDetailKillChainPhasesItem] | Unset = UNSET
        if _kill_chain_phases is not UNSET:
            kill_chain_phases = []
            for kill_chain_phases_item_data in _kill_chain_phases:
                kill_chain_phases_item = TechniqueDetailKillChainPhasesItem.from_dict(kill_chain_phases_item_data)

                kill_chain_phases.append(kill_chain_phases_item)

        _log_sources = d.pop("log_sources", UNSET)
        log_sources: list[LogSource] | Unset = UNSET
        if _log_sources is not UNSET:
            log_sources = []
            for log_sources_item_data in _log_sources:
                log_sources_item = LogSource.from_dict(log_sources_item_data)

                log_sources.append(log_sources_item)

        log_sources_total = d.pop("log_sources_total", UNSET)

        log_sources_truncated = d.pop("log_sources_truncated", UNSET)

        def _parse_modified(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        modified = _parse_modified(d.pop("modified", UNSET))

        def _parse_name(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        name = _parse_name(d.pop("name", UNSET))

        object_marking_refs = cast(list[str], d.pop("object_marking_refs", UNSET))

        def _parse_parent_technique_id(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        parent_technique_id = _parse_parent_technique_id(d.pop("parent_technique_id", UNSET))

        platforms = cast(list[str], d.pop("platforms", UNSET))

        def _parse_remote_support(data: object) -> bool | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(bool | None | Unset, data)

        remote_support = _parse_remote_support(d.pop("remote_support", UNSET))

        _revision_history = d.pop("revision_history", UNSET)
        revision_history: list[RevisionEntry] | Unset = UNSET
        if _revision_history is not UNSET:
            revision_history = []
            for revision_history_item_data in _revision_history:
                revision_history_item = RevisionEntry.from_dict(revision_history_item_data)

                revision_history.append(revision_history_item)

        revoked = d.pop("revoked", UNSET)

        def _parse_spec_version(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        spec_version = _parse_spec_version(d.pop("spec_version", UNSET))

        def _parse_stix_id(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        stix_id = _parse_stix_id(d.pop("stix_id", UNSET))

        subtechnique_ids = cast(list[str], d.pop("subtechnique_ids", UNSET))

        def _parse_tactic_rank(data: object) -> int | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(int | None | Unset, data)

        tactic_rank = _parse_tactic_rank(d.pop("tactic_rank", UNSET))

        def _parse_tactic_shortname(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        tactic_shortname = _parse_tactic_shortname(d.pop("tactic_shortname", UNSET))

        tactic_type = cast(list[str], d.pop("tactic_type", UNSET))

        tactics = cast(list[str], d.pop("tactics", UNSET))

        def _parse_url(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        url = _parse_url(d.pop("url", UNSET))

        def _parse_version(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        version = _parse_version(d.pop("version", UNSET))

        technique_detail = cls(
            technique_id=technique_id,
            assets=assets,
            contributors=contributors,
            created=created,
            data_sources=data_sources,
            deprecated=deprecated,
            description=description,
            detection=detection,
            detection_strategies=detection_strategies,
            domains=domains,
            f3_techniques=f3_techniques,
            impact_type=impact_type,
            is_subtechnique=is_subtechnique,
            kill_chain_phases=kill_chain_phases,
            log_sources=log_sources,
            log_sources_total=log_sources_total,
            log_sources_truncated=log_sources_truncated,
            modified=modified,
            name=name,
            object_marking_refs=object_marking_refs,
            parent_technique_id=parent_technique_id,
            platforms=platforms,
            remote_support=remote_support,
            revision_history=revision_history,
            revoked=revoked,
            spec_version=spec_version,
            stix_id=stix_id,
            subtechnique_ids=subtechnique_ids,
            tactic_rank=tactic_rank,
            tactic_shortname=tactic_shortname,
            tactic_type=tactic_type,
            tactics=tactics,
            url=url,
            version=version,
        )

        technique_detail.additional_properties = d
        return technique_detail

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

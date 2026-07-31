from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, BinaryIO, Generator, TextIO, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.knowledgebase_result_metadata_type_0 import KnowledgebaseResultMetadataType0


T = TypeVar("T", bound="KnowledgebaseResult")


@_attrs_define
class KnowledgebaseResult:
    """Knowledge base search result with relevance scoring.

    Attributes:
        content (str): Matched content
        collection (None | str | Unset): Knowledge base collection the result came from
        distance (float | None | Unset): Vector distance for the match (lower is closer), when computed
        metadata (KnowledgebaseResultMetadataType0 | None | Unset): Per-chunk metadata fields beyond text/source/score
            (e.g. ttp_id, source_repo, phase, platforms, executors for the red_team collection). Shape varies by collection.
        score (float | None | Unset): Relevance score (higher is more relevant)
        source (None | str | Unset): Source document or reference
    """

    content: str
    collection: None | str | Unset = UNSET
    distance: float | None | Unset = UNSET
    metadata: KnowledgebaseResultMetadataType0 | None | Unset = UNSET
    score: float | None | Unset = UNSET
    source: None | str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        from ..models.knowledgebase_result_metadata_type_0 import KnowledgebaseResultMetadataType0

        content = self.content

        collection: None | str | Unset
        if isinstance(self.collection, Unset):
            collection = UNSET
        else:
            collection = self.collection

        distance: float | None | Unset
        if isinstance(self.distance, Unset):
            distance = UNSET
        else:
            distance = self.distance

        metadata: dict[str, Any] | None | Unset
        if isinstance(self.metadata, Unset):
            metadata = UNSET
        elif isinstance(self.metadata, KnowledgebaseResultMetadataType0):
            metadata = self.metadata.to_dict()
        else:
            metadata = self.metadata

        score: float | None | Unset
        if isinstance(self.score, Unset):
            score = UNSET
        else:
            score = self.score

        source: None | str | Unset
        if isinstance(self.source, Unset):
            source = UNSET
        else:
            source = self.source

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "content": content,
            }
        )
        if collection is not UNSET:
            field_dict["collection"] = collection
        if distance is not UNSET:
            field_dict["distance"] = distance
        if metadata is not UNSET:
            field_dict["metadata"] = metadata
        if score is not UNSET:
            field_dict["score"] = score
        if source is not UNSET:
            field_dict["source"] = source

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.knowledgebase_result_metadata_type_0 import KnowledgebaseResultMetadataType0

        d = dict(src_dict)
        content = d.pop("content")

        def _parse_collection(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        collection = _parse_collection(d.pop("collection", UNSET))

        def _parse_distance(data: object) -> float | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(float | None | Unset, data)

        distance = _parse_distance(d.pop("distance", UNSET))

        def _parse_metadata(data: object) -> KnowledgebaseResultMetadataType0 | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, dict):
                    raise TypeError()
                metadata_type_0 = KnowledgebaseResultMetadataType0.from_dict(data)

                return metadata_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(KnowledgebaseResultMetadataType0 | None | Unset, data)

        metadata = _parse_metadata(d.pop("metadata", UNSET))

        def _parse_score(data: object) -> float | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(float | None | Unset, data)

        score = _parse_score(d.pop("score", UNSET))

        def _parse_source(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        source = _parse_source(d.pop("source", UNSET))

        knowledgebase_result = cls(
            content=content,
            collection=collection,
            distance=distance,
            metadata=metadata,
            score=score,
            source=source,
        )

        knowledgebase_result.additional_properties = d
        return knowledgebase_result

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

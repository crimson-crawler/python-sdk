from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, BinaryIO, Generator, TextIO, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="JVNAdvisory")


@_attrs_define
class JVNAdvisory:
    """One JVN advisory that references a CVE.

    Two sources answer under one shape: JVN iPedia's ``JVNDB-YYYY-NNNNNN`` rows (the English
    RDF feed) and the JVN site's own ``JVN#`` / ``JVNVU#`` notes (jvn.jp), which the corpus
    also ingests while JVN iPedia is suspended. Link and metadata only — an advisory body is
    never redistributed.

        Attributes:
            jvndb_id (str): Advisory id: `JVNDB-YYYY-NNNNNN`, or a JVN site note id (`JVN#…` / `JVNVU#…`)
            source_url (str): The feed the row came from: the JVNDB English feed, or `jvn.jp`'s note feed
            title (str): Advisory title as published
            url (str): Canonical JVNDB advisory URL
            cve_ids (list[str] | Unset): CVE ids the advisory references, as the feed's own `sec:identifier` entries state
                them — the structured refs the corpus already parses for its CVE index. Empty on an advisory that names no CVE.
            product (None | str | Unset): First `sec:cpe` product
            published (None | str | Unset): Published timestamp as published
            source (str | Unset): Source label: `jvndb` (JVN iPedia feed) or `jvn` (JVN site note) Default: 'jvndb'.
            vendor (None | str | Unset): First `sec:cpe` vendor
    """

    jvndb_id: str
    source_url: str
    title: str
    url: str
    cve_ids: list[str] | Unset = UNSET
    product: None | str | Unset = UNSET
    published: None | str | Unset = UNSET
    source: str | Unset = "jvndb"
    vendor: None | str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        jvndb_id = self.jvndb_id

        source_url = self.source_url

        title = self.title

        url = self.url

        cve_ids: list[str] | Unset = UNSET
        if not isinstance(self.cve_ids, Unset):
            cve_ids = self.cve_ids

        product: None | str | Unset
        if isinstance(self.product, Unset):
            product = UNSET
        else:
            product = self.product

        published: None | str | Unset
        if isinstance(self.published, Unset):
            published = UNSET
        else:
            published = self.published

        source = self.source

        vendor: None | str | Unset
        if isinstance(self.vendor, Unset):
            vendor = UNSET
        else:
            vendor = self.vendor

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "jvndb_id": jvndb_id,
                "source_url": source_url,
                "title": title,
                "url": url,
            }
        )
        if cve_ids is not UNSET:
            field_dict["cve_ids"] = cve_ids
        if product is not UNSET:
            field_dict["product"] = product
        if published is not UNSET:
            field_dict["published"] = published
        if source is not UNSET:
            field_dict["source"] = source
        if vendor is not UNSET:
            field_dict["vendor"] = vendor

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        jvndb_id = d.pop("jvndb_id")

        source_url = d.pop("source_url")

        title = d.pop("title")

        url = d.pop("url")

        cve_ids = cast(list[str], d.pop("cve_ids", UNSET))

        def _parse_product(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        product = _parse_product(d.pop("product", UNSET))

        def _parse_published(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        published = _parse_published(d.pop("published", UNSET))

        source = d.pop("source", UNSET)

        def _parse_vendor(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        vendor = _parse_vendor(d.pop("vendor", UNSET))

        jvn_advisory = cls(
            jvndb_id=jvndb_id,
            source_url=source_url,
            title=title,
            url=url,
            cve_ids=cve_ids,
            product=product,
            published=published,
            source=source,
            vendor=vendor,
        )

        jvn_advisory.additional_properties = d
        return jvn_advisory

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

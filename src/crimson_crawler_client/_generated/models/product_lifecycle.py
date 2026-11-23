from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, BinaryIO, Generator, TextIO, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="ProductLifecycle")


@_attrs_define
class ProductLifecycle:
    """One endoflife.date cycle for a product (support/EOL dates, latest release).

    `eol` and `support` are the upstream's own values and may be a date string or a
    boolean, so they stay `str | bool | None` rather than being coerced.

        Attributes:
            product (str): Product the row describes
            slug (str): endoflife.date slug the row was read from
            source_url (str): The API URL the row was read from
            attribution (str | Unset): Copyright and permission notice for the lifecycle source data. Default: 'Copyright
                2020 endoflife.date contributors. Permission is hereby granted, free of charge, to any person obtaining a copy
                of this software and associated documentation files (the \\\\"Software\\\\"), to deal in the Software without
                restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute,
                sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do
                so, subject to the following conditions: The above copyright notice and this permission notice shall be included
                in all copies or substantial portions of the Software. THE SOFTWARE IS PROVIDED \\\\"AS IS\\\\", WITHOUT
                WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
                FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
                LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
                FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.'.
            cycle (None | str | Unset): Release cycle (e.g. '2.4')
            eol (bool | None | str | Unset): End-of-life date, or false while supported
            latest (None | str | Unset): Latest release in the cycle
            latest_release_date (None | str | Unset): Date of the latest release
            licence (str | Unset): Licence of the endoflife.date source data. Default: 'MIT'.
            link (None | str | Unset): Upstream release-notes link
            lts (bool | None | Unset): Whether the cycle is a long-term-support line
            release_date (None | str | Unset): Cycle release date
            retrieved_at (str | Unset): When this codebase read it (ISO 8601) Default: ''.
            source (str | Unset): Stable source label Default: 'endoflife.date'.
            support (bool | None | str | Unset): Support end date, or false when open
    """

    product: str
    slug: str
    source_url: str
    attribution: str | Unset = (
        'Copyright 2020 endoflife.date contributors. Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the \\"Software\\"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions: The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software. THE SOFTWARE IS PROVIDED \\"AS IS\\", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.'
    )
    cycle: None | str | Unset = UNSET
    eol: bool | None | str | Unset = UNSET
    latest: None | str | Unset = UNSET
    latest_release_date: None | str | Unset = UNSET
    licence: str | Unset = "MIT"
    link: None | str | Unset = UNSET
    lts: bool | None | Unset = UNSET
    release_date: None | str | Unset = UNSET
    retrieved_at: str | Unset = ""
    source: str | Unset = "endoflife.date"
    support: bool | None | str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        product = self.product

        slug = self.slug

        source_url = self.source_url

        attribution = self.attribution

        cycle: None | str | Unset
        if isinstance(self.cycle, Unset):
            cycle = UNSET
        else:
            cycle = self.cycle

        eol: bool | None | str | Unset
        if isinstance(self.eol, Unset):
            eol = UNSET
        else:
            eol = self.eol

        latest: None | str | Unset
        if isinstance(self.latest, Unset):
            latest = UNSET
        else:
            latest = self.latest

        latest_release_date: None | str | Unset
        if isinstance(self.latest_release_date, Unset):
            latest_release_date = UNSET
        else:
            latest_release_date = self.latest_release_date

        licence = self.licence

        link: None | str | Unset
        if isinstance(self.link, Unset):
            link = UNSET
        else:
            link = self.link

        lts: bool | None | Unset
        if isinstance(self.lts, Unset):
            lts = UNSET
        else:
            lts = self.lts

        release_date: None | str | Unset
        if isinstance(self.release_date, Unset):
            release_date = UNSET
        else:
            release_date = self.release_date

        retrieved_at = self.retrieved_at

        source = self.source

        support: bool | None | str | Unset
        if isinstance(self.support, Unset):
            support = UNSET
        else:
            support = self.support

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "product": product,
                "slug": slug,
                "source_url": source_url,
            }
        )
        if attribution is not UNSET:
            field_dict["attribution"] = attribution
        if cycle is not UNSET:
            field_dict["cycle"] = cycle
        if eol is not UNSET:
            field_dict["eol"] = eol
        if latest is not UNSET:
            field_dict["latest"] = latest
        if latest_release_date is not UNSET:
            field_dict["latest_release_date"] = latest_release_date
        if licence is not UNSET:
            field_dict["licence"] = licence
        if link is not UNSET:
            field_dict["link"] = link
        if lts is not UNSET:
            field_dict["lts"] = lts
        if release_date is not UNSET:
            field_dict["release_date"] = release_date
        if retrieved_at is not UNSET:
            field_dict["retrieved_at"] = retrieved_at
        if source is not UNSET:
            field_dict["source"] = source
        if support is not UNSET:
            field_dict["support"] = support

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        product = d.pop("product")

        slug = d.pop("slug")

        source_url = d.pop("source_url")

        attribution = d.pop("attribution", UNSET)

        def _parse_cycle(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        cycle = _parse_cycle(d.pop("cycle", UNSET))

        def _parse_eol(data: object) -> bool | None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(bool | None | str | Unset, data)

        eol = _parse_eol(d.pop("eol", UNSET))

        def _parse_latest(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        latest = _parse_latest(d.pop("latest", UNSET))

        def _parse_latest_release_date(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        latest_release_date = _parse_latest_release_date(d.pop("latest_release_date", UNSET))

        licence = d.pop("licence", UNSET)

        def _parse_link(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        link = _parse_link(d.pop("link", UNSET))

        def _parse_lts(data: object) -> bool | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(bool | None | Unset, data)

        lts = _parse_lts(d.pop("lts", UNSET))

        def _parse_release_date(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        release_date = _parse_release_date(d.pop("release_date", UNSET))

        retrieved_at = d.pop("retrieved_at", UNSET)

        source = d.pop("source", UNSET)

        def _parse_support(data: object) -> bool | None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(bool | None | str | Unset, data)

        support = _parse_support(d.pop("support", UNSET))

        product_lifecycle = cls(
            product=product,
            slug=slug,
            source_url=source_url,
            attribution=attribution,
            cycle=cycle,
            eol=eol,
            latest=latest,
            latest_release_date=latest_release_date,
            licence=licence,
            link=link,
            lts=lts,
            release_date=release_date,
            retrieved_at=retrieved_at,
            source=source,
            support=support,
        )

        product_lifecycle.additional_properties = d
        return product_lifecycle

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

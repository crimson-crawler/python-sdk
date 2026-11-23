from http import HTTPStatus
from typing import Any, cast
from urllib.parse import quote

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.search_misp_request import SearchMISPRequest
from ...models.search_misp_response import SearchMISPResponse
from ...types import UNSET, Response


def _get_kwargs(
    *,
    body: SearchMISPRequest,
) -> dict[str, Any]:
    headers: dict[str, Any] = {}

    _kwargs: dict[str, Any] = {
        "method": "post",
        "url": "/v1/search/misp",
    }

    _kwargs["json"] = body.to_dict()

    headers["Content-Type"] = "application/json"

    _kwargs["headers"] = headers
    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> Any | SearchMISPResponse | None:
    if response.status_code == 200:
        response_200 = SearchMISPResponse.from_dict(response.json())

        return response_200

    if response.status_code == 401:
        response_401 = cast(Any, None)
        return response_401

    if response.status_code == 422:
        response_422 = cast(Any, None)
        return response_422

    if response.status_code == 429:
        response_429 = cast(Any, None)
        return response_429

    if response.status_code == 500:
        response_500 = cast(Any, None)
        return response_500

    if client.raise_on_unexpected_status:
        raise errors.UnexpectedStatus(response.status_code, response.content)
    else:
        return None


def _build_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> Response[Any | SearchMISPResponse]:
    return Response(
        status_code=HTTPStatus(response.status_code),
        content=response.content,
        headers=response.headers,
        parsed=_parse_response(client=client, response=response),
    )


def sync_detailed(
    *,
    client: AuthenticatedClient,
    body: SearchMISPRequest,
) -> Response[Any | SearchMISPResponse]:
    """Search MISP

     Search our curated MISP by indicator, event text, or event ID.

    Returns matching threat events and indicators with actor and malware context. Our curated MISP pulls
    a small set of public feeds on a daily schedule; the full list is at
    https://crimsoncrawler.com/docs/guides/data-sources/#our-curated-misp.

    **Filters**

    - `value` — indicator value to match (IP, hash, domain, etc.)
    - `eventinfo` — search events by title or description text
    - `event_id` — look up one event directly by ID
    - `type_attribute` — restrict to one attribute type (e.g. `ip-dst`, `md5`, `domain`)
    - `category` — restrict to one MISP attribute category (e.g. `Network activity`, `Payload delivery`)
    - `tags` — match any of the given tags (supports `tlp:` prefixes and galaxy cluster names)
    - `to_ids` — attribute selector: `true` returns only attributes flagged for IDS detection
      (high-confidence indicators), `false` only attributes NOT flagged. Omitting it does not filter.
    - `threat_level_id` — event threat level: `1` (high), `2` (medium), `3` (low), `4` (undefined)
    - `date_from` / `date_to` — restrict to an event date range (`YYYY-MM-DD`)
    - `published` — restrict to events published by their owning org (excludes analyst drafts)

    Attribute filters (`value`, `type_attribute`, `category`, `tags`, `to_ids`) search attributes
    only; event filters (`eventinfo`, `published`) search events only; `event_id` looks one event up
    directly. `threat_level_id` and the date range apply to BOTH kinds, so a request carrying only
    those — with no attribute, event, or event-ID selector — searches attributes and events.
    Explicitly scoped requests keep their scope; a common filter never broadens one.

    A request with no content selector and no filter reads no content: `attributes`, `events`, and
    `feed_previews` all come back empty, with a 200 rather than an error. Scheduling nothing there
    is deliberate, because an unfiltered sweep of the whole instance is not what this endpoint
    answers. The instance-level include layers still respond, since they don't depend on a match:
    `version` reports the MISP build and `tags` returns one page of tag names.

    **Include options**

    - `sightings` — adds the event-level sighting records (deduplicated across each event's own
      attributes and `/sightings/index`). Per-attribute `sighting_count` / `sightings` on the
      returned attribute rows come from the correlation join that always runs, so they are present
      with or without this token; the token governs the event-level reads.
    - `event_reports` — the analyst-written reports attached to the returned events
    - `stats` — each returned event's composition (attributes by category, objects by name)
    - `version` — the MISP build behind the data (`misp_version`)
    - `tags` — one page of the instance's tag names (`tag_names` + `tag_names_total`)
    - `feeds` — read-only previews of the feeds that carried the returned indicators
    - `objects` — resolve composite-object reference targets the search payload left unresolved
    - `misp_events_full` — full event bodies; otherwise event rows are summarized

    `event_reports`, `tags`, and `version` are on by default. An explicit include replaces them.
    Event searches request ascending event IDs. Pages are not a snapshot; edits or deletions may shift
    results between requests, and cached pages may reflect an earlier MISP state.

    Omitted filters are ignored. The `errors` array reports any partial failures.

    Args:
        body (SearchMISPRequest): Search our curated MISP (public threat feeds) by indicator
            value, event info, or event ID.

            Attribute filters (`value`, `type_attribute`, `category`, `tags`, `to_ids`) search
            attributes;
            event filters (`eventinfo`, `published`) search events; `event_id` looks one event up
            directly.
            The threat-level and date filters apply to BOTH kinds, so a request carrying only those —
            with no attribute, event, or event-ID selector — searches attributes and events.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[Any | SearchMISPResponse]
    """

    kwargs = _get_kwargs(
        body=body,
    )

    response = client.get_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)


def sync(
    *,
    client: AuthenticatedClient,
    body: SearchMISPRequest,
) -> Any | SearchMISPResponse | None:
    """Search MISP

     Search our curated MISP by indicator, event text, or event ID.

    Returns matching threat events and indicators with actor and malware context. Our curated MISP pulls
    a small set of public feeds on a daily schedule; the full list is at
    https://crimsoncrawler.com/docs/guides/data-sources/#our-curated-misp.

    **Filters**

    - `value` — indicator value to match (IP, hash, domain, etc.)
    - `eventinfo` — search events by title or description text
    - `event_id` — look up one event directly by ID
    - `type_attribute` — restrict to one attribute type (e.g. `ip-dst`, `md5`, `domain`)
    - `category` — restrict to one MISP attribute category (e.g. `Network activity`, `Payload delivery`)
    - `tags` — match any of the given tags (supports `tlp:` prefixes and galaxy cluster names)
    - `to_ids` — attribute selector: `true` returns only attributes flagged for IDS detection
      (high-confidence indicators), `false` only attributes NOT flagged. Omitting it does not filter.
    - `threat_level_id` — event threat level: `1` (high), `2` (medium), `3` (low), `4` (undefined)
    - `date_from` / `date_to` — restrict to an event date range (`YYYY-MM-DD`)
    - `published` — restrict to events published by their owning org (excludes analyst drafts)

    Attribute filters (`value`, `type_attribute`, `category`, `tags`, `to_ids`) search attributes
    only; event filters (`eventinfo`, `published`) search events only; `event_id` looks one event up
    directly. `threat_level_id` and the date range apply to BOTH kinds, so a request carrying only
    those — with no attribute, event, or event-ID selector — searches attributes and events.
    Explicitly scoped requests keep their scope; a common filter never broadens one.

    A request with no content selector and no filter reads no content: `attributes`, `events`, and
    `feed_previews` all come back empty, with a 200 rather than an error. Scheduling nothing there
    is deliberate, because an unfiltered sweep of the whole instance is not what this endpoint
    answers. The instance-level include layers still respond, since they don't depend on a match:
    `version` reports the MISP build and `tags` returns one page of tag names.

    **Include options**

    - `sightings` — adds the event-level sighting records (deduplicated across each event's own
      attributes and `/sightings/index`). Per-attribute `sighting_count` / `sightings` on the
      returned attribute rows come from the correlation join that always runs, so they are present
      with or without this token; the token governs the event-level reads.
    - `event_reports` — the analyst-written reports attached to the returned events
    - `stats` — each returned event's composition (attributes by category, objects by name)
    - `version` — the MISP build behind the data (`misp_version`)
    - `tags` — one page of the instance's tag names (`tag_names` + `tag_names_total`)
    - `feeds` — read-only previews of the feeds that carried the returned indicators
    - `objects` — resolve composite-object reference targets the search payload left unresolved
    - `misp_events_full` — full event bodies; otherwise event rows are summarized

    `event_reports`, `tags`, and `version` are on by default. An explicit include replaces them.
    Event searches request ascending event IDs. Pages are not a snapshot; edits or deletions may shift
    results between requests, and cached pages may reflect an earlier MISP state.

    Omitted filters are ignored. The `errors` array reports any partial failures.

    Args:
        body (SearchMISPRequest): Search our curated MISP (public threat feeds) by indicator
            value, event info, or event ID.

            Attribute filters (`value`, `type_attribute`, `category`, `tags`, `to_ids`) search
            attributes;
            event filters (`eventinfo`, `published`) search events; `event_id` looks one event up
            directly.
            The threat-level and date filters apply to BOTH kinds, so a request carrying only those —
            with no attribute, event, or event-ID selector — searches attributes and events.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Any | SearchMISPResponse
    """

    return sync_detailed(
        client=client,
        body=body,
    ).parsed


async def asyncio_detailed(
    *,
    client: AuthenticatedClient,
    body: SearchMISPRequest,
) -> Response[Any | SearchMISPResponse]:
    """Search MISP

     Search our curated MISP by indicator, event text, or event ID.

    Returns matching threat events and indicators with actor and malware context. Our curated MISP pulls
    a small set of public feeds on a daily schedule; the full list is at
    https://crimsoncrawler.com/docs/guides/data-sources/#our-curated-misp.

    **Filters**

    - `value` — indicator value to match (IP, hash, domain, etc.)
    - `eventinfo` — search events by title or description text
    - `event_id` — look up one event directly by ID
    - `type_attribute` — restrict to one attribute type (e.g. `ip-dst`, `md5`, `domain`)
    - `category` — restrict to one MISP attribute category (e.g. `Network activity`, `Payload delivery`)
    - `tags` — match any of the given tags (supports `tlp:` prefixes and galaxy cluster names)
    - `to_ids` — attribute selector: `true` returns only attributes flagged for IDS detection
      (high-confidence indicators), `false` only attributes NOT flagged. Omitting it does not filter.
    - `threat_level_id` — event threat level: `1` (high), `2` (medium), `3` (low), `4` (undefined)
    - `date_from` / `date_to` — restrict to an event date range (`YYYY-MM-DD`)
    - `published` — restrict to events published by their owning org (excludes analyst drafts)

    Attribute filters (`value`, `type_attribute`, `category`, `tags`, `to_ids`) search attributes
    only; event filters (`eventinfo`, `published`) search events only; `event_id` looks one event up
    directly. `threat_level_id` and the date range apply to BOTH kinds, so a request carrying only
    those — with no attribute, event, or event-ID selector — searches attributes and events.
    Explicitly scoped requests keep their scope; a common filter never broadens one.

    A request with no content selector and no filter reads no content: `attributes`, `events`, and
    `feed_previews` all come back empty, with a 200 rather than an error. Scheduling nothing there
    is deliberate, because an unfiltered sweep of the whole instance is not what this endpoint
    answers. The instance-level include layers still respond, since they don't depend on a match:
    `version` reports the MISP build and `tags` returns one page of tag names.

    **Include options**

    - `sightings` — adds the event-level sighting records (deduplicated across each event's own
      attributes and `/sightings/index`). Per-attribute `sighting_count` / `sightings` on the
      returned attribute rows come from the correlation join that always runs, so they are present
      with or without this token; the token governs the event-level reads.
    - `event_reports` — the analyst-written reports attached to the returned events
    - `stats` — each returned event's composition (attributes by category, objects by name)
    - `version` — the MISP build behind the data (`misp_version`)
    - `tags` — one page of the instance's tag names (`tag_names` + `tag_names_total`)
    - `feeds` — read-only previews of the feeds that carried the returned indicators
    - `objects` — resolve composite-object reference targets the search payload left unresolved
    - `misp_events_full` — full event bodies; otherwise event rows are summarized

    `event_reports`, `tags`, and `version` are on by default. An explicit include replaces them.
    Event searches request ascending event IDs. Pages are not a snapshot; edits or deletions may shift
    results between requests, and cached pages may reflect an earlier MISP state.

    Omitted filters are ignored. The `errors` array reports any partial failures.

    Args:
        body (SearchMISPRequest): Search our curated MISP (public threat feeds) by indicator
            value, event info, or event ID.

            Attribute filters (`value`, `type_attribute`, `category`, `tags`, `to_ids`) search
            attributes;
            event filters (`eventinfo`, `published`) search events; `event_id` looks one event up
            directly.
            The threat-level and date filters apply to BOTH kinds, so a request carrying only those —
            with no attribute, event, or event-ID selector — searches attributes and events.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[Any | SearchMISPResponse]
    """

    kwargs = _get_kwargs(
        body=body,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    *,
    client: AuthenticatedClient,
    body: SearchMISPRequest,
) -> Any | SearchMISPResponse | None:
    """Search MISP

     Search our curated MISP by indicator, event text, or event ID.

    Returns matching threat events and indicators with actor and malware context. Our curated MISP pulls
    a small set of public feeds on a daily schedule; the full list is at
    https://crimsoncrawler.com/docs/guides/data-sources/#our-curated-misp.

    **Filters**

    - `value` — indicator value to match (IP, hash, domain, etc.)
    - `eventinfo` — search events by title or description text
    - `event_id` — look up one event directly by ID
    - `type_attribute` — restrict to one attribute type (e.g. `ip-dst`, `md5`, `domain`)
    - `category` — restrict to one MISP attribute category (e.g. `Network activity`, `Payload delivery`)
    - `tags` — match any of the given tags (supports `tlp:` prefixes and galaxy cluster names)
    - `to_ids` — attribute selector: `true` returns only attributes flagged for IDS detection
      (high-confidence indicators), `false` only attributes NOT flagged. Omitting it does not filter.
    - `threat_level_id` — event threat level: `1` (high), `2` (medium), `3` (low), `4` (undefined)
    - `date_from` / `date_to` — restrict to an event date range (`YYYY-MM-DD`)
    - `published` — restrict to events published by their owning org (excludes analyst drafts)

    Attribute filters (`value`, `type_attribute`, `category`, `tags`, `to_ids`) search attributes
    only; event filters (`eventinfo`, `published`) search events only; `event_id` looks one event up
    directly. `threat_level_id` and the date range apply to BOTH kinds, so a request carrying only
    those — with no attribute, event, or event-ID selector — searches attributes and events.
    Explicitly scoped requests keep their scope; a common filter never broadens one.

    A request with no content selector and no filter reads no content: `attributes`, `events`, and
    `feed_previews` all come back empty, with a 200 rather than an error. Scheduling nothing there
    is deliberate, because an unfiltered sweep of the whole instance is not what this endpoint
    answers. The instance-level include layers still respond, since they don't depend on a match:
    `version` reports the MISP build and `tags` returns one page of tag names.

    **Include options**

    - `sightings` — adds the event-level sighting records (deduplicated across each event's own
      attributes and `/sightings/index`). Per-attribute `sighting_count` / `sightings` on the
      returned attribute rows come from the correlation join that always runs, so they are present
      with or without this token; the token governs the event-level reads.
    - `event_reports` — the analyst-written reports attached to the returned events
    - `stats` — each returned event's composition (attributes by category, objects by name)
    - `version` — the MISP build behind the data (`misp_version`)
    - `tags` — one page of the instance's tag names (`tag_names` + `tag_names_total`)
    - `feeds` — read-only previews of the feeds that carried the returned indicators
    - `objects` — resolve composite-object reference targets the search payload left unresolved
    - `misp_events_full` — full event bodies; otherwise event rows are summarized

    `event_reports`, `tags`, and `version` are on by default. An explicit include replaces them.
    Event searches request ascending event IDs. Pages are not a snapshot; edits or deletions may shift
    results between requests, and cached pages may reflect an earlier MISP state.

    Omitted filters are ignored. The `errors` array reports any partial failures.

    Args:
        body (SearchMISPRequest): Search our curated MISP (public threat feeds) by indicator
            value, event info, or event ID.

            Attribute filters (`value`, `type_attribute`, `category`, `tags`, `to_ids`) search
            attributes;
            event filters (`eventinfo`, `published`) search events; `event_id` looks one event up
            directly.
            The threat-level and date filters apply to BOTH kinds, so a request carrying only those —
            with no attribute, event, or event-ID selector — searches attributes and events.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Any | SearchMISPResponse
    """

    return (
        await asyncio_detailed(
            client=client,
            body=body,
        )
    ).parsed
